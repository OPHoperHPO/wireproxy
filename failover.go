package wireproxy

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/things-go/go-socks5"
)

// dialFunc opens a connection through one specific tunnel
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// tunnelState tracks the health of one tunnel and the connections it carries
type tunnelState struct {
	vt   *VirtualTun
	name string
	dial dialFunc

	healthy atomic.Bool

	// guarded by TunnelGroup.mu
	fails, oks int

	connsMu sync.Mutex
	conns   map[*trackedConn]struct{}
}

// TunnelGroup spreads connections over one or more tunnels. Every tunnel is
// kept up at all times; new connections go to the most preferred healthy one.
// A new TCP connection that does not complete on a tunnel within
// FallbackDelay is raced on the next tunnel, so a tunnel that dies between
// two health checks does not stall clients.
type TunnelGroup struct {
	tunnels []*tunnelState
	conf    FailoverConfig

	mu     sync.Mutex
	active int
}

// NewTunnelGroup groups tunnels given in order of preference
func NewTunnelGroup(tunnels []*VirtualTun, conf *FailoverConfig) *TunnelGroup {
	tg := &TunnelGroup{}
	if conf != nil {
		tg.conf = *conf
	}
	for _, vt := range tunnels {
		state := &tunnelState{vt: vt, name: vt.Name, conns: make(map[*trackedConn]struct{})}
		state.dial = vt.dialContext
		state.healthy.Store(true)
		tg.tunnels = append(tg.tunnels, state)
	}
	return tg
}

// Tunnels returns the tunnels in order of preference
func (tg *TunnelGroup) Tunnels() []*VirtualTun {
	tunnels := make([]*VirtualTun, 0, len(tg.tunnels))
	for _, t := range tg.tunnels {
		tunnels = append(tunnels, t.vt)
	}
	return tunnels
}

// dialContext resolves the address on this tunnel and dials it
func (d VirtualTun) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		resolved, err := d.ResolveAddrWithContext(ctx, host)
		if err != nil {
			return nil, err
		}
		addr = *resolved
	}
	return d.Tnet.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}

// candidates lists healthy tunnels first, each part in order of preference
func (tg *TunnelGroup) candidates() []*tunnelState {
	order := make([]*tunnelState, 0, len(tg.tunnels))
	for _, t := range tg.tunnels {
		if t.healthy.Load() {
			order = append(order, t)
		}
	}
	for _, t := range tg.tunnels {
		if !t.healthy.Load() {
			order = append(order, t)
		}
	}
	return order
}

func isTCP(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6"
}

// DialContext opens a connection through the best tunnel available
func (tg *TunnelGroup) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	order := tg.candidates()
	if len(order) == 0 {
		return nil, errors.New("no tunnel configured")
	}
	// Datagram "connections" succeed without a handshake, so there is nothing
	// to race: use the preferred healthy tunnel.
	if len(order) == 1 || !isTCP(network) {
		return order[0].dialTracked(ctx, network, address)
	}
	return tg.race(ctx, order, network, address)
}

type dialResult struct {
	conn net.Conn
	err  error
}

// race dials through the tunnels in order. The next tunnel is tried when the
// previous attempt fails or has not completed within FallbackDelay; the first
// connection established wins and the others are discarded.
func (tg *TunnelGroup) race(ctx context.Context, order []*tunnelState, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, len(order))
	next, pending := 0, 0
	start := func() {
		t := order[next]
		next++
		pending++
		go func() {
			conn, err := t.dialTracked(ctx, network, address)
			results <- dialResult{conn, err}
		}()
	}

	delay := tg.conf.FallbackDelay
	if delay <= 0 {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	start()
	var firstErr error
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				if pending > 0 {
					go discard(results, pending)
				}
				return r.conn, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			if next < len(order) {
				start()
				timer.Reset(delay)
			}
		case <-timer.C:
			if next < len(order) {
				start()
				timer.Reset(delay)
			}
		}
	}
	return nil, firstErr
}

// discard closes connections that lost a race
func discard(results <-chan dialResult, n int) {
	for ; n > 0; n-- {
		if r := <-results; r.conn != nil {
			_ = r.conn.Close()
		}
	}
}

// RoutedDial returns a dialer that sends whitelisted hosts through the tunnel
// and dials everything else directly. Used by the HTTP and SNI proxies, whose
// dial callbacks receive the destination hostname intact.
func (tg *TunnelGroup) RoutedDial(router *DomainRouter) func(network, address string) (net.Conn, error) {
	return func(network, address string) (net.Conn, error) {
		if router.route(hostFromAddr(address)) {
			return tg.DialContext(context.Background(), network, address)
		}
		return net.Dial(network, address)
	}
}

// routedSocks5Dial returns a socks5 dial-with-request callback that routes based
// on the original destination FQDN (preserved on request.DestAddr), falling back
// to the address host for IP-literal targets.
func (tg *TunnelGroup) routedSocks5Dial(router *DomainRouter) func(context.Context, string, string, *socks5.Request) (net.Conn, error) {
	return func(ctx context.Context, network, address string, request *socks5.Request) (net.Conn, error) {
		host := request.DestAddr.FQDN
		if host == "" {
			host = hostFromAddr(address)
		}
		if router.route(host) {
			return tg.DialContext(ctx, network, address)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
}

// routedDialContext is RoutedDial with a context, for callers that only see
// the destination address
func (tg *TunnelGroup) routedDialContext(router *DomainRouter) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if router.route(hostFromAddr(address)) {
			return tg.DialContext(ctx, network, address)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
}

// trackedConn remembers which tunnel carries it, so the connection can be
// closed when that tunnel goes down
type trackedConn struct {
	net.Conn
	tunnel *tunnelState
	once   sync.Once
}

func (t *tunnelState) dialTracked(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tracked := &trackedConn{Conn: conn, tunnel: t}
	t.connsMu.Lock()
	t.conns[tracked] = struct{}{}
	t.connsMu.Unlock()
	return tracked, nil
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.tunnel.connsMu.Lock()
		delete(c.tunnel.conns, c)
		c.tunnel.connsMu.Unlock()
	})
	return c.Conn.Close()
}

// CloseWrite half-closes TCP connections, as proxies expect from a *net.TCPConn
func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("close write is not supported")
}

// closeConns closes every connection carried by the tunnel and returns how
// many there were
func (t *tunnelState) closeConns() int {
	t.connsMu.Lock()
	conns := make([]*trackedConn, 0, len(t.conns))
	for c := range t.conns {
		conns = append(conns, c)
	}
	t.connsMu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

// StartHealthChecks pings the CheckAlive addresses of every tunnel each
// CheckAliveInterval. Tunnels without CheckAlive are always considered up.
func (tg *TunnelGroup) StartHealthChecks() {
	for _, t := range tg.tunnels {
		conf := t.vt.Conf
		if len(conf.CheckAlive) == 0 {
			continue
		}

		t.vt.PingRecordLock.Lock()
		for _, addr := range conf.CheckAlive {
			t.vt.PingRecord[addr.String()] = 0
		}
		t.vt.PingRecordLock.Unlock()

		go func(t *tunnelState) {
			interval := time.Duration(t.vt.Conf.CheckAliveInterval) * time.Second
			for {
				started := time.Now()
				tg.report(t, t.vt.probe(interval))
				time.Sleep(interval - time.Since(started))
			}
		}(t)
	}
}

// report records the result of one health check of a tunnel
func (tg *TunnelGroup) report(t *tunnelState, alive bool) {
	failAfter, recoverAfter := max(tg.conf.FailAfter, 1), max(tg.conf.RecoverAfter, 1)

	tg.mu.Lock()
	wentDown, wentUp := false, false
	if alive {
		t.fails = 0
		t.oks++
		if !t.healthy.Load() && t.oks >= recoverAfter {
			t.healthy.Store(true)
			wentUp = true
			log.Printf("tunnel %s is up\n", t.name)
			tg.reselect()
		}
	} else {
		t.oks = 0
		t.fails++
		if t.healthy.Load() && t.fails >= failAfter {
			t.healthy.Store(false)
			wentDown = true
			log.Printf("tunnel %s is down after %d failed checks\n", t.name, t.fails)
			tg.reselect()
		}
	}
	// Connections are only dropped when another tunnel can take over; when
	// every tunnel looks down the checks themselves may be what is failing.
	// Once a tunnel comes back, connections kept on tunnels that are still
	// down are dropped as well.
	var stale []*tunnelState
	if tg.conf.CloseOnDown && tg.tunnels[tg.active].healthy.Load() {
		if wentDown {
			stale = append(stale, t)
		}
		if wentUp {
			for _, other := range tg.tunnels {
				if !other.healthy.Load() {
					stale = append(stale, other)
				}
			}
		}
	}
	tg.mu.Unlock()

	for _, s := range stale {
		if n := s.closeConns(); n > 0 {
			log.Printf("closed %d connections of tunnel %s\n", n, s.name)
		}
	}
}

// reselect makes the most preferred healthy tunnel active. Must hold tg.mu.
func (tg *TunnelGroup) reselect() {
	active := tg.active
	for i, t := range tg.tunnels {
		if t.healthy.Load() {
			active = i
			break
		}
	}
	if active != tg.active {
		log.Printf("failover: switching from tunnel %s to %s\n", tg.tunnels[tg.active].name, tg.tunnels[active].name)
		tg.active = active
	}
}

type tunnelStatus struct {
	Active  bool              `json:"active"`
	Healthy bool              `json:"healthy"`
	Pings   map[string]uint64 `json:"pings"`
}

// ServeHTTP exposes health status and device metrics
func (tg *TunnelGroup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health metric request: %s\n", r.URL.Path)
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		var body []byte
		var err error
		status := http.StatusOK
		if len(tg.tunnels) == 1 {
			vt := tg.tunnels[0].vt
			records := vt.pingRecords()
			if vt.pingsStale(records) {
				status = http.StatusServiceUnavailable
			}
			body, err = json.Marshal(records)
		} else {
			tg.mu.Lock()
			active := tg.active
			tg.mu.Unlock()
			report := make(map[string]tunnelStatus, len(tg.tunnels))
			anyHealthy := false
			for i, t := range tg.tunnels {
				healthy := t.healthy.Load()
				anyHealthy = anyHealthy || healthy
				report[t.name] = tunnelStatus{Active: i == active, Healthy: healthy, Pings: t.vt.pingRecords()}
			}
			if !anyHealthy {
				status = http.StatusServiceUnavailable
			}
			body, err = json.Marshal(report)
		}
		if err != nil {
			errorLogger.Printf("Failed to get device metrics: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(status)
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	case "/metrics":
		var out []byte
		for _, t := range tg.tunnels {
			metrics, err := t.vt.metrics()
			if err != nil {
				errorLogger.Printf("Failed to get device metrics: %s\n", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if len(tg.tunnels) > 1 {
				out = append(out, "# tunnel "+t.name+"\n"...)
			}
			out = append(out, metrics...)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
