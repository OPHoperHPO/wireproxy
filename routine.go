package wireproxy

import (
	"bytes"
	"context"
	srand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/device"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"

	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// errorLogger is the logger to print error message
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
}

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	// Name identifies the tunnel in logs and health reports
	Name          string
	Tnet          *netstack.Net
	Dev           *device.Device
	SystemDNS     bool
	Conf          *DeviceConfig
	ResolveConfig *ResolveConfig
	// PingRecord stores the last time an IP was pinged
	PingRecord     map[string]uint64
	PingRecordLock *sync.Mutex
}

// RoutineSpawner spawns a routine (e.g. socks5, tcp static routes) after the configuration is parsed
type RoutineSpawner interface {
	SpawnRoutine(tg *TunnelGroup)
}

type addressPort struct {
	address string
	port    uint16
}

// LookupAddr lookups a hostname.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	return d.Tnet.LookupContextHost(ctx, name)
}

// ResolveAddrWithContext resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	addrs_v4 := []netip.Addr{}
	addrs_v6 := []netip.Addr{}

	for _, saddr := range addrs {
		addr, err := netip.ParseAddr(saddr)
		if err == nil {
			if addr.Is4() {
				addrs_v4 = append(addrs_v4, addr)
			} else if addr.Is6() {
				addrs_v6 = append(addrs_v6, addr)
			}
		}
	}

	rand.Shuffle(len(addrs_v4), func(i, j int) {
		addrs_v4[i], addrs_v4[j] = addrs_v4[j], addrs_v4[i]
	})
	rand.Shuffle(len(addrs_v6), func(i, j int) {
		addrs_v6[i], addrs_v6[j] = addrs_v6[j], addrs_v6[i]
	})

	addrs_all := []netip.Addr{}

	switch d.ResolveConfig.ResolveStrategy {
	case "ipv4":
		addrs_all = append(addrs_v4, addrs_v6...)
	case "ipv6":
		addrs_all = append(addrs_v6, addrs_v4...)
	}

	if len(addrs_all) == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	return &addrs_all[0], nil
}

func parseAddressPort(endpoint string) (*addressPort, error) {
	name, sport, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("port must be numeric")}
	}

	return &addressPort{address: name, port: uint16(port)}, nil
}

func (d VirtualTun) resolveToAddrPort(endpoint *addressPort) (*netip.AddrPort, error) {
	addr, err := d.ResolveAddrWithContext(context.Background(), endpoint.address)
	if err != nil {
		return nil, err
	}

	addrPort := netip.AddrPortFrom(*addr, endpoint.port)
	return &addrPort, nil
}

// passthroughResolver is a socks5 NameResolver that performs no resolution: it
// leaves the FQDN untouched (returns a nil IP) so the FQDN survives to the dial
// callback, where the domain-based routing decision is made. Resolution then
// happens on the chosen network — the tunnel netstack for tunnelled hosts, the
// system resolver for direct hosts.
type passthroughResolver struct{}

func (passthroughResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

// SpawnRoutine spawns a socks5 server.
func (config *Socks5Config) SpawnRoutine(tg *TunnelGroup) {
	var authMethods []socks5.Authenticator
	if config.Username != "" || config.Password != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{config.Username: config.Password},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	options := []socks5.Option{
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
	}

	// Names are resolved at dial time, on the tunnel that carries the
	// connection, so a failing tunnel cannot stall name resolution.
	options = append(options, socks5.WithResolver(passthroughResolver{}))
	if len(config.TunnelDomains) == 0 && !config.LogDomains {
		// Legacy path: everything through the tunnel.
		options = append(options, socks5.WithDial(tg.DialContext))
	} else {
		// Split-routing path: keep the FQDN so we can decide per connection.
		router := NewDomainRouter(config.TunnelDomains, config.LogDomains)
		options = append(options,
			socks5.WithDialAndRequest(tg.routedSocks5Dial(router)),
			// UDP ASSOCIATE only uses the plain dialer
			socks5.WithDial(tg.routedDialContext(router)),
		)
	}

	server := socks5.NewServer(options...)

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		log.Fatal(err)
	}
}

// SpawnRoutine spawns a http server.
func (config *HTTPConfig) SpawnRoutine(tg *TunnelGroup) {
	router := NewDomainRouter(config.TunnelDomains, config.LogDomains)
	server := &HTTPServer{
		config: config,
		dial:   tg.RoutedDial(router),
		auth:   CredentialValidator{config.Username, config.Password},
	}
	if config.Username != "" || config.Password != "" {
		server.authRequired = true
	}

	if config.CertFile != "" && config.KeyFile != "" {
		server.tlsRequired = true
	}

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		log.Fatal(err)
	}
}

// Valid checks the authentication data in CredentialValidator and compare them
// to username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

// connForward copy data from `from` to `to`
func connForward(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	defer func() { _ = from.Close() }()
	defer func() { _ = to.Close() }()

	_, err := io.Copy(to, from)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
}

// tcpClientForward starts a new connection via wireguard and forward traffic from `conn`
func tcpClientForward(tg *TunnelGroup, target string, conn net.Conn) {
	sconn, err := tg.DialContext(context.Background(), "tcp", target)
	if err != nil {
		_ = conn.Close()
		errorLogger.Printf("TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)
}

// STDIOTcpForward starts a new connection via wireguard and forward traffic from `conn`
func STDIOTcpForward(tg *TunnelGroup, target string, input *os.File, output *os.File) {
	sconn, err := tg.DialContext(context.Background(), "tcp", target)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(input, sconn)
	go connForward(sconn, output)
}

// SpawnRoutine spawns a local TCP server which acts as a proxy to the specified target
func (conf *TCPClientTunnelConfig) SpawnRoutine(tg *TunnelGroup) {
	if _, err := parseAddressPort(conf.Target); err != nil {
		log.Fatal(err)
	}

	server, err := net.ListenTCP("tcp", conf.BindAddress)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go tcpClientForward(tg, conf.Target, conn)
	}
}

// SpawnRoutine connects to the specified target and plumbs it to STDIN / STDOUT
func (conf *STDIOTunnelConfig) SpawnRoutine(tg *TunnelGroup) {
	if _, err := parseAddressPort(conf.Target); err != nil {
		log.Fatal(err)
	}

	go STDIOTcpForward(tg, conf.Target, conf.Input, conf.Output)
}

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		_ = conn.Close()
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		_ = conn.Close()
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)

}

// SpawnRoutine spawns a TCP server on wireguard which acts as a proxy to the specified target.
// It listens on the first tunnel only, so backup servers get no inbound access.
func (conf *TCPServerTunnelConfig) SpawnRoutine(tg *TunnelGroup) {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		log.Fatal(err)
	}

	vt := tg.Tunnels()[0]
	addr := &net.TCPAddr{Port: conf.ListenPort}
	server, err := vt.Tnet.ListenTCP(addr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go tcpServerForward(vt, raddr, conn)
	}
}

// SpawnRoutine spawns an SNI proxy server.
func (config *SNIConfig) SpawnRoutine(tg *TunnelGroup) {
	router := NewDomainRouter(config.TunnelDomains, config.LogDomains)
	dial := tg.RoutedDial(router)

	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go sniServe(dial, conn)
	}
}

// pingRecords returns a copy of the last pong time per CheckAlive address
func (d VirtualTun) pingRecords() map[string]uint64 {
	d.PingRecordLock.Lock()
	defer d.PingRecordLock.Unlock()
	records := make(map[string]uint64, len(d.PingRecord))
	for addr, record := range d.PingRecord {
		records[addr] = record
	}
	return records
}

// pingsStale reports whether a CheckAlive address has not answered recently
func (d VirtualTun) pingsStale(records map[string]uint64) bool {
	for _, record := range records {
		lastPong := time.Unix(int64(record), 0)
		// +2 seconds to account for the time it takes to ping the IP
		if time.Since(lastPong) > time.Duration(d.Conf.CheckAliveInterval+2)*time.Second {
			return true
		}
	}
	return false
}

// metrics returns the device state as `wg show` would, without secrets
func (d VirtualTun) metrics() ([]byte, error) {
	get, err := d.Dev.IpcGet()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, peer := range strings.Split(get, "\n") {
		pair := strings.SplitN(peer, "=", 2)
		if len(pair) != 2 {
			buf.WriteString(peer)
			continue
		}
		if pair[0] == "private_key" || pair[0] == "preshared_key" {
			pair[1] = "REDACTED"
		}
		buf.WriteString(pair[0])
		buf.WriteString("=")
		buf.WriteString(pair[1])
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

// ping sends one ICMP echo request to addr through the tunnel and waits for
// the matching reply until deadline.
func (d VirtualTun) ping(addr netip.Addr, deadline time.Time) error {
	if !addr.Is4() && !addr.Is6() {
		return errors.New("invalid address: " + addr.String())
	}

	socket, err := d.Tnet.Dial("ping", addr.String())
	if err != nil {
		return err
	}
	defer func() { _ = socket.Close() }()

	data := make([]byte, 16)
	if _, err := srand.Read(data); err != nil {
		return err
	}

	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: data,
	}

	var icmpBytes []byte
	if addr.Is4() {
		icmpBytes, err = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	} else {
		icmpBytes, err = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &requestPing}).Marshal(nil)
	}
	if err != nil {
		return err
	}

	if err := socket.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := socket.Write(icmpBytes); err != nil {
		return err
	}

	readBytes := make([]byte, 1500)
	n, err := socket.Read(readBytes)
	if err != nil {
		return err
	}

	replyPacket, err := icmp.ParseMessage(1, readBytes[:n])
	if err != nil {
		return err
	}

	if addr.Is4() {
		replyPing, ok := replyPacket.Body.(*icmp.Echo)
		if !ok {
			return fmt.Errorf("invalid reply type: %s", replyPacket.Type)
		}
		if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
			return fmt.Errorf("invalid ping reply: %v", replyPing)
		}
	} else {
		replyPing, ok := replyPacket.Body.(*icmp.RawBody)
		if !ok {
			return fmt.Errorf("invalid reply type: %s", replyPacket.Type)
		}
		if len(replyPing.Data) < 4 {
			return errors.New("reply too short")
		}

		seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
		pongBody := replyPing.Data[4:]
		if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
			return fmt.Errorf("invalid ping reply: %v", replyPing)
		}
	}

	d.PingRecordLock.Lock()
	d.PingRecord[addr.String()] = uint64(time.Now().Unix())
	d.PingRecordLock.Unlock()
	return nil
}

// probe pings every CheckAlive address in parallel and reports whether at
// least one of them answered within timeout.
func (d VirtualTun) probe(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	results := make(chan bool, len(d.Conf.CheckAlive))
	for _, addr := range d.Conf.CheckAlive {
		go func(addr netip.Addr) {
			err := d.ping(addr, deadline)
			if err != nil {
				errorLogger.Printf("Failed to ping %s via %s: %s\n", addr, d.Name, err.Error())
			}
			results <- err == nil
		}(addr)
	}

	alive := false
	for range d.Conf.CheckAlive {
		if <-results {
			alive = true
		}
	}
	return alive
}
