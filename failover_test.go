package wireproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func fakeTunnel(name string, dial dialFunc) *tunnelState {
	t := &tunnelState{vt: &VirtualTun{Name: name}, name: name, dial: dial, conns: make(map[*trackedConn]struct{})}
	t.healthy.Store(true)
	return t
}

func fakeGroup(conf FailoverConfig, tunnels ...*tunnelState) *TunnelGroup {
	return &TunnelGroup{tunnels: tunnels, conf: conf}
}

func pipeDial(ctx context.Context, network, address string) (net.Conn, error) {
	c, _ := net.Pipe()
	return c, nil
}

func failDial(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("unreachable")
}

func hangDial(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func dialedThrough(t *testing.T, c net.Conn) string {
	t.Helper()
	tc, ok := c.(*trackedConn)
	if !ok {
		t.Fatalf("connection is not tracked: %T", c)
	}
	return tc.tunnel.name
}

func TestRaceFailsOverAtOnceOnError(t *testing.T) {
	tg := fakeGroup(FailoverConfig{FallbackDelay: time.Hour}, fakeTunnel("a", failDial), fakeTunnel("b", pipeDial))
	c, err := tg.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got := dialedThrough(t, c); got != "b" {
		t.Fatalf("dialed through %s, want b", got)
	}
}

func TestRaceStartsNextTunnelAfterDelay(t *testing.T) {
	tg := fakeGroup(FailoverConfig{FallbackDelay: 50 * time.Millisecond}, fakeTunnel("a", hangDial), fakeTunnel("b", pipeDial))
	started := time.Now()
	c, err := tg.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got := dialedThrough(t, c); got != "b" {
		t.Fatalf("dialed through %s, want b", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fallback took %s", elapsed)
	}
}

func TestRaceReturnsFirstErrorWhenAllFail(t *testing.T) {
	second := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("second")
	}
	tg := fakeGroup(FailoverConfig{FallbackDelay: time.Hour}, fakeTunnel("a", failDial), fakeTunnel("b", second))
	if _, err := tg.DialContext(context.Background(), "tcp", "example.com:80"); err == nil || err.Error() != "unreachable" {
		t.Fatalf("got %v, want the error of the preferred tunnel", err)
	}
}

func TestRaceClosesLosers(t *testing.T) {
	release := make(chan struct{})
	slow := func(ctx context.Context, network, address string) (net.Conn, error) {
		<-release
		return pipeDial(ctx, network, address)
	}
	a := fakeTunnel("a", slow)
	tg := fakeGroup(FailoverConfig{FallbackDelay: 10 * time.Millisecond}, a, fakeTunnel("b", pipeDial))
	c, err := tg.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	close(release)

	deadline := time.Now().Add(time.Second)
	for {
		a.connsMu.Lock()
		n := len(a.conns)
		a.connsMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("losing connection was not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUDPUsesPreferredHealthyTunnel(t *testing.T) {
	a, b := fakeTunnel("a", pipeDial), fakeTunnel("b", pipeDial)
	tg := fakeGroup(FailoverConfig{FailAfter: 1, RecoverAfter: 1}, a, b)
	tg.report(a, false)
	c, err := tg.DialContext(context.Background(), "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got := dialedThrough(t, c); got != "b" {
		t.Fatalf("dialed through %s, want b", got)
	}
}

func TestHealthTransitions(t *testing.T) {
	a, b := fakeTunnel("a", pipeDial), fakeTunnel("b", pipeDial)
	tg := fakeGroup(FailoverConfig{FailAfter: 2, RecoverAfter: 2, CloseOnDown: true}, a, b)

	c, err := a.dialTracked(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}

	tg.report(a, false)
	if !a.healthy.Load() || tg.active != 0 {
		t.Fatal("one failed check must not switch tunnels")
	}
	tg.report(a, false)
	if a.healthy.Load() || tg.active != 1 {
		t.Fatal("tunnel a should be down and b active")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("connection of the failed tunnel was not closed")
	}

	tg.report(a, true)
	if tg.active != 1 {
		t.Fatal("one good check must not switch back")
	}
	tg.report(a, true)
	if !a.healthy.Load() || tg.active != 0 {
		t.Fatal("tunnel a should be preferred again")
	}
}

func TestConnectionsKeptWhenNoTunnelIsHealthy(t *testing.T) {
	a, b := fakeTunnel("a", pipeDial), fakeTunnel("b", pipeDial)
	tg := fakeGroup(FailoverConfig{FailAfter: 1, RecoverAfter: 1, CloseOnDown: true}, a, b)
	tg.report(b, false)

	c, err := a.dialTracked(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	tg.report(a, false)

	a.connsMu.Lock()
	n := len(a.conns)
	a.connsMu.Unlock()
	if n != 1 {
		t.Fatal("connections must stay open when no tunnel can take over")
	}
}

func TestParseMultipleWGConfigs(t *testing.T) {
	dir := t.TempDir()
	wg := func(name, addr string) {
		conf := "[Interface]\nPrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=\nAddress = " + addr +
			"\nCheckAlive = 1.1.1.1\n\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\nEndpoint = 127.0.0.1:51820\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wg("main.conf", "10.0.0.2")
	wg("backup.conf", "10.0.1.2")
	main := filepath.Join(dir, "wireproxy.conf")
	conf := "WGConfig = main.conf\nWGConfig = backup.conf\n\n[Failover]\nFallbackDelay = 250ms\nFailAfter = 3\nCloseOnDown = false\n\n[Socks5]\nBindAddress = 127.0.0.1:1080\n"
	if err := os.WriteFile(main, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseConfig(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Devices) != 2 || parsed.Devices[0].Name != "main" || parsed.Devices[1].Name != "backup" {
		t.Fatalf("unexpected devices: %+v", parsed.Devices)
	}
	f := parsed.Failover
	if f.FallbackDelay != 250*time.Millisecond || f.FailAfter != 3 || f.RecoverAfter != 3 || f.CloseOnDown {
		t.Fatalf("unexpected failover config: %+v", f)
	}
}

func TestParseFailoverRejectsBadValues(t *testing.T) {
	for _, section := range []string{"FallbackDelay = 0s", "FallbackDelay = soon", "FailAfter = 0", "RecoverAfter = -1", "CloseOnDown = maybe"} {
		cfg, err := loadIniConfig("[Failover]\n" + section)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseFailoverConfig(cfg); err == nil {
			t.Errorf("%q was accepted", section)
		}
	}
}

// End-to-end: two real wireguard tunnels to two in-process servers that both
// serve the same address. Killing the first server must move new connections
// to the second one without waiting for the health checks, then close the
// connections stuck on the dead tunnel.

func newKeyPair(t *testing.T) (private, public string) {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	pub, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key[:]), hex.EncodeToString(pub)
}

var sharedAddr = netip.MustParseAddr("10.9.9.9")

func startServer(t *testing.T, name string, own netip.Addr, clientPub string, clientAddr netip.Addr) (*device.Device, string, string) {
	t.Helper()
	priv, pub := newKeyPair(t)
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{own, sharedAddr}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	ipc := "private_key=" + priv + "\nlisten_port=0\npublic_key=" + clientPub + "\nallowed_ip=" + clientAddr.String() + "/32\n"
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)

	get, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(get, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}

	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: sharedAddr.AsSlice(), Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Write([]byte(name))
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}()
		}
	}()
	return dev, pub, "127.0.0.1:" + port
}

func startClient(t *testing.T, name string, own, server netip.Addr) (*VirtualTun, *device.Device) {
	t.Helper()
	priv, pub := newKeyPair(t)
	serverDev, serverPub, endpoint := startServer(t, name, server, pub, own)
	conf := &DeviceConfig{
		Name:      name,
		SecretKey: priv,
		Endpoint:  []netip.Addr{own},
		MTU:       1420,
		Peers: []PeerConfig{{
			PublicKey:    serverPub,
			PreSharedKey: strings.Repeat("0", 64),
			Endpoint:     &endpoint,
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
		CheckAlive:         []netip.Addr{server},
		CheckAliveInterval: 1,
	}
	vt, err := StartWireguard(conf, &ResolveConfig{ResolveStrategy: "auto"}, device.LogLevelSilent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vt.Dev.Close)
	return vt, serverDev
}

func readName(t *testing.T, c net.Conn) string {
	t.Helper()
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return string(buf[:n])
}

func TestFailoverBetweenRealTunnels(t *testing.T) {
	if testing.Short() {
		t.Skip("starts wireguard devices")
	}
	a, serverA := startClient(t, "a", netip.MustParseAddr("10.0.1.2"), netip.MustParseAddr("10.0.1.1"))
	b, _ := startClient(t, "b", netip.MustParseAddr("10.0.2.2"), netip.MustParseAddr("10.0.2.1"))

	const fallback = 300 * time.Millisecond
	tg := NewTunnelGroup([]*VirtualTun{a, b}, &FailoverConfig{FallbackDelay: fallback, FailAfter: 2, RecoverAfter: 1, CloseOnDown: true})
	tg.StartHealthChecks()

	target := net.JoinHostPort(sharedAddr.String(), "80")
	dial := func() (net.Conn, string, time.Duration) {
		started := time.Now()
		c, err := tg.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		return c, readName(t, c), time.Since(started)
	}

	stuck, name, _ := dial()
	defer func() { _ = stuck.Close() }()
	if name != "a" {
		t.Fatalf("served by %s, want a", name)
	}

	serverA.Close()

	c, name, elapsed := dial()
	_ = c.Close()
	if name != "b" {
		t.Fatalf("served by %s after the first server died, want b", name)
	}
	if elapsed > fallback+2*time.Second {
		t.Fatalf("failover took %s", elapsed)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		tg.mu.Lock()
		active := tg.active
		tg.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("health checks did not switch to tunnel b")
		}
		time.Sleep(50 * time.Millisecond)
	}

	_ = stuck.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stuck.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection on the dead tunnel was not closed: %v", err)
	}

	c, name, elapsed = dial()
	_ = c.Close()
	if name != "b" || elapsed >= fallback {
		t.Fatalf("served by %s in %s, want b without waiting", name, elapsed)
	}
}

func TestRecoveryClosesConnectionsLeftOnDeadTunnel(t *testing.T) {
	a, b := fakeTunnel("a", pipeDial), fakeTunnel("b", pipeDial)
	tg := fakeGroup(FailoverConfig{FailAfter: 1, RecoverAfter: 1, CloseOnDown: true}, a, b)
	tg.report(b, false)

	c, err := a.dialTracked(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tg.report(a, false) // every tunnel down: connection is kept
	tg.report(b, true)  // b is back: the connection stuck on a must go

	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("connection on the dead tunnel was not closed after recovery")
	}
}
