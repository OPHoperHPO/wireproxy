package wireproxy

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	if conf.ListenPort != nil {
		request.WriteString(fmt.Sprintf("listen_port=%d\n", *conf.ListenPort))
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		))
		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

// sendRandomUDPPackets dials a UDP socket from the given localPort and sends a few
// small random payloads to each peer Endpoint, if present.
func sendRandomUDPPackets(conf *DeviceConfig, localPort int, peers []PeerConfig) error {
	packetsPerPeer := conf.UDPWarmupPacketCount // how many packets to send to each peer
	minSize := conf.UDPWarmupMinPacketSize
	maxSize := conf.UDPWarmupMaxPacketSize
	chunkSize := 1400 // how many bytes to send per chunk

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	// Listen on the chosen port from "the normal network."
	ln, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero, // 0.0.0.0
		Port: localPort,
	})
	if err != nil {
		return fmt.Errorf("failed to listen on local UDP port %d: %w", localPort, err)
	}
	defer ln.Close()

	for _, p := range peers {
		if p.Endpoint == nil || *p.Endpoint == "" {
			continue
		}

		remoteAddr, err := net.ResolveUDPAddr("udp", *p.Endpoint)
		if err != nil {
			errorLogger.Printf("warning: cannot resolve endpoint %q: %v\n", *p.Endpoint, err)
			continue
		}

		errorLogger.Printf("Sending random UDP packets to %s\n", remoteAddr)
		for i := 0; i < packetsPerPeer; i++ {
			// Generate random data length in [minSize..maxSize]
			dataLen := rng.Intn(maxSize-minSize+1) + minSize
			errorLogger.Printf("Sending random UDP packet of total size %d bytes (in chunks)\n", dataLen)

			// Create the entire payload (for demonstration)
			payload := make([]byte, dataLen)
			if _, err := io.ReadFull(rand.Reader, payload); err != nil {
				errorLogger.Printf("warning: random payload generation failed: %v\n", err)
				continue
			}

			// Chunk and send
			offset := 0
			for offset < dataLen {
				end := offset + chunkSize
				if end > dataLen {
					end = dataLen
				}
				chunk := payload[offset:end]
				offset = end

				_, sendErr := ln.WriteToUDP(chunk, remoteAddr)
				if sendErr != nil {
					errorLogger.Printf("warning: sending chunk to %v failed: %v\n", remoteAddr, sendErr)
				}
			}
		}
	}
	return nil
}

func selectFreePort() (int, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to acquire ephemeral port: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.Port, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *DeviceConfig, logLevel int) (*VirtualTun, error) {
	// If no listen port specified, pick a random free UDP port.
	if conf.ListenPort == nil {
		port, err := selectFreePort()
		if err != nil {
			return nil, fmt.Errorf("failed to select a free port: %w", err)
		}
		conf.ListenPort = &port
		errorLogger.Printf("No listen port specified, picking a random free UDP port: %d\n", port)
	}

	setting, err := CreateIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, err
	}

	if conf.UDPWarmup {
		err = sendRandomUDPPackets(conf, *conf.ListenPort, conf.Peers)
		if err != nil {
			return nil, fmt.Errorf("failed to send random UDP packets: %w", err)
		}
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return &VirtualTun{
		Tnet:           tnet,
		Dev:            dev,
		Conf:           conf,
		SystemDNS:      len(setting.DNS) == 0,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),

		ConsecutivePingFailures: make(map[string]int),
		ConsecutiveFailsLock:    new(sync.Mutex),

		// Flag to avoid repeated restarts in parallel
		restarting:     false,
		restartingLock: new(sync.Mutex),
	}, nil
}
