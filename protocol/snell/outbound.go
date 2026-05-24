package snellprotocol

import (
	"context"
	"fmt"
	"net"
	"os"

	snell "github.com/reF1nd/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	dialer     N.Dialer
	client     *snell.Client
	pool       *snell.Pool
	serverAddr M.Socksaddr
	obfsMode   string
	obfsHost   string
	serverPort string
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell: psk is required")
	}

	switch options.ObfsMode {
	case "", "http", "tls":
	default:
		return nil, E.New("snell: unsupported obfs mode: ", options.ObfsMode)
	}

	serverAddr := options.ServerOptions.Build()

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	version := options.Version
	if version == 0 {
		version = snell.DefaultVersion
	}

	// Build network list. If the user specified an explicit `network` field use
	// that; otherwise apply the protocol default: v3/v4/v5 enable TCP+UDP by
	// default, while v1/v2 default to TCP-only (no UDP support).
	var networks []string
	if string(options.Network) != "" {
		networks = options.Network.Build()
		for _, net := range networks {
			if net == N.NetworkUDP && version < snell.Version3 {
				return nil, E.New("snell: UDP requires version 3 or above")
			}
		}
	} else if version >= snell.Version3 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		networks = []string{N.NetworkTCP}
	}

	client, err := snell.NewClient([]byte(options.PSK), version)
	if err != nil {
		return nil, err
	}

	o := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, networks, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		client:     client,
		serverAddr: serverAddr,
		obfsMode:   options.ObfsMode,
		obfsHost:   options.ObfsHost,
		serverPort: fmt.Sprintf("%d", serverAddr.Port),
	}

	// Connection reuse (v4+): build a pool whose factory dials + encrypts a
	// fresh stream.  The pool is only active when reuse is explicitly enabled.
	if options.Reuse && version >= snell.Version4 {
		o.pool = snell.NewPool(func(ctx context.Context) (net.Conn, error) {
			rawConn, err := outboundDialer.DialContext(ctx, N.NetworkTCP, serverAddr)
			if err != nil {
				return nil, err
			}
			return client.WrapStream(o.applyObfs(rawConn)), nil
		})
	}

	return o, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		if h.pool != nil {
			return h.client.DialContextWithPool(ctx, h.pool, destination)
		}
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.applyObfs(rawConn)
		return h.client.DialContext(ctx, conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UDP connection to ", destination)
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.applyObfs(rawConn)
		udpStream, err := h.client.DialUDP(ctx, conn)
		if err != nil {
			return nil, err
		}
		pc := snell.NewClientPacketConn(udpStream)
		return &packetConnWrapper{PacketConn: pc, destination: destination}, nil
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := h.applyObfs(rawConn)
	udpStream, err := h.client.DialUDP(ctx, conn)
	if err != nil {
		return nil, err
	}
	return snell.NewClientPacketConn(udpStream), nil
}

func (h *Outbound) applyObfs(conn net.Conn) net.Conn {
	obfsHost := h.obfsHost
	if obfsHost == "" {
		obfsHost = "bing.com"
	}
	switch h.obfsMode {
	case "http":
		return obfs.NewHTTPObfs(conn, obfsHost, h.serverPort)
	case "tls":
		return obfs.NewTLSObfs(conn, obfsHost)
	}
	return conn
}

// packetConnWrapper wraps net.PacketConn as net.Conn so it can be used in DialContext for UDP networks.
type packetConnWrapper struct {
	net.PacketConn
	destination M.Socksaddr
}

func (w *packetConnWrapper) Read(p []byte) (int, error) {
	n, _, err := w.PacketConn.ReadFrom(p)
	return n, err
}

func (w *packetConnWrapper) Write(p []byte) (int, error) {
	return w.PacketConn.WriteTo(p, w.destination)
}

func (w *packetConnWrapper) RemoteAddr() net.Addr {
	return w.destination
}
