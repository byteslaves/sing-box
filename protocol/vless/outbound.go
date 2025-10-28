package vless

import (
	"context"
	"encoding/base64"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/vision"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless/encryption"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.VLESSOutboundOptions](registry, C.TypeVLESS, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	client          *vless.Client
	serverAddr      M.Socksaddr
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	transport       adapter.V2RayClientTransport
	packetAddr      bool
	xudp            bool
	encryption      *encryption.ClientInstance
	vision          bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeVLESS, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		vision:     strings.HasPrefix(options.Flow, "xtls-rprx-vision"),
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClient(ctx, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outbound.dialer, outbound.serverAddr, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	if options.PacketEncoding == nil {
		outbound.xudp = true
	} else {
		switch *options.PacketEncoding {
		case "":
		case "packetaddr":
			outbound.packetAddr = true
		case "xudp":
			outbound.xudp = true
		default:
			return nil, E.New("unknown packet encoding: ", options.PacketEncoding)
		}
	}
	// Parse encryption configuration
	if options.Encryption != "" && options.Encryption != "none" {
		s := strings.Split(options.Encryption, ".")

		// Parse xorMode, seconds, and padding from encryption string
		// Format: mlkem768x25519plus.MODE.RTT[.PADDING].KEY1.KEY2...
		// MODE: native=0, xorpub=1, random=2
		// RTT: 0rtt=1 (enable), 1rtt=0 (disable), or time like "600s"
		xorMode := uint32(0)
		seconds := uint32(0)
		padding := ""
		keyStartIndex := 0

		if len(s) >= 3 && s[0] == "mlkem768x25519plus" {
			// Parse mode
			switch s[1] {
			case "native":
				xorMode = 0
			case "xorpub":
				xorMode = 1
			case "random":
				xorMode = 2
			default:
				logger.Warn("unknown encryption mode: ", s[1], ", using native")
			}

			// Parse RTT mode
			if s[2] == "0rtt" {
				seconds = 1 // enable 0-RTT
			} else if s[2] == "1rtt" {
				seconds = 0 // disable 0-RTT
			} else if strings.HasSuffix(s[2], "s") {
				// Server-side format like "600s", client should use 0-RTT
				seconds = 1
			}

			keyStartIndex = 3

			// Check if there's a padding parameter (short string before keys)
			if len(s) > 3 {
				// Padding is typically a short string like "100-111-1111"
				// Keys are long base64 strings
				if len(s[3]) < 50 { // heuristic: padding is much shorter than keys
					testDecode, _ := base64.RawURLEncoding.DecodeString(s[3])
					if len(testDecode) != 32 && len(testDecode) != 1184 {
						padding = s[3]
						keyStartIndex = 4
					}
				}
			}
		}

		// Extract keys
		var nfsPKeysBytes [][]byte
		for i := keyStartIndex; i < len(s); i++ {
			b, _ := base64.RawURLEncoding.DecodeString(s[i])
			// Only accept valid key lengths: 32 bytes for X25519, 1184 bytes for ML-KEM-768 public key
			if len(b) == 32 || len(b) == 1184 {
				nfsPKeysBytes = append(nfsPKeysBytes, b)
			}
		}

		if len(nfsPKeysBytes) == 0 {
			return nil, E.New("no valid encryption keys found in encryption string")
		}

		outbound.encryption = &encryption.ClientInstance{}
		if err := outbound.encryption.Init(nfsPKeysBytes, xorMode, seconds, padding); err != nil {
			return nil, E.Cause(err, "initialize encryption")
		}
		logger.Debug("encryption initialized: keys=", len(nfsPKeysBytes), " xorMode=", xorMode, " seconds=", seconds, " padding=", padding)
	}

	muxOpts := common.PtrValueOrDefault(options.Multiplex)
	if muxOpts.Enabled {
		options.Flow = ""
	}
	outbound.client, err = vless.NewClient(options.UUID, options.Flow, logger)
	if err != nil {
		return nil, err
	}
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*vlessDialer)(outbound), logger, muxOpts)
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*vlessDialer)(h).DialContext(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*vlessDialer)(h).ListenPacket(ctx, destination)
	} else {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *Outbound) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) Close() error {
	return common.Close(common.PtrOrNil(h.multiplexDialer), h.transport)
}

type vlessDialer Outbound

func (h *vlessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var baseConn net.Conn
	var hookOnce sync.Once
	if h.vision {
		ctx = vision.WithHook(ctx, func(tlsConn net.Conn) {
			if tlsConn == nil {
				return
			}
			hookOnce.Do(func() {
				baseConn = tlsConn
			})
		})
	}
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
		if err == nil && h.vision {
			if baseConn == nil {
				// Only set baseConn if we have TLS/Reality
				// For encryption-only mode, baseConn should remain nil
				if h.tlsConfig != nil {
					h.logger.Warn("Vision enabled but hook was not called by transport, using fallback")
					baseConn = conn
				}
			}
		}
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err == nil && h.tlsConfig != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.tlsConfig)
			if err == nil && h.vision && baseConn == nil {
				baseConn = conn
			}
		}
	}
	if err != nil {
		return nil, err
	}

	// Apply encryption if configured
	if h.encryption != nil {
		conn, err = h.encryption.Handshake(conn)
		if err != nil {
			return nil, E.Cause(err, "encryption handshake")
		}
	}

	// For Vision: wrap the connection to expose the TLS/encryption connection for vless client
	var visionBaseConn net.Conn // The connection to pass to Vision (TLS or encryption layer)
	if h.vision {
		if baseConn != nil {
			// Has TLS/Reality: use baseConn (TLS connection)
			visionBaseConn = baseConn
			conn = newVisionConnWrapper(conn, baseConn)
		} else if h.encryption != nil {
			// Only has encryption (no TLS/Reality): use encryption layer itself
			// Find the actual encryption connection by unwrapping all layers
			var encConn net.Conn
			currentConn := conn

			// Unwrap up to 10 layers to find the encryption layer
			for i := 0; i < 10; i++ {
				// Check if current connection is encryption layer
				if currentConn != nil {
					typeName := ""
					if reflect.TypeOf(currentConn).Kind() == reflect.Ptr {
						typeName = reflect.TypeOf(currentConn).Elem().Name()
					}
					if typeName == "CommonConn" || typeName == "XorConn" {
						encConn = currentConn
						break
					}
				}

				// Try to unwrap to next layer
				if upstream, ok := currentConn.(common.WithUpstream); ok {
					if next := upstream.Upstream(); next != nil {
						if nextConn, ok := next.(net.Conn); ok {
							currentConn = nextConn
							continue
						}
					}
				}

				// Can't unwrap further
				break
			}

			if encConn != nil {
				visionBaseConn = encConn
				conn = newVisionConnWrapper(conn, encConn)
			} else {
				return nil, E.New("Vision: failed to find encryption layer (CommonConn/XorConn)")
			}
		} else {
			return nil, E.New("Vision requires either TLS/Reality or Encryption")
		}
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		if h.vision && visionBaseConn != nil {
			// For Vision, we need to pass the base connection (TLS or encryption layer)
			// to prepareConn so it can properly initialize VisionConn
			return h.client.DialEarlyConnWithBase(conn, visionBaseConn, destination)
		}
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		if h.xudp {
			return h.client.DialEarlyXUDPPacketConn(conn, destination)
		} else if h.packetAddr {
			if destination.IsFqdn() {
				return nil, E.New("packetaddr: domain destination is not supported")
			}
			packetConn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(packetaddr.NewConn(packetConn, destination), destination), nil
		} else {
			return h.client.DialEarlyPacketConn(conn, destination)
		}
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vlessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err == nil && h.tlsConfig != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.tlsConfig)
		}
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	// Apply encryption if configured
	if h.encryption != nil {
		conn, err = h.encryption.Handshake(conn)
		if err != nil {
			common.Close(conn)
			return nil, E.Cause(err, "encryption handshake")
		}
	}
	if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	} else if h.packetAddr {
		if destination.IsFqdn() {
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		conn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination)
	}
}

type visionConnWrapper struct {
	net.Conn
	upstream net.Conn
}

var (
	_ N.ReaderWithUpstream = (*visionConnWrapper)(nil)
	_ N.WriterWithUpstream = (*visionConnWrapper)(nil)
	_ common.WithUpstream  = (*visionConnWrapper)(nil)
)

func newVisionConnWrapper(conn net.Conn, upstream net.Conn) net.Conn {
	if upstream == nil || conn == nil || conn == upstream {
		return conn
	}
	return &visionConnWrapper{
		Conn:     conn,
		upstream: upstream,
	}
}

func (c *visionConnWrapper) Upstream() any {
	return c.upstream
}

func (c *visionConnWrapper) ReaderReplaceable() bool {
	if replacer, ok := c.Conn.(N.ReaderWithUpstream); ok {
		return replacer.ReaderReplaceable()
	}
	return true
}

func (c *visionConnWrapper) WriterReplaceable() bool {
	if replacer, ok := c.Conn.(N.WriterWithUpstream); ok {
		return replacer.WriterReplaceable()
	}
	return true
}
