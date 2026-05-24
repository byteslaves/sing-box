package snellprotocol

import (
	"context"
	"net"

	snell "github.com/reF1nd/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SnellInboundOptions](registry, C.TypeSnell, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  *snell.Service
	obfsMode string
	obfsHost string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellInboundOptions) (adapter.Inbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell: psk is required")
	}

	switch options.ObfsMode {
	case "", "http", "tls":
	default:
		return nil, E.New("snell: unsupported obfs mode: ", options.ObfsMode)
	}

	i := &Inbound{
		Adapter:  inbound.NewAdapter(C.TypeSnell, tag),
		router:   uot.NewRouter(router, logger),
		logger:   logger,
		obfsMode: options.ObfsMode,
		obfsHost: options.ObfsHost,
	}

	networks := []string{N.NetworkTCP}
	service, err := snell.NewService(snell.ServiceConfig{
		PSK:        []byte(options.PSK),
		Version:    options.Version,
		UDPEnabled: true,
		Handler:    (*inboundHandler)(i),
		UDPHandler: (*inboundUDPHandler)(i),
		Logger:     logger,
	})
	if err != nil {
		return nil, err
	}
	i.service = service

	i.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           networks,
		Listen:            options.ListenOptions,
		ConnectionHandler: i,
	})
	return i, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	switch h.obfsMode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

//nolint:staticcheck
func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	switch h.obfsMode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

type inboundUDPHandler Inbound

func (h *inboundUDPHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	h.logger.InfoContext(ctx, "inbound packet connection")
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
