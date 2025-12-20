package transport

import (
	"context"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
)

type HTTPSTransportWrapper struct {
	transport *http.Transport
}

func NewHTTPSTransportWrapper(dialer tls.Dialer, serverAddr M.Socksaddr) *HTTPSTransportWrapper {
	return &HTTPSTransportWrapper{
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialTLSContext(ctx, serverAddr)
			},
		},
	}
}

func (h *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	return h.transport.RoundTrip(request)
}

func (h *HTTPSTransportWrapper) CloseIdleConnections() {
	h.transport.CloseIdleConnections()
}

func (h *HTTPSTransportWrapper) Clone() *HTTPSTransportWrapper {
	return &HTTPSTransportWrapper{
		transport: h.transport.Clone(),
	}
}
