package option

type SnellInboundOptions struct {
	ListenOptions
	PSK      string `json:"psk"`
	Version  int    `json:"version,omitempty"`
	ObfsMode string `json:"obfs_mode,omitempty"`
	ObfsHost string `json:"obfs_host,omitempty"`
}

type SnellOutboundOptions struct {
	DialerOptions
	ServerOptions
	PSK      string      `json:"psk"`
	Version  int         `json:"version,omitempty"`
	Reuse    bool        `json:"reuse,omitempty"`
	Network  NetworkList `json:"network,omitempty"`
	ObfsMode string      `json:"obfs_mode,omitempty"`
	ObfsHost string      `json:"obfs_host,omitempty"`
}
