package libngrok

import "github.com/ngrok/libngrok-go/internal/tunnel/proto"

type TunnelConfig struct {
	// Note: Only one set of options should be set at a time - either proto,
	// opts, and extra, or labels and metadata.
	forwardsTo string

	// HTTP(s), TCP, and TLS tunnels
	proto string
	opts  any
	extra proto.BindExtra

	// Labeled tunnels
	labels map[string]string
}

type ToTunnelConfig interface {
	ToTunnelConfig() TunnelConfig
}
