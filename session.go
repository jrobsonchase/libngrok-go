package libngrok

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/inconshreveable/muxado"
	tunnel_client "github.com/ngrok/libngrok-go/internal/tunnel/client"
	"github.com/ngrok/libngrok-go/internal/tunnel/proto"
	"golang.org/x/net/proxy"
)

type Session interface {
	Close() error

	StartTunnel(ctx context.Context, cfg ToTunnelConfig) (Tunnel, error)
}

//go:embed ngrok.ca.crt
var defaultCACert []byte

const defaultServer = "tunnel.ngrok.com:443"

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ConnectConfig struct {
	AuthToken  string
	ServerAddr string
	CAPool     *x509.CertPool

	Dialer Dialer

	Resolver *net.Resolver
	ProxyURL *url.URL

	Metadata string

	HeartbeatConfig *muxado.HeartbeatConfig

	Logger log15.Logger
}

func ConnectOptions() *ConnectConfig {
	return &ConnectConfig{
		HeartbeatConfig: muxado.NewHeartbeatConfig(),
	}
}

func (cfg *ConnectConfig) WithMetadata(meta string) *ConnectConfig {
	cfg.Metadata = meta
	return cfg
}

func (cfg *ConnectConfig) WithDialer(dialer Dialer) *ConnectConfig {
	cfg.Dialer = dialer
	return cfg
}

func (cfg *ConnectConfig) WithProxyURL(url *url.URL) *ConnectConfig {
	cfg.ProxyURL = url
	return cfg
}

func (cfg *ConnectConfig) WithResolver(resolver *net.Resolver) *ConnectConfig {
	cfg.Resolver = resolver
	return cfg
}

func (cfg *ConnectConfig) WithAuthToken(token string) *ConnectConfig {
	cfg.AuthToken = token
	return cfg
}

func (cfg *ConnectConfig) WithServer(addr string) *ConnectConfig {
	cfg.ServerAddr = addr
	return cfg
}

func (cfg *ConnectConfig) WithCA(pool *x509.CertPool) *ConnectConfig {
	cfg.CAPool = pool
	return cfg
}

func (cfg *ConnectConfig) WithHeartbeatTolerance(tolerance time.Duration) *ConnectConfig {
	cfg.HeartbeatConfig.Tolerance = tolerance
	return cfg
}

func (cfg *ConnectConfig) WithHeartbeatInterval(interval time.Duration) *ConnectConfig {
	cfg.HeartbeatConfig.Interval = interval
	return cfg
}

func (cfg *ConnectConfig) WithLogger(logger log15.Logger) *ConnectConfig {
	cfg.Logger = logger
	return cfg
}

func Connect(ctx context.Context, cfg *ConnectConfig) (Session, error) {
	var err error
	if cfg.CAPool == nil {
		cfg.CAPool = x509.NewCertPool()
		cfg.CAPool.AppendCertsFromPEM(defaultCACert)
	}

	if cfg.ServerAddr == "" {
		cfg.ServerAddr = defaultServer
	}

	tlsConfig := &tls.Config{
		RootCAs:    cfg.CAPool,
		ServerName: strings.Split(cfg.ServerAddr, ":")[0],
		MinVersion: tls.VersionTLS12,
	}

	if cfg.Logger == nil {
		cfg.Logger = log15.New()
		cfg.Logger.SetHandler(log15.DiscardHandler())
	}

	var dialer Dialer

	if cfg.Dialer != nil {
		dialer = cfg.Dialer
	} else {
		netDialer := &net.Dialer{
			Resolver: cfg.Resolver,
		}

		if cfg.ProxyURL != nil {
			proxied, err := proxy.FromURL(cfg.ProxyURL, netDialer)
			if err != nil {
				return nil, fmt.Errorf("failed to construct proxy dialer: %w", err)
			}
			dialer = proxied.(Dialer)
		} else {
			dialer = netDialer
		}
	}

	conn, err := dialer.DialContext(ctx, "tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ngrok server: %w", err)
	}

	conn = tls.Client(conn, tlsConfig)

	sess := muxado.Client(conn, &muxado.Config{})

	tunnelSess := tunnel_client.NewSession(cfg.Logger, sess, cfg.HeartbeatConfig, nopHandler{})
	resp, err := tunnelSess.Auth(proto.AuthExtra{
		Version:   "4.0.0-library",
		Authtoken: cfg.AuthToken,
		Metadata:  cfg.Metadata,
		// TODO: More metadata here
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send auth request: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("authentication error: %s", resp.Error)
	}

	return &sessionImpl{
		TunnelSession: tunnelSess,
	}, nil
}

type sessionImpl struct {
	TunnelSession tunnel_client.Session
}

func (s *sessionImpl) Close() error {
	return s.TunnelSession.Close()
}

func (s *sessionImpl) StartTunnel(ctx context.Context, cfg ToTunnelConfig) (Tunnel, error) {
	var (
		tunnel tunnel_client.Tunnel
		err    error
	)

	tunnelCfg := cfg.ToTunnelConfig()

	if tunnelCfg.proto != "" {
		tunnel, err = s.TunnelSession.Listen(tunnelCfg.proto, tunnelCfg.opts, tunnelCfg.extra, tunnelCfg.forwardsTo)
	} else {
		tunnel, err = s.TunnelSession.ListenLabel(tunnelCfg.labels, tunnelCfg.extra.Metadata, tunnelCfg.forwardsTo)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to start tunnel: %w", err)
	}

	return &tunnelImpl{
		Tunnel: tunnel,
	}, nil
}
