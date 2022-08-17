package libngrok

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/inconshreveable/muxado"

	"github.com/ngrok/libngrok-go/internal/pb_agent"
	tunnel_client "github.com/ngrok/libngrok-go/internal/tunnel/client"
	"github.com/ngrok/libngrok-go/internal/tunnel/proto"
)

//go:embed ngrok.ca.crt
var defaultCACert []byte

const defaultServer = "tunnel.ngrok.com:443"

type ConnectConfig struct {
	AuthToken  string
	ServerAddr string
	CAPool     *x509.CertPool

	Logger log15.Logger
}

func ConnectOptions() *ConnectConfig {
	return &ConnectConfig{}
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

func (cfg *ConnectConfig) WithLogger(logger log15.Logger) *ConnectConfig {
	cfg.Logger = logger
	return cfg
}

type Headers struct {
	Added   map[string]string
	Removed []string
}

func (h *Headers) Add(name, value string) *Headers {
	h.Added[name] = value
	return h
}

func (h *Headers) Remove(name string) *Headers {
	h.Removed = append(h.Removed, name)
	return h
}

func (h *Headers) toProtoConfig() *pb_agent.MiddlewareConfiguration_Headers {
	if h == nil {
		return nil
	}

	headers := &pb_agent.MiddlewareConfiguration_Headers{
		Remove: h.Removed,
	}

	for k, v := range h.Added {
		headers.Add = append(headers.Add, fmt.Sprintf("%s:%s", k, v))
	}

	return headers
}

type Session interface {
	Close() error

	StartTunnel(ctx context.Context, cfg ToTunnelConfig) (Tunnel, error)
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

	conn, err := net.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ngrok server: %w", err)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	sess := muxado.Client(tlsConn, nil)

	tunnelSess := tunnel_client.NewSession(cfg.Logger, sess, nopHandler{})
	resp, err := tunnelSess.Auth(proto.AuthExtra{
		// TODO: More metadata here
		Version:   "4.0.0-library",
		Authtoken: cfg.AuthToken,
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
		tunnel, err = s.TunnelSession.Listen(tunnelCfg.proto, tunnelCfg.opts, tunnelCfg.extra, "application")
	} else {
		tunnel, err = s.TunnelSession.ListenLabel(tunnelCfg.labels, tunnelCfg.metadata, "application")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to start tunnel: %w", err)
	}

	return &tunnelImpl{
		Tunnel: tunnel,
	}, nil
}

type Tunnel interface {
	net.Listener

	CloseWithContext(context.Context) error

	// Not available for labeled tunnels
	URL() string
	Proto() string

	// Metadata() string
	// Labels() map[string]string

	// ID() string
}

type tunnelImpl struct {
	Tunnel tunnel_client.Tunnel
}

func (t *tunnelImpl) Accept() (net.Conn, error) {
	conn, err := t.Tunnel.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept tunnel connection: %w", err)
	}
	return &connImpl{
		Conn:  conn.Conn,
		Proxy: conn,
	}, nil
}

func (t *tunnelImpl) Close() error {
	return t.Tunnel.Close()
}

func (t *tunnelImpl) CloseWithContext(_ context.Context) error {
	return t.Tunnel.Close()
}

func (t *tunnelImpl) Addr() net.Addr {
	return t.Tunnel.Addr()
}

func (t *tunnelImpl) URL() string {
	return t.Tunnel.RemoteBindConfig().URL
}

func (t *tunnelImpl) Proto() string {
	return t.Tunnel.RemoteBindConfig().ConfigProto
}

type Conn interface {
	net.Conn

	// other methods?
}

type connImpl struct {
	net.Conn
	Proxy *tunnel_client.ProxyConn
}

type nopHandler struct{}

func (nopHandler) OnStop(*proto.Stop, tunnel_client.HandlerRespFunc)       {}
func (nopHandler) OnRestart(*proto.Restart, tunnel_client.HandlerRespFunc) {}
func (nopHandler) OnUpdate(*proto.Update, tunnel_client.HandlerRespFunc)   {}
