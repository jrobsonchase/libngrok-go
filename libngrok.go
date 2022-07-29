package libngrok

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/inconshreveable/muxado"

	tunnel_client "github.com/ngrok/libngrok-go/tunnel/client"
	"github.com/ngrok/libngrok-go/tunnel/proto"
)

type ConnectConfig struct {
	AuthToken  string `yaml:"authtoken"`
	ServerAddr string `yaml:"server_addr"`
	CACert     string `yaml:"ca_cert"`
}

func ConnectOptions(authtoken string) *ConnectConfig {
	return &ConnectConfig{
		AuthToken: authtoken,
	}
}

func (cfg *ConnectConfig) WithServer(addr string) *ConnectConfig {
	cfg.ServerAddr = addr
	return cfg
}

func (cfg *ConnectConfig) WithCA(path string) *ConnectConfig {
	cfg.CACert = path
	return cfg
}

type HTTPConfig struct {
	Domain string
}
type TCPConfig struct {
	RemoteAddr string
}

type TunnelConfig struct {
	*HTTPConfig
	*TCPConfig
}

func TCPOptions() *TunnelConfig {
	return &TunnelConfig{
		TCPConfig: &TCPConfig{},
	}
}
func HTTPOptions() *TunnelConfig {
	return &TunnelConfig{
		HTTPConfig: &HTTPConfig{},
	}
}

func (http *HTTPConfig) WithDomain(domain string) *TunnelConfig {
	http.Domain = domain
	return &TunnelConfig{
		HTTPConfig: http,
	}
}

func (http *HTTPConfig) ToProtoConfig() *proto.HTTPOptions {
	return &proto.HTTPOptions{
		Hostname: http.Domain,
	}
}

func (tcp *TCPConfig) WithRemoteAddr(addr string) *TunnelConfig {
	tcp.RemoteAddr = addr
	return &TunnelConfig{
		TCPConfig: tcp,
	}
}

func (tcp *TCPConfig) ToProtoConfig() *proto.TCPOptions {
	return &proto.TCPOptions{
		Addr: tcp.RemoteAddr,
	}
}

type Session interface {
	Close() error

	StartTunnel(ctx context.Context, cfg *TunnelConfig) (Tunnel, error)
}

func Connect(ctx context.Context, cfg *ConnectConfig) (Session, error) {
	caFile, err := ioutil.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caFile)

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		ServerName: strings.Split(cfg.ServerAddr, ":")[0],
		MinVersion: tls.VersionTLS12,
	}

	conn, err := net.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ngrok server: %w", err)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	sess := muxado.Client(tlsConn, nil)

	tunnelSess := tunnel_client.NewSession(sess, nopHandler{})
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

func (s *sessionImpl) StartTunnel(ctx context.Context, cfg *TunnelConfig) (Tunnel, error) {
	var listen func() (tunnel_client.Tunnel, error)

	if cfg.HTTPConfig != nil {
		opts := cfg.HTTPConfig.ToProtoConfig()
		listen = func() (tunnel_client.Tunnel, error) {
			return s.TunnelSession.ListenHTTP(opts, proto.BindExtra{}, "application")
		}
	}

	if cfg.TCPConfig != nil {
		if listen != nil {
			return nil, fmt.Errorf("multiple tunnel configs provided")
		}
		opts := cfg.TCPConfig.ToProtoConfig()
		listen = func() (tunnel_client.Tunnel, error) {
			return s.TunnelSession.ListenTCP(opts, proto.BindExtra{}, "application")
		}
	}

	tunnel, err := listen()
	if err != nil {
		return nil, fmt.Errorf("failed to start tunnel: %w", err)
	}

	return &tunnelImpl{
		Tunnel: tunnel,
	}, nil
}

type Tunnel interface {
	net.Listener

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
