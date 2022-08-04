package libngrok

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io/ioutil"
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

type Scheme string

const SchemeHTTP = Scheme("http")
const SchemeHTTPS = Scheme("https")

type ConnectConfig struct {
	AuthToken  string
	ServerAddr string
	CACert     string

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

func (cfg *ConnectConfig) WithCA(path string) *ConnectConfig {
	cfg.CACert = path
	return cfg
}

func (cfg *ConnectConfig) WithLogger(logger log15.Logger) *ConnectConfig {
	cfg.Logger = logger
	return cfg
}

type Headers struct {
	Add    map[string]string
	Remove []string
}

func (h *Headers) AddHeader(name, value string) *Headers {
	h.Add[name] = value
	return h
}

func (h *Headers) RemoveHeader(name string) *Headers {
	h.Remove = append(h.Remove, name)
	return h
}

func (h *Headers) toProtoConfig() *pb_agent.MiddlewareConfiguration_Headers {
	if h == nil {
		return nil
	}

	headers := &pb_agent.MiddlewareConfiguration_Headers{
		Remove: h.Remove,
	}

	for k, v := range h.Add {
		headers.Add = append(headers.Add, fmt.Sprintf("%s:%s", k, v))
	}

	return headers
}

func HTTPHeaders() *Headers {
	return &Headers{
		Add:    map[string]string{},
		Remove: []string{},
	}
}

type ProxyProtoVersion int32

const (
	ProxyProtoV1 = ProxyProtoVersion(1)
	ProxyProtoV2 = ProxyProtoVersion(2)
)

type HTTPConfig struct {
	parent *TunnelConfig

	Scheme         Scheme
	Hostname       string
	Subdomain      string
	Compression    bool
	CircuitBreaker float64

	RequestHeaders  *Headers
	ResponseHeaders *Headers

	BasicAuth           *BasicAuth
	OAuth               *OAuth
	WebhookVerification *WebhookVerification

	MutualTLSCA []byte
}

type TCPConfig struct {
	parent     *TunnelConfig
	RemoteAddr string
}

type IPRestriction struct {
	AllowCIDRs []string
	DenyCIDRs  []string
}

func IPRestrictionSet() *IPRestriction {
	return &IPRestriction{}
}

func (ir *IPRestriction) AllowCIDR(cidr ...string) *IPRestriction {
	ir.AllowCIDRs = append(ir.AllowCIDRs, cidr...)
	return ir
}

func (ir *IPRestriction) DenyCIDR(cidr ...string) *IPRestriction {
	ir.DenyCIDRs = append(ir.DenyCIDRs, cidr...)
	return ir
}

func (ir *IPRestriction) toProtoConfig() *pb_agent.MiddlewareConfiguration_IPRestriction {
	if ir == nil {
		return nil
	}

	return &pb_agent.MiddlewareConfiguration_IPRestriction{
		AllowCIDRs: ir.AllowCIDRs,
		DenyCIDRs:  ir.DenyCIDRs,
	}
}

type CommonConfig struct {
	parent         *TunnelConfig
	IPRestrictions *IPRestriction
	ProxyProto     ProxyProtoVersion
}

type TunnelConfig struct {
	*CommonConfig
	*HTTPConfig
	*TCPConfig
}

func newTunnelConfig() *TunnelConfig {
	opts := &TunnelConfig{
		CommonConfig: &CommonConfig{},
	}
	opts.CommonConfig.parent = opts
	return opts
}

func TCPOptions() *TunnelConfig {
	opts := newTunnelConfig()
	opts.TCPConfig = &TCPConfig{parent: opts}
	return opts
}

func HTTPOptions() *TunnelConfig {
	opts := newTunnelConfig()
	opts.HTTPConfig = &HTTPConfig{parent: opts}
	return opts
}

func (http *HTTPConfig) WithScheme(scheme Scheme) *TunnelConfig {
	http.Scheme = scheme
	return http.parent
}

func (http *HTTPConfig) WithSubdomain(domain string) *TunnelConfig {
	http.Subdomain = domain
	return http.parent
}

func (http *HTTPConfig) WithHostname(hostname string) *TunnelConfig {
	http.Hostname = hostname
	return &TunnelConfig{
		HTTPConfig: http,
	}
}

func (http *HTTPConfig) WithCompression() *TunnelConfig {
	http.Compression = true
	return &TunnelConfig{
		HTTPConfig: http,
	}
}

func (http *HTTPConfig) WithCircuitBreaker(ratio float64) *TunnelConfig {
	http.CircuitBreaker = ratio
	return &TunnelConfig{
		HTTPConfig: http,
	}
}

func (http *HTTPConfig) WithRequestHeaders(headers *Headers) *TunnelConfig {
	http.RequestHeaders = headers
	return &TunnelConfig{
		HTTPConfig: http,
	}
}

func (http *HTTPConfig) WithResponseHeaders(headers *Headers) *TunnelConfig {
	http.ResponseHeaders = headers
	return http.parent
}

type BasicAuth struct {
	Username, Password string
}

func (ba *BasicAuth) toProtoConfig() *pb_agent.MiddlewareConfiguration_BasicAuth {
	if ba == nil {
		return nil
	}
	return &pb_agent.MiddlewareConfiguration_BasicAuth{
		Credentials: []*pb_agent.MiddlewareConfiguration_BasicAuthCredential{{
			CleartextPassword: ba.Password,
			Username:          ba.Username,
		}},
	}
}

type OAuth struct {
	Provider     OAuthProvider
	AllowEmails  []string
	AllowDomains []string
	Scopes       []string
}

type OAuthProvider string

const (
	OAuthGoogle    = OAuthProvider("google")
	OAuthFacebook  = OAuthProvider("facebook")
	OAuthGitHub    = OAuthProvider("github")
	OAuthMicrosoft = OAuthProvider("microsoft")
)

func (http *HTTPConfig) WithOAuth(provider OAuthProvider, allowEmails, allowDomains, scopes []string) *TunnelConfig {
	http.OAuth = &OAuth{
		Provider:     provider,
		AllowEmails:  allowEmails,
		AllowDomains: allowDomains,
		Scopes:       scopes,
	}

	return http.parent
}

func (oauth *OAuth) toProtoConfig() *pb_agent.MiddlewareConfiguration_OAuth {
	if oauth == nil {
		return nil
	}

	return &pb_agent.MiddlewareConfiguration_OAuth{
		Provider:     string(oauth.Provider),
		AllowEmails:  oauth.AllowEmails,
		AllowDomains: oauth.AllowDomains,
		Scopes:       oauth.Scopes,
	}
}

func (http *HTTPConfig) WithBasicAuth(username, password string) *TunnelConfig {
	http.BasicAuth = &BasicAuth{
		Username: username,
		Password: password,
	}
	return http.parent
}

func (http *HTTPConfig) WithMutualTLS(caBytes []byte) *TunnelConfig {
	http.MutualTLSCA = caBytes
	return http.parent
}

func (cfg *CommonConfig) WithProxyProto(version ProxyProtoVersion) *TunnelConfig {
	cfg.ProxyProto = version
	return cfg.parent
}

type WebhookVerification struct {
	Provider string
	Secret   string
}

func (http *HTTPConfig) WithWebhookVerification(provider string, secret string) *TunnelConfig {
	http.WebhookVerification = &WebhookVerification{
		Provider: provider,
		Secret:   secret,
	}
	return http.parent
}

func (wv *WebhookVerification) toProtoConfig() *pb_agent.MiddlewareConfiguration_WebhookVerification {
	if wv == nil {
		return nil
	}
	return &pb_agent.MiddlewareConfiguration_WebhookVerification{
		Provider: wv.Provider,
		Secret:   wv.Secret,
	}
}

func (http *HTTPConfig) toProtoConfig() *proto.HTTPOptions {
	opts := &proto.HTTPOptions{
		Hostname:  http.Hostname,
		Subdomain: http.Subdomain,
	}

	if http.Compression {
		opts.Compression = &pb_agent.MiddlewareConfiguration_Compression{}
	}

	if http.CircuitBreaker != 0 {
		opts.CircuitBreaker = &pb_agent.MiddlewareConfiguration_CircuitBreaker{
			ErrorThreshold: http.CircuitBreaker,
		}
	}

	if http.MutualTLSCA != nil {
		opts.MutualTLSCA = &pb_agent.MiddlewareConfiguration_MutualTLS{
			MutualTLSCA: http.MutualTLSCA,
		}
	}

	opts.ProxyProto = proto.ProxyProto(http.parent.ProxyProto)

	opts.RequestHeaders = http.RequestHeaders.toProtoConfig()
	opts.ResponseHeaders = http.ResponseHeaders.toProtoConfig()
	opts.BasicAuth = http.BasicAuth.toProtoConfig()
	opts.OAuth = http.OAuth.toProtoConfig()
	opts.WebhookVerification = http.WebhookVerification.toProtoConfig()
	opts.IPRestriction = http.parent.IPRestrictions.toProtoConfig()

	return opts
}

func (tcp *TCPConfig) WithRemoteAddr(addr string) *TunnelConfig {
	tcp.RemoteAddr = addr
	return tcp.parent
}

func (tcp *TCPConfig) toProtoConfig() *proto.TCPOptions {
	return &proto.TCPOptions{
		Addr:          tcp.RemoteAddr,
		IPRestriction: tcp.parent.IPRestrictions.toProtoConfig(),
		ProxyProto:    proto.ProxyProto(tcp.parent.ProxyProto),
	}
}

func (cfg *CommonConfig) WithIPRestriction(set *IPRestriction) *TunnelConfig {
	if cfg.IPRestrictions != nil && set != nil {
		cfg.IPRestrictions.AllowCIDR(set.AllowCIDRs...)
		cfg.IPRestrictions.DenyCIDR(set.DenyCIDRs...)
	} else {
		cfg.IPRestrictions = set
	}
	return cfg.parent
}

type Session interface {
	Close() error

	StartTunnel(ctx context.Context, cfg *TunnelConfig) (Tunnel, error)
}

func Connect(ctx context.Context, cfg *ConnectConfig) (Session, error) {
	var (
		caContents []byte
		err        error
	)
	if cfg.CACert != "" {
		caContents, err = ioutil.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	} else {
		caContents = defaultCACert
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caContents)

	if cfg.ServerAddr == "" {
		cfg.ServerAddr = defaultServer
	}

	tlsConfig := &tls.Config{
		RootCAs:    pool,
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

func (s *sessionImpl) StartTunnel(ctx context.Context, cfg *TunnelConfig) (Tunnel, error) {
	var listen func() (tunnel_client.Tunnel, error)

	if cfg.HTTPConfig != nil {
		opts := cfg.HTTPConfig.toProtoConfig()
		listen = func() (tunnel_client.Tunnel, error) {
			switch cfg.Scheme {
			case "", SchemeHTTPS:
				return s.TunnelSession.ListenHTTPS(opts, proto.BindExtra{}, "application")
			case SchemeHTTP:
				return s.TunnelSession.ListenHTTP(opts, proto.BindExtra{}, "application")
			default:
				return nil, fmt.Errorf("invalid scheme for HTTP tunnel: %s", cfg.Scheme)
			}
		}
	}

	if cfg.TCPConfig != nil {
		if listen != nil {
			return nil, fmt.Errorf("multiple tunnel configs provided")
		}
		opts := cfg.TCPConfig.toProtoConfig()
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
