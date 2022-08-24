package libngrok

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/inconshreveable/log15"
	"github.com/inconshreveable/muxado"
	tunnel_client "github.com/ngrok/libngrok-go/internal/tunnel/client"
	"github.com/ngrok/libngrok-go/internal/tunnel/proto"
	"golang.org/x/net/proxy"
)

const VERSION = "4.0.0-library"

type Session interface {
	Close() error

	StartTunnel(ctx context.Context, cfg TunnelConfig) (Tunnel, error)

	SrvInfo() (SrvInfo, error)
	AuthResp() AuthResp

	Heartbeat() (time.Duration, error)

	Latency() <-chan time.Duration
}

//go:embed ngrok.ca.crt
var defaultCACert []byte

const defaultServer = "tunnel.ngrok.com:443"

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Callbacks in response to local(ish) network events.
type LocalCallbacks struct {
	// Called any time a session (re)connects.
	OnConnect func(sess Session)
	// Called any time a session disconnects.
	// If the session has been closed locally, `OnDisconnect` will be called a
	// final time with a `nil` `err`.
	OnDisconnect func(sess Session, err error)
	// Called any time an automatic heartbeat response is received.
	// This does not include on-demand heartbeating via the `Session.Heartbeat`
	// method.
	OnHeartbeat func(sess Session, latency time.Duration)
}

// Callbacks in response to remote requests
type RemoteCallbacks struct {
	// Called when a stop is requested via the dashboard or API.
	// If it returns nil, success will be reported and the session closed.
	OnStop func(sess Session) error
	// Called when a restart is requested via the dashboard or API.
	// If it returns nil, success will be reported and the session closed.
	// It is the implementer's responsibility to ensure that the application
	// recreates the session.
	OnRestart func(sess Session) error
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

	LocalCallbacks  LocalCallbacks
	RemoteCallbacks RemoteCallbacks

	Cookie string

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

func (cfg *ConnectConfig) WithLocalCallbacks(callbacks LocalCallbacks) *ConnectConfig {
	cfg.LocalCallbacks = callbacks
	return cfg
}

func (cfg *ConnectConfig) WithRemoteCallbacks(callbacks RemoteCallbacks) *ConnectConfig {
	cfg.RemoteCallbacks = callbacks
	return cfg
}

func (cfg *ConnectConfig) WithReconnectCookie(cookie string) *ConnectConfig {
	cfg.Cookie = cookie
	return cfg
}

func Connect(ctx context.Context, cfg *ConnectConfig) (Session, error) {
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

	session := new(sessionImpl)

	stateChanges := make(chan error, 32)

	callbackHandler := remoteCallbackHandler{
		Logger: cfg.Logger,
		sess:   session,
		cb:     cfg.RemoteCallbacks,
	}

	rawDialer := func() (tunnel_client.RawSession, error) {
		conn, err := dialer.DialContext(ctx, "tcp", cfg.ServerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to ngrok server: %w", err)
		}

		conn = tls.Client(conn, tlsConfig)

		sess := muxado.Client(conn, &muxado.Config{})
		return tunnel_client.NewRawSession(cfg.Logger, sess, cfg.HeartbeatConfig, callbackHandler), nil
	}

	empty := ""
	notImplemented := "not implemented"
	notSupported := "libraries don't support remote updates"

	var remoteStopErr, remoteRestartErr = &notImplemented, &notImplemented
	if cfg.RemoteCallbacks.OnStop != nil {
		remoteStopErr = &empty
	}
	if cfg.RemoteCallbacks.OnRestart != nil {
		remoteRestartErr = &empty
	}

	auth := proto.AuthExtra{
		Version:            VERSION,
		Authtoken:          cfg.AuthToken,
		Metadata:           cfg.Metadata,
		OS:                 runtime.GOOS,
		Arch:               runtime.GOARCH,
		HeartbeatInterval:  int64(cfg.HeartbeatConfig.Interval),
		HeartbeatTolerance: int64(cfg.HeartbeatConfig.Tolerance),

		RestartUnsupportedError: remoteRestartErr,
		StopUnsupportedError:    remoteStopErr,
		UpdateUnsupportedError:  &notSupported,

		Cookie: cfg.Cookie,

		// TODO: More fields here?
	}

	reconnect := func(sess tunnel_client.Session) error {
		resp, err := sess.Auth(auth)
		if err != nil {
			if resp.Error == "" {
				return fmt.Errorf("failed to send auth request: %w", err)
			}
			return errors.New(resp.Error)
		}

		session.setInner(&sessionInner{
			Session:  sess,
			AuthResp: resp,
		})

		if cfg.LocalCallbacks.OnHeartbeat != nil {
			go func() {
				beats := session.Latency()
				for {
					select {
					case <-ctx.Done():
						return
					case latency, ok := <-beats:
						if !ok {
							return
						}
						cfg.LocalCallbacks.OnHeartbeat(session, latency)
					}
				}
			}()
		}

		auth.Cookie = resp.Extra.Cookie
		return nil
	}

	_ = tunnel_client.NewReconnectingSession(cfg.Logger, rawDialer, stateChanges, reconnect)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-stateChanges:
		if err != nil {
			return nil, err
		}
	}

	if cfg.LocalCallbacks.OnConnect != nil {
		cfg.LocalCallbacks.OnConnect(session)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-stateChanges:
				if !ok {
					if cfg.LocalCallbacks.OnDisconnect != nil {
						cfg.Logger.Info("no more state changes")
						cfg.LocalCallbacks.OnDisconnect(session, nil)
					}
					return
				}
				if err == nil && cfg.LocalCallbacks.OnConnect != nil {
					cfg.LocalCallbacks.OnConnect(session)
				}
				if err != nil && cfg.LocalCallbacks.OnDisconnect != nil {
					cfg.LocalCallbacks.OnDisconnect(session, err)
				}
			}
		}
	}()

	return session, nil
}

type sessionImpl struct {
	raw unsafe.Pointer
}

type sessionInner struct {
	tunnel_client.Session
	AuthResp proto.AuthResp
}

func (s *sessionImpl) inner() *sessionInner {
	ptr := atomic.LoadPointer(&s.raw)
	if ptr == nil {
		return nil
	}
	return (*sessionInner)(ptr)
}

func (s *sessionImpl) setInner(raw *sessionInner) {
	atomic.StorePointer(&s.raw, unsafe.Pointer(raw))
}

func (s *sessionImpl) Close() error {
	return s.inner().Close()
}

func (s *sessionImpl) StartTunnel(ctx context.Context, cfg TunnelConfig) (Tunnel, error) {
	var (
		tunnel tunnel_client.Tunnel
		err    error
	)

	tunnelCfg := cfg.tunnelConfig()

	if tunnelCfg.proto != "" {
		tunnel, err = s.inner().Listen(tunnelCfg.proto, tunnelCfg.opts, tunnelCfg.extra, tunnelCfg.forwardsTo)
	} else {
		tunnel, err = s.inner().ListenLabel(tunnelCfg.labels, tunnelCfg.extra.Metadata, tunnelCfg.forwardsTo)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to start tunnel: %w", err)
	}

	return &tunnelImpl{
		Tunnel: tunnel,
	}, nil
}

type SrvInfo proto.SrvInfoResp
type AuthResp proto.AuthResp

func (s *sessionImpl) AuthResp() AuthResp {
	return AuthResp(s.inner().AuthResp)
}

func (s *sessionImpl) SrvInfo() (SrvInfo, error) {
	resp, err := s.inner().SrvInfo()
	return SrvInfo(resp), err
}

func (s *sessionImpl) Heartbeat() (time.Duration, error) {
	return s.inner().Heartbeat()
}

func (s *sessionImpl) Latency() <-chan time.Duration {
	return s.inner().Latency()
}

type remoteCallbackHandler struct {
	log15.Logger
	sess Session
	cb   RemoteCallbacks
}

func (rc remoteCallbackHandler) OnStop(_ *proto.Stop, respond tunnel_client.HandlerRespFunc) {
	if rc.cb.OnStop != nil {
		resp := new(proto.StopResp)
		close := true
		if err := rc.cb.OnStop(rc.sess); err != nil {
			close = false
			resp.Error = err.Error()
		}
		if err := respond(resp); err != nil {
			rc.Warn("error responding to stop request", "error", err)
		}
		if close {
			_ = rc.sess.Close()
		}
	}
}

func (rc remoteCallbackHandler) OnRestart(_ *proto.Restart, respond tunnel_client.HandlerRespFunc) {
	if rc.cb.OnRestart != nil {
		resp := new(proto.RestartResp)
		close := true
		if err := rc.cb.OnRestart(rc.sess); err != nil {
			close = false
			resp.Error = err.Error()
		}
		if err := respond(resp); err != nil {
			rc.Warn("error responding to restart request", "error", err)
		}
		if close {
			_ = rc.sess.Close()
		}
	}

}
func (rc remoteCallbackHandler) OnUpdate(*proto.Update, tunnel_client.HandlerRespFunc) {}
