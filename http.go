package libngrok

import (
	"github.com/ngrok/libngrok-go/internal/pb_agent"
	"github.com/ngrok/libngrok-go/internal/tunnel/proto"
)

type Scheme string

const SchemeHTTP = Scheme("http")
const SchemeHTTPS = Scheme("https")

func HTTPHeaders() *Headers {
	return &Headers{
		Added:   map[string]string{},
		Removed: []string{},
	}
}

type HTTPConfig struct {
	*CommonConfig[HTTPConfig]

	Scheme         Scheme
	Compression    bool
	CircuitBreaker float64

	RequestHeaders  *Headers
	ResponseHeaders *Headers

	BasicAuth           []*BasicAuth
	OAuth               *OAuth
	WebhookVerification *WebhookVerification
}

func HTTPOptions() *HTTPConfig {
	opts := &HTTPConfig{
		Scheme: SchemeHTTPS,
	}

	opts.CommonConfig = &CommonConfig[HTTPConfig]{
		parent: opts,
	}

	return opts
}

func (http *HTTPConfig) WithScheme(scheme Scheme) *HTTPConfig {
	http.Scheme = scheme
	return http
}

func (http *HTTPConfig) WithCompression() *HTTPConfig {
	http.Compression = true
	return http
}

func (http *HTTPConfig) WithCircuitBreaker(ratio float64) *HTTPConfig {
	http.CircuitBreaker = ratio
	return http
}

func (http *HTTPConfig) WithRequestHeaders(headers *Headers) *HTTPConfig {
	http.RequestHeaders = headers
	return http
}

func (http *HTTPConfig) WithResponseHeaders(headers *Headers) *HTTPConfig {
	http.ResponseHeaders = headers
	return http
}

type BasicAuth struct {
	Username, Password string
}

func (ba *BasicAuth) toProtoConfig() *pb_agent.MiddlewareConfiguration_BasicAuthCredential {
	if ba == nil {
		return nil
	}
	return &pb_agent.MiddlewareConfiguration_BasicAuthCredential{
		CleartextPassword: ba.Password,
		Username:          ba.Username,
	}
}

type OAuth struct {
	Provider     string
	AllowEmails  []string
	AllowDomains []string
	Scopes       []string
}

func OAuthProvider(name string) *OAuth {
	return &OAuth{
		Provider: name,
	}
}

func (p *OAuth) AllowEmail(addr string) *OAuth {
	p.AllowEmails = append(p.AllowEmails, addr)
	return p
}

func (p *OAuth) AllowDomain(domain string) *OAuth {
	p.AllowDomains = append(p.AllowDomains, domain)
	return p
}

func (p *OAuth) WithScope(scope string) *OAuth {
	p.Scopes = append(p.Scopes, scope)
	return p
}

func (http *HTTPConfig) WithOAuth(cfg *OAuth) *HTTPConfig {
	http.OAuth = cfg
	return http
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

func (http *HTTPConfig) WithBasicAuth(username, password string) *HTTPConfig {
	http.BasicAuth = append(http.BasicAuth, &BasicAuth{
		Username: username,
		Password: password,
	})
	return http
}

type WebhookVerification struct {
	Provider string
	Secret   string
}

func (http *HTTPConfig) WithWebhookVerification(provider string, secret string) *HTTPConfig {
	http.WebhookVerification = &WebhookVerification{
		Provider: provider,
		Secret:   secret,
	}
	return http
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

	opts.ProxyProto = proto.ProxyProto(http.ProxyProto)

	opts.RequestHeaders = http.RequestHeaders.toProtoConfig()
	opts.ResponseHeaders = http.ResponseHeaders.toProtoConfig()
	if len(http.BasicAuth) > 0 {
		opts.BasicAuth = &pb_agent.MiddlewareConfiguration_BasicAuth{}
		for _, c := range http.BasicAuth {
			opts.BasicAuth.Credentials = append(opts.BasicAuth.Credentials, c.toProtoConfig())
		}
	}
	opts.OAuth = http.OAuth.toProtoConfig()
	opts.WebhookVerification = http.WebhookVerification.toProtoConfig()
	opts.IPRestriction = http.CIDRRestrictions.toProtoConfig()

	return opts
}

func (cfg *HTTPConfig) ToTunnelConfig() TunnelConfig {
	return TunnelConfig{
		proto: string(cfg.Scheme),
		opts:  cfg.toProtoConfig(),
	}
}
