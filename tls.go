package libngrok

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/ngrok/libngrok-go/internal/pb_agent"
	"github.com/ngrok/libngrok-go/internal/tunnel/proto"
)

type TLSCommon[T any] struct {
	parent *T

	Domain      string
	MutualTLSCA []*x509.Certificate
}

func (cfg *TLSCommon[T]) WithDomain(name string) *T {
	cfg.Domain = name
	return cfg.parent
}

func (cfg *TLSCommon[T]) WithMutualTLSCA(certs ...*x509.Certificate) *T {
	cfg.MutualTLSCA = append(cfg.MutualTLSCA, certs...)
	return cfg.parent
}

func (cfg *TLSCommon[T]) toProtoConfig() *pb_agent.MiddlewareConfiguration_MutualTLS {
	opts := &pb_agent.MiddlewareConfiguration_MutualTLS{}
	for _, cert := range cfg.MutualTLSCA {
		opts.MutualTLSCA = append(opts.MutualTLSCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return opts
}

type TLSKeypair struct {
	KeyPEM  []byte
	CertPEM []byte
}

type TLSConfig struct {
	TLSCommon[TLSConfig]
	CommonConfig[TLSConfig]

	TerminateKeypair *TLSKeypair
}

func (cfg *TLSConfig) WithEdgeTermination(certPEM, keyPEM []byte) *TLSConfig {
	cfg.TerminateKeypair = &TLSKeypair{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	return cfg
}

func TLSOptions() *TLSConfig {
	opts := &TLSConfig{}
	opts.TLSCommon = TLSCommon[TLSConfig]{
		parent: opts,
	}
	opts.CommonConfig = CommonConfig[TLSConfig]{
		parent: opts,
	}
	return opts
}

func (tls *TLSConfig) toProtoConfig() *proto.TLSOptions {
	opts := &proto.TLSOptions{
		Hostname:   tls.TLSCommon.Domain,
		ProxyProto: proto.ProxyProto(tls.CommonConfig.ProxyProto),
	}
	if tls.MutualTLSCA != nil {
		opts.MutualTLSAtEdge = tls.TLSCommon.toProtoConfig()
	}
	if tls.CIDRRestrictions != nil {
		opts.IPRestriction = tls.CIDRRestrictions.toProtoConfig()
	}
	if tls.TerminateKeypair != nil {
		opts.TLSTermination = &pb_agent.MiddlewareConfiguration_TLSTermination{
			Key:  tls.TerminateKeypair.KeyPEM,
			Cert: tls.TerminateKeypair.CertPEM,
		}
	}
	return opts
}

func (tls *TLSConfig) ToTunnelConfig() TunnelConfig {
	return TunnelConfig{
		proto: "tls",
		opts:  tls.toProtoConfig(),
		extra: proto.BindExtra{
			Metadata: tls.Metadata,
		},
	}
}
