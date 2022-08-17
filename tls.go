package libngrok

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/ngrok/libngrok-go/internal/pb_agent"
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

type TLSConfig struct {
	TLSCommon[TLSConfig]
	CommonConfig[TLSConfig]
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
