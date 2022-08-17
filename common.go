package libngrok

import (
	"crypto/x509"
	"encoding/pem"
	"net"

	"github.com/ngrok/libngrok-go/internal/pb_agent"
)

type CommonConfig[T any] struct {
	Subdomain        string
	Hostname         string
	parent           *T
	CIDRRestrictions *CIDRRestriction
	ProxyProto       ProxyProtoVersion

	MutualTLSCA []byte
}

func (cfg *CommonConfig[T]) WithDomain(name string) *T {
	cfg.Hostname = name
	return cfg.parent
}

func (cfg *CommonConfig[T]) WithMutualTLSCA(certs []*x509.Certificate) *T {
	for _, cert := range certs {
		cfg.MutualTLSCA = append(cfg.MutualTLSCA, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return cfg.parent
}

type ProxyProtoVersion int32

const (
	ProxyProtoV1 = ProxyProtoVersion(1)
	ProxyProtoV2 = ProxyProtoVersion(2)
)

func (cfg *CommonConfig[T]) WithProxyProto(version ProxyProtoVersion) *T {
	cfg.ProxyProto = version
	return cfg.parent
}

type CIDRRestriction struct {
	Allowed []string
	Denied  []string
}

func CIDRSet() *CIDRRestriction {
	return &CIDRRestriction{}
}

func (cr *CIDRRestriction) AllowString(cidr ...string) *CIDRRestriction {
	cr.Allowed = append(cr.Allowed, cidr...)
	return cr
}

func (cr *CIDRRestriction) Allow(net ...*net.IPNet) *CIDRRestriction {
	for _, n := range net {
		cr.AllowString(n.String())
	}
	return cr
}

func (cr *CIDRRestriction) DenyString(cidr ...string) *CIDRRestriction {
	cr.Denied = append(cr.Denied, cidr...)
	return cr
}

func (cr *CIDRRestriction) Deny(net ...*net.IPNet) *CIDRRestriction {
	for _, n := range net {
		cr.DenyString(n.String())
	}
	return cr
}

func (ir *CIDRRestriction) toProtoConfig() *pb_agent.MiddlewareConfiguration_IPRestriction {
	if ir == nil {
		return nil
	}

	return &pb_agent.MiddlewareConfiguration_IPRestriction{
		AllowCIDRs: ir.Allowed,
		DenyCIDRs:  ir.Denied,
	}
}

func (cfg *CommonConfig[T]) WithCIDRRestriction(set *CIDRRestriction) *T {
	if cfg.CIDRRestrictions != nil && set != nil {
		cfg.CIDRRestrictions.AllowString(set.Allowed...)
		cfg.CIDRRestrictions.DenyString(set.Denied...)
	} else {
		cfg.CIDRRestrictions = set
	}
	return cfg.parent
}
