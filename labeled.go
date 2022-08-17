package libngrok

type LabeledConfig struct {
	Labels   map[string]string
	Metadata string
}

func LabeledOptions() *LabeledConfig {
	opts := &LabeledConfig{
		Labels: map[string]string{},
	}
	return opts
}

func (lo *LabeledConfig) WithLabel(key, value string) *LabeledConfig {
	lo.Labels[key] = value
	return lo
}

func (lo *LabeledConfig) WithMetadata(meta string) *LabeledConfig {
	lo.Metadata = meta
	return lo
}

func (lo *LabeledConfig) ToTunnelConfig() TunnelConfig {
	return TunnelConfig{
		labels:   lo.Labels,
		metadata: lo.Metadata,
	}
}
