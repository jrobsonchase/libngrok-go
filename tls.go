package libngrok

type TLSConfig struct {
	*CommonConfig[TLSConfig]
}

func TLSOptions() *TLSConfig {
	opts := &TLSConfig{}
	opts.CommonConfig = &CommonConfig[TLSConfig]{
		parent: opts,
	}
	return opts
}
