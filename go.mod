module github.com/ngrok/libngrok-go

go 1.18

require (
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac
	github.com/inconshreveable/muxado v0.0.0-20160802230925-fc182d90f26e
	github.com/jpillora/backoff v1.0.0
	github.com/stretchr/testify v1.8.0
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.0.0-20220812174116-3211cb980234
	golang.org/x/sys v0.0.0-20220728004956-3c1f35247d10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/inconshreveable/muxado => ./internal/muxado
