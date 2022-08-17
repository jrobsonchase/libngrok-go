package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/davecgh/go-spew/spew"
	libngrok "github.com/ngrok/libngrok-go"
)

func exitErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
func main() {
	ctx := context.Background()

	proxyURL, err := url.Parse("socks5://localhost:1080")
	exitErr(err)

	opts := libngrok.ConnectOptions().
		WithAuthToken(os.Getenv("NGROK_TOKEN")).
		WithServer(os.Getenv("NGROK_SERVER")).
		WithMetadata("Hello, world!").
		WithProxyURL(proxyURL)
	if caPath := os.Getenv("NGROK_CA"); caPath != "" {
		caBytes, err := ioutil.ReadFile(caPath)
		exitErr(err)
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(caBytes)
		if !ok {
			exitErr(errors.New("failed to add CA Certificates"))
		}
		opts.WithCA(pool)
	}
	sess, err := libngrok.Connect(ctx, opts)
	exitErr(err)

	tun, err := sess.StartTunnel(ctx, libngrok.
		HTTPOptions().
		WithMetadata(`{"foo":"bar"}`).
		WithForwardsTo("foobarbaz"),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	l := tun.AsHTTP()
	fmt.Println("url: ", l.URL())

	err = l.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spew.Fdump(w, r)
	}))
	exitErr(err)
}
