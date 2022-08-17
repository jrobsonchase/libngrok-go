package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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
	opts := libngrok.ConnectOptions().
		WithAuthToken(os.Getenv("NGROK_TOKEN")).
		WithServer(os.Getenv("NGROK_SERVER"))
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
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tun, err := sess.StartTunnel(ctx, libngrok.HTTPOptions().
		WithOAuth(libngrok.OAuthProvider("google").
			AllowDomain("ngrok.com"),
		),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	l := tun.AsTCP()
	fmt.Println("url: ", l.URL())

	err = http.Serve(&dumpListener{l}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spew.Fdump(w, r)
	}))

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type dumpListener struct {
	inner net.Listener
}

type dumpConn struct {
	net.Conn
}

func (dc *dumpConn) Read(bs []byte) (int, error) {
	n, err := dc.Conn.Read(bs)

	spew.Dump(bs[:n])

	return n, err
}

// Accept waits for and returns the next connection to the listener.
func (dl *dumpListener) Accept() (net.Conn, error) {
	inner, err := dl.inner.Accept()
	if err != nil {
		return nil, err
	}

	fmt.Println("accepted connection from", inner.RemoteAddr())

	return &dumpConn{inner}, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (dl *dumpListener) Close() error {
	return dl.inner.Close()
}

// Addr returns the listener's network address.
func (dl *dumpListener) Addr() net.Addr {
	return dl.inner.Addr()
}
