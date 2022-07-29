package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	libngrok "github.com/ngrok/libngrok-go"
)

func main() {
	ctx := context.Background()
	sess, err := libngrok.Connect(ctx, libngrok.
		ConnectOptions("1yEmu1I7Nk4SqxKtdQwVbcBGdHk_53NW4yEmNDBnufjb1XDod").
		WithServer("tunnel.us.ngrok.com.lan:443").
		WithCA("./ca.crt"),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tun, err := sess.StartTunnel(ctx, libngrok.
		HTTPOptions().WithDomain("foo.ngrok.io.lan"),
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("url: ", tun.URL())
	err = http.Serve(tun, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(rw, "Hello, world!")
	}))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
