package libngrok

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

func setupSession(ctx context.Context, t *testing.T) Session {
	opts := ConnectOptions().WithAuthToken(os.Getenv("NGROK_TOKEN"))
	sess, err := Connect(ctx, opts)
	require.NoError(t, err, "Session Connect")
	return sess
}

func startTunnel(ctx context.Context, t *testing.T, sess Session, opts ToTunnelConfig) Tunnel {
	tun, err := sess.StartTunnel(ctx, opts)
	require.NoError(t, err, "StartTunnel")
	return tun
}

var helloHandler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintln(rw, "Hello, world!")
})

func serveHTTP(ctx context.Context, t *testing.T, opts ToTunnelConfig, handler http.Handler) (Tunnel, <-chan error) {
	sess := setupSession(ctx, t)

	tun := startTunnel(ctx, t, sess, opts)
	exited := make(chan error)

	httpTun := tun.AsHTTP()

	go func() {
		exited <- httpTun.Serve(handler)
	}()
	return tun, exited
}

func TestTunnel(t *testing.T) {
	ctx := context.Background()
	sess := setupSession(ctx, t)

	tun := startTunnel(ctx, t, sess, HTTPOptions().
		WithMetadata("Hello, world!").
		WithForwardsTo("some application"))

	require.NotEmpty(t, tun.URL(), "Tunnel URL")
	require.Equal(t, "Hello, world!", tun.Metadata())
	require.Equal(t, "some application", tun.ForwardsTo())
}

func TestHTTPS(t *testing.T) {
	ctx := context.Background()
	tun, exited := serveHTTP(ctx, t,
		HTTPOptions(),
		helloHandler,
	)

	resp, err := http.Get(tun.URL())
	require.NoError(t, err, "GET tunnel url")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.NotNil(t, resp.TLS, "TLS established")

	// Closing the tunnel should be fine
	require.NoError(t, tun.CloseWithContext(ctx))

	// The http server should exit with a "closed" error
	require.Error(t, <-exited)
}

func TestHTTP(t *testing.T) {
	ctx := context.Background()
	tun, exited := serveHTTP(ctx, t,
		HTTPOptions().
			WithScheme(SchemeHTTP),
		helloHandler,
	)

	resp, err := http.Get(tun.URL())
	require.NoError(t, err, "GET tunnel url")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.Nil(t, resp.TLS, "No TLS")

	// Closing the tunnel should be fine
	require.NoError(t, tun.CloseWithContext(ctx))

	// The http server should exit with a "closed" error
	require.Error(t, <-exited)
}

func TestHTTPCompression(t *testing.T) {
	ctx := context.Background()
	opts := HTTPOptions().WithCompression()
	tun, exited := serveHTTP(ctx, t, opts, helloHandler)

	req, err := http.NewRequest(http.MethodGet, tun.URL(), nil)
	require.NoError(t, err, "Create request")
	req.Header.Add("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "GET tunnel url")

	require.Equal(t, http.StatusOK, resp.StatusCode)

	gzReader, err := gzip.NewReader(resp.Body)
	require.NoError(t, err, "gzip reader")

	body, err := io.ReadAll(gzReader)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

// *testing.T wrapper to force `require` to Fail() then panic() rather than
// FailNow(). Permits better flow control in test functions.
type failPanic struct {
	t *testing.T
}

func (f failPanic) Errorf(format string, args ...interface{}) {
	f.t.Errorf(format, args...)
}

func (f failPanic) FailNow() {
	f.t.Fail()
	panic("test failed")
}

func TestHTTPHeaders(t *testing.T) {
	ctx := context.Background()
	opts := HTTPOptions().
		WithRequestHeaders(HTTPHeaders().
			Add("foo", "bar").
			Remove("baz")).
		WithResponseHeaders(HTTPHeaders().
			Add("spam", "eggs").
			Remove("python"))

	tun, exited := serveHTTP(ctx, t, opts, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		defer func() { _ = recover() }()
		t := failPanic{t}

		require.NotContains(t, r.Header, "Baz", "Baz Removed")
		require.Contains(t, r.Header, "Foo", "Foo added")
		require.Equal(t, "bar", r.Header.Get("Foo"), "Foo=bar")

		rw.Header().Add("Python", "bad header")
		_, _ = fmt.Fprintln(rw, "Hello, world!")
	}))

	req, err := http.NewRequest(http.MethodGet, tun.URL(), nil)
	require.NoError(t, err, "Create request")
	req.Header.Add("Baz", "bad header")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "GET tunnel url")

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.NotContains(t, resp.Header, "Python", "Python removed")
	require.Contains(t, resp.Header, "Spam", "Spam added")
	require.Equal(t, "eggs", resp.Header.Get("Spam"), "Spam=eggs")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestBasicAuth(t *testing.T) {
	ctx := context.Background()

	opts := HTTPOptions().WithBasicAuth("user", "foobarbaz")

	tun, exited := serveHTTP(ctx, t, opts, helloHandler)

	req, err := http.NewRequest(http.MethodGet, tun.URL(), nil)
	require.NoError(t, err, "Create request")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "GET tunnel url")

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	req.SetBasicAuth("user", "foobarbaz")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err, "GET tunnel url")

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestCircuitBreaker(t *testing.T) {
	// Don't run this one by default - it has to make ~50 requests.
	if os.Getenv("NGROK_TEST_LONG") == "" {
		t.Skip("Skipping long circuit breaker test")
		return
	}
	ctx := context.Background()

	opts := HTTPOptions().WithCircuitBreaker(0.1)

	n := 0
	tun, exited := serveHTTP(ctx, t, opts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n = n + 1
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	var (
		resp *http.Response
		err  error
	)

	for i := 0; i < 50; i++ {
		resp, err = http.Get(tun.URL())
		require.NoError(t, err)
	}

	// Should see fewer than 50 requests come through.
	require.Less(t, n, 50)

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

type TestConfig interface {
	ToTunnelConfig
	WithProxyProtoI(version ProxyProtoVersion) ToTunnelConfig
}

func (http *HTTPConfig) WithProxyProtoI(version ProxyProtoVersion) ToTunnelConfig {
	return http.WithProxyProto(version)
}

func (tcp *TCPConfig) WithProxyProtoI(version ProxyProtoVersion) ToTunnelConfig {
	return tcp.WithProxyProto(version)
}

func TestProxyProto(t *testing.T) {
	ctx := context.Background()

	type testCase struct {
		name          string
		optsFunc      func() TestConfig
		reqFunc       func(*testing.T, string)
		version       ProxyProtoVersion
		shouldContain string
	}

	base := []testCase{
		{
			version:       ProxyProtoV1,
			shouldContain: "PROXY TCP4",
		},
		{
			version:       ProxyProtoV2,
			shouldContain: "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A",
		},
	}

	var cases []testCase

	for _, c := range base {
		cases = append(cases,
			testCase{
				name:     fmt.Sprintf("HTTP/Version%d", c.version),
				optsFunc: func() TestConfig { return HTTPOptions() },
				reqFunc: func(t *testing.T, url string) {
					_, _ = http.Get(url)
				},
				version:       c.version,
				shouldContain: c.shouldContain,
			},
			testCase{
				name:     fmt.Sprintf("TCP/Version%d", c.version),
				optsFunc: func() TestConfig { return TCPOptions() },
				reqFunc: func(t *testing.T, u string) {
					url, err := url.Parse(u)
					require.NoError(t, err)
					conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", url.Hostname(), url.Port()))
					require.NoError(t, err)
					_, _ = fmt.Fprint(conn, "Hello, world!")
				},
				version:       c.version,
				shouldContain: c.shouldContain,
			},
		)
	}

	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			sess := setupSession(ctx, t)
			tun := startTunnel(ctx, t, sess, tcase.optsFunc().
				WithProxyProtoI(tcase.version),
			).AsListener()

			go tcase.reqFunc(t, tun.URL())

			conn, err := tun.Accept()
			require.NoError(t, err, "Accept connection")

			buf := make([]byte, 12)
			_, err = io.ReadAtLeast(conn, buf, 12)
			require.NoError(t, err, "Read connection contents")

			conn.Close()

			require.Contains(t, string(buf), tcase.shouldContain)
		})
	}
}

func TestHostname(t *testing.T) {
	ctx := context.Background()

	tun, exited := serveHTTP(ctx, t,
		HTTPOptions().WithDomain("foo.robsonchase.com"),
		helloHandler,
	)
	require.Equal(t, "https://foo.robsonchase.com", tun.URL())

	resp, err := http.Get(tun.URL())
	require.NoError(t, err)

	content, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, world!\n", string(content))

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestSubdomain(t *testing.T) {
	ctx := context.Background()

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, rand.Uint64())

	subdomain := hex.EncodeToString(buf)

	tun, exited := serveHTTP(ctx, t,
		HTTPOptions().WithDomain(subdomain+".ngrok.io"),
		helloHandler,
	)

	require.Contains(t, tun.URL(), subdomain)

	resp, err := http.Get(tun.URL())
	require.NoError(t, err)

	content, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, world!\n", string(content))

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestOAuth(t *testing.T) {
	ctx := context.Background()

	opts := HTTPOptions().WithOAuth(OAuthProvider("google"))

	tun, exited := serveHTTP(ctx, t, opts, helloHandler)

	resp, err := http.Get(tun.URL())
	require.NoError(t, err, "GET tunnel url")

	content, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotContains(t, string(content), "Hello, world!")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestHTTPIPRestriction(t *testing.T) {
	ctx := context.Background()

	_, cidr, err := net.ParseCIDR("0.0.0.0/0")
	require.NoError(t, err)

	opts := HTTPOptions().WithCIDRRestriction(
		CIDRSet().
			AllowString("127.0.0.1/32").
			Deny(cidr),
	)

	tun, exited := serveHTTP(ctx, t, opts, helloHandler)

	resp, err := http.Get(tun.URL())
	require.NoError(t, err, "GET tunnel url")

	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestTCP(t *testing.T) {
	ctx := context.Background()

	opts := TCPOptions()

	// Easier to test by pretending it's HTTP on this end.
	tun, exited := serveHTTP(ctx, t, opts, helloHandler)

	url, err := url.Parse(tun.URL())
	require.NoError(t, err)
	url.Scheme = "http"
	resp, err := http.Get(url.String())
	require.NoError(t, err, "GET tunnel url")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestTCPIPRestriction(t *testing.T) {
	ctx := context.Background()

	_, cidr, err := net.ParseCIDR("127.0.0.1/32")
	require.NoError(t, err)

	opts := TCPOptions().WithCIDRRestriction(
		CIDRSet().
			Allow(cidr).
			DenyString("0.0.0.0/0"),
	)

	// Easier to test by pretending it's HTTP on this end.
	tun, exited := serveHTTP(ctx, t, opts, helloHandler)

	url, err := url.Parse(tun.URL())
	require.NoError(t, err)
	url.Scheme = "http"
	_, err = http.Get(url.String())

	// Rather than layer-7 error, we should see it at the connection level
	require.Error(t, err, "GET Tunnel URL")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestLabeled(t *testing.T) {
	ctx := context.Background()
	tun, exited := serveHTTP(ctx, t,
		LabeledOptions().
			WithLabel("edge", "edghts_2CtuOWQFCrvggKT34fRCFXs0AiK").
			WithMetadata("Hello, world!"),
		helloHandler,
	)

	require.Equal(t, "Hello, world!", tun.Metadata())

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)

	for {
		require.NoError(t, ctx.Err(), "context deadline reached while waiting for edge")
		resp, err := http.Get("https://kzu7214a.ngrok.io/")
		require.NoError(t, err, "GET tunnel url")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Read response body")

		if string(body) == "Hello, world!\n" {
			break
		}
	}

	cancel()

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}

func TestWebsocketConversion(t *testing.T) {
	ctx := context.Background()
	sess := setupSession(ctx, t)
	tun := startTunnel(ctx, t, sess,
		HTTPOptions().
			WithWebsocketTCPConversion(),
	)

	// HTTP over websockets? suuuure lol
	exited := make(chan error)
	go func() {
		exited <- http.Serve(tun.AsListener(), helloHandler)
	}()

	resp, err := http.Get(tun.URL())
	require.NoError(t, err)

	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "Normal http should be rejected")

	url, err := url.Parse(tun.URL())
	require.NoError(t, err)

	url.Scheme = "wss"

	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return websocket.Dial(url.String(), "", tun.URL())
			},
		},
	}

	resp, err = client.Get("http://example.com")
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Read response body")

	require.Equal(t, "Hello, world!\n", string(body), "HTTP Body Contents")

	require.NoError(t, tun.CloseWithContext(ctx))
	require.Error(t, <-exited)
}
