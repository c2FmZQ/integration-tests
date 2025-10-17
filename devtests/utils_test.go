package integration_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// httpClient returns an http.Client that's configured to trust tlsproxy's
// current ephemeral certificate authority. This is safefor testing. Don't do
// this in prod.
func httpClient(t *testing.T) *http.Client {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	pool := x509.NewCertPool()
	for {
		c, err := tls.Dial("tcp", "www.example.com:443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			pc := c.ConnectionState().PeerCertificates
			pool.AddCert(pc[len(pc)-1])
			c.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("httpClient: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}
}

// httpClientECH return an http.Client that's configured to trust tlsproxy's
// current ephemeral certificate authority, and that can use Encrypted Client
// Hello with tlsproxy.
func httpClientECH(t *testing.T) *http.Client {
	client := httpClient(t)
	resp, err := client.Get("https://www.example.com/.ech")
	if err != nil {
		t.Fatalf("ech: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ech body: %v", err)
	}
	ech, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		t.Fatalf("ech decode: %v", err)
	}
	client.Transport.(*http.Transport).TLSClientConfig.EncryptedClientHelloConfigList = ech
	return client
}

func click(t *testing.T, ctx context.Context, selector string) bool {
	t.Helper()
	defer time.Sleep(100 * time.Millisecond)
	var present bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(function(){
		const el = document.querySelector('`+selector+`');
		if (el) {
			el.click();
			return true;
		}
		return false;
	}())`, &present)); err != nil {
		t.Logf("click(%s): %v", selector, err)
		return false
	}
	if present {
		t.Logf("clicked %s", selector)
	}
	return present
}

func navigateWithSSO(t *testing.T, ctx context.Context, id, url string) error {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	elems := []string{
		`button[tkey=sso-login]`,
		`a.user-id-link[href*="` + id + `"]`,
	}
	for {
		var clicked bool
		for _, e := range elems {
			if click(t, ctx, e) {
				clicked = true
				break
			}
		}
		if clicked {
			continue
		}
		break
	}
	return nil
}

func screenshot(t *testing.T, ctx context.Context, filename string) {
	t.Helper()
	var buf []byte
	if err := chromedp.Run(context.WithoutCancel(ctx),
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		t.Fatalf("Failed to take screenshot: %v", err)
	}
	if err := os.WriteFile(filename, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func dumpPageContent(t *testing.T, ctx context.Context) {
	t.Helper()
	var pageContent string
	if err := chromedp.Run(context.WithoutCancel(ctx),
		chromedp.WaitReady(`body`),
		chromedp.OuterHTML(`body`, &pageContent, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("OuterHTML(body): %v", err)
	}
	t.Logf("==== PAGE CONTENT ====\n%s\n======================", pageContent)
}

func navigateContains(t *testing.T, ctx context.Context, id, url, content string) {
	t.Helper()
	if err := navigateWithSSO(t, ctx, id, url); err != nil {
		t.Fatalf("navigate(%s): %v", url, err)
	}
	var pageContent string
	if err := chromedp.Run(ctx,
		chromedp.WaitReady(`body`),
		chromedp.OuterHTML(`body`, &pageContent, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("OuterHTML(body): %v", err)
	}
	if !strings.Contains(pageContent, content) {
		screenshot(t, ctx, "screenshot-navigate-contains.png")
		t.Fatalf("Content = %s, want %s", pageContent, content)
	}
}

func clearCookies(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := chromedp.Run(ctx, network.ClearBrowserCookies()); err != nil {
		t.Fatalf("clearCookies: %v", err)
	}
}
