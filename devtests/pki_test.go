package integration_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/chromedp"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestPKIGetCertificateP12(t *testing.T) {
	// create context
	ctx, cancel := chromedp.NewRemoteAllocator(t.Context(), chromeWS)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(t.Logf))
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	clearCookies(t, ctx)

	if err := chromedp.Run(ctx,
		browser.
			SetDownloadBehavior(browser.SetDownloadBehaviorBehaviorAllow).
			WithDownloadPath("/download").
			WithEventsEnabled(true),
	); err != nil {
		t.Fatalf("browser.SetDownloadBehavior: %v", err)
	}

	done := make(chan string, 1)
	chromedp.ListenTarget(ctx, func(v interface{}) {
		if ev, ok := v.(*browser.EventDownloadProgress); ok {
			completed := "(unknown)"
			if ev.TotalBytes != 0 {
				completed = fmt.Sprintf("%0.2f%%", ev.ReceivedBytes/ev.TotalBytes*100.0)
			}
			t.Logf("Download state: %s, completed: %s", ev.State.String(), completed)
			if ev.State == browser.DownloadProgressStateCompleted {
				select {
				case done <- ev.FilePath:
				default:
				}
			}
		}
	})

	url := "https://pki.example.com/manage"
	if err := navigateWithSSO(t, ctx, "alice@example.com", url); err != nil {
		dumpPageContent(t, ctx)
		t.Fatalf("navigate(%s): %v", url, err)
	}

	// Test PKI UI
	if err := chromedp.Run(ctx,
		chromedp.WaitVisible(`a[tkey="pki-new-cert"]`, chromedp.ByQuery),
		chromedp.Click(`a[tkey="pki-new-cert"]`, chromedp.ByQuery),

		chromedp.WaitVisible(`select[name=format]`, chromedp.ByQuery),
		chromedp.SetValue(`select[name=format]`, "p12", chromedp.ByQuery),
		chromedp.SetValue(`select[name=keytype]`, "ecdsa-p256", chromedp.ByQuery),
		chromedp.SetValue(`input[name=label]`, "test", chromedp.ByQuery),
		chromedp.SetValue(`select[name=usage]`, "client", chromedp.ByQuery),
		chromedp.SetValue(`input[name=pw1]`, "password", chromedp.ByQuery),
		chromedp.SetValue(`input[name=pw2]`, "password", chromedp.ByQuery),
		chromedp.Click(`button[tkey="pki-get-key-and-cert"]`, chromedp.ByQuery),
	); err != nil {
		dumpPageContent(t, ctx)
		t.Fatalf("Get gpg key+cert: %v", err)
	}
	t.Log("Waiting for download")
	filename := <-done
	t.Logf("Downloaded %s", filename)
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", filename, err)
	}
	key, cert, err := pkcs12.Decode(data, "password")
	if err != nil {
		t.Fatalf("pkcs12.Decode: %v", err)
	}
	t.Logf("Received a %T and a X.509 Certificate with Subject: %s", key, cert.Subject)

	// Verify that the certificate works.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{{
					PrivateKey:  key,
					Certificate: [][]byte{cert.Raw},
					Leaf:        cert,
				}},
			},
		},
	}
	url = "https://secure.example.com/"
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Get(%q): %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := resp.StatusCode, 200; got != want {
		t.Errorf("Get(%q) StatusCode: %d, want %d", url, got, want)
	}
	t.Logf("Get(%q) Body: %q", url, body)
}
