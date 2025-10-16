package integration_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	chromeWS = "ws://headless-shell:9222"
)

func TestHTTPS(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	to := time.After(10 * time.Second)
	for _, h := range []struct {
		url  string
		code int
	}{
		{"https://www.example.com", 200},
		{"https://www.example.com/foo/", 403},
		{"https://ssh.example.com", 403},
		{"https://photos.example.com", 200},
	} {
		for {
			resp, err := client.Get(h.url)
			if err == nil && resp.StatusCode == h.code {
				break
			}
			var code int
			if resp != nil {
				code = resp.StatusCode
			}
			t.Logf("Waiting for %s [err:%v, code:%d]", h.url, err, code)
			select {
			case <-to:
				t.Fatalf("not ready: %s", h.url)
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
}

func TestPhotos(t *testing.T) {
	// create context
	ctx, cancel := chromedp.NewRemoteAllocator(t.Context(), chromeWS)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(t.Logf))
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	clearCookies(t, ctx)

	username := "test@example.com"
	password := "password"

	// Test photos UI
	if err := chromedp.Run(ctx,
		chromedp.Navigate(`https://photos.example.com`),

		chromedp.WaitVisible(`#skip-passphrase-button`, chromedp.ByQuery),
		chromedp.Click(`#skip-passphrase-button`, chromedp.ByQuery),

		chromedp.WaitVisible(`button.prompt-confirm-button`, chromedp.ByQuery),
		chromedp.Click(`button.prompt-confirm-button`, chromedp.ByQuery),

		chromedp.WaitVisible(`#register-tab`, chromedp.ByQuery),
		chromedp.Click(`#register-tab`, chromedp.ByQuery),

		chromedp.WaitVisible(`input[name=email]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=email]`, username, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=password]`, password, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=password2]`, password, chromedp.ByQuery),
		chromedp.Click(`#login-button`, chromedp.ByQuery),

		chromedp.WaitVisible(`#gallery`, chromedp.ByQuery),
	); err != nil {
		dumpPageContent(t, ctx)
		t.Fatalf("Register account: %v", err)
	}

	if err := chromedp.Run(ctx,
		chromedp.WaitVisible(`#add-button`, chromedp.ByQuery),
		chromedp.Click(`#add-button`, chromedp.ByQuery),
		chromedp.WaitVisible(`#menu-upload-files`, chromedp.ByQuery),
		chromedp.Click(`#menu-upload-files`, chromedp.ByQuery),

		chromedp.WaitVisible(`#upload-file-input`, chromedp.ByQuery),
		chromedp.SetUploadFiles(`#upload-file-input`, []string{"/test.jpg"}),
		chromedp.WaitVisible(`.upload-file-list-upload-button`, chromedp.ByQuery),
		chromedp.Click(`.upload-file-list-upload-button`, chromedp.ByQuery),

		chromedp.WaitVisible(`img[alt="test.jpg"]`, chromedp.ByQuery),
	); err != nil {
		dumpPageContent(t, ctx)
		t.Fatalf("Upload file: %v", err)
	}
}

func TestSSHTerm(t *testing.T) {
	// create context
	ctx, cancel := chromedp.NewRemoteAllocator(t.Context(), chromeWS)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(t.Logf))
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	clearCookies(t, ctx)

	url := "https://ssh.example.com"

	// Test sshterm UI
	if err := navigateWithSSO(t, ctx, "bob@example.com", url); err != nil {
		dumpPageContent(t, ctx)
		t.Fatalf("navigate(%s): %v", url, err)
	}
	var termContent string
	for {
		select {
		case <-ctx.Done():
			dumpPageContent(t, ctx)
			t.Fatalf("Unexpected terminal content: %q", termContent)
		case <-time.After(500 * time.Millisecond):
		}

		if err := chromedp.Run(ctx,
			chromedp.Evaluate(`Array.from(document.querySelectorAll('div.xterm-rows>div')).map(x => x.textContent).join('\n')`, &termContent),
		); err != nil {
			dumpPageContent(t, ctx)
			t.Fatalf("Failed to get terminal content: %v", err)
		}
		t.Logf("terminal content:\n%s", termContent)
		if strings.Contains(termContent, "Hello bob@example.com") {
			return
		}
	}
}

func TestSSO(t *testing.T) {
	ctx, cancel := chromedp.NewRemoteAllocator(t.Context(), chromeWS)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(t.Logf))
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	clearCookies(t, ctx)
	id := "bob@example.com"
	navigateContains(t, ctx, "", "https://www.example.com/", "Hello")
	navigateContains(t, ctx, id, "https://www.example.com/foo/", "sso only")
	navigateContains(t, ctx, id, "https://www.example.com/.sso/", id)
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
