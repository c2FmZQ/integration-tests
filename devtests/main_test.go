package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

const (
	chromeWS = "ws://headless-shell:9222"
)

func TestHTTPS(t *testing.T) {
	to := time.After(10 * time.Second)
	for _, h := range []struct {
		url  string
		code int
	}{
		{"https://www.example.com", 200},
		{"https://www.example.com/foo/", 403},
		{"https://ssh.example.com", 403},
		{"https://photos.example.com", 200},
		{"https://c2fmzq.org", 200},
		{"https://mock-backend.example.com", 403},
		{"https://pki.example.com", 403},
	} {
		for {
			resp, err := http.Get(h.url)
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

	clearCookies(t, ctx)

	username := "test@example.com"
	password := "password"

	runWithTimeout := func(timeout time.Duration, tasks ...chromedp.Action) {
		t.Helper()
		taskCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := chromedp.Run(taskCtx, tasks...); err != nil {
			dumpPageContent(t, ctx)
			t.Fatalf("chromedp.Run failed: %v", err)
		}
	}

	t.Logf("Starting registration flow")
	runWithTimeout(30*time.Second,
		chromedp.Navigate(`https://photos.example.com`),
	)

	runWithTimeout(10*time.Second,
		chromedp.WaitVisible(`#skip-passphrase-button`, chromedp.ByQuery),
		chromedp.ScrollIntoView(`#skip-passphrase-button`, chromedp.ByQuery),
		chromedp.WaitEnabled(`#skip-passphrase-button`, chromedp.ByQuery),
		chromedp.Focus(`#skip-passphrase-button`, chromedp.ByQuery),
		chromedp.Click(`#skip-passphrase-button`, chromedp.ByQuery),
	)

	runWithTimeout(10*time.Second,
		chromedp.WaitVisible(`button.prompt-confirm-button`, chromedp.ByQuery),
		chromedp.Click(`button.prompt-confirm-button`, chromedp.ByQuery),
	)

	runWithTimeout(30*time.Second,
		chromedp.WaitVisible(`#register-tab`, chromedp.ByQuery),
		chromedp.WaitEnabled(`#register-tab`, chromedp.ByQuery),
		chromedp.Click(`#register-tab`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name=email]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=email]`, username, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=password]`, password, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=password2]`, password, chromedp.ByQuery),
		chromedp.WaitEnabled(`#login-button`, chromedp.ByQuery),
		chromedp.Click(`#login-button`, chromedp.ByQuery),
		chromedp.WaitVisible(`#gallery`, chromedp.ByQuery),
	)
	t.Logf("Finished registration flow")

	t.Logf("Starting upload flow")
	runWithTimeout(30*time.Second,
		chromedp.WaitVisible(`#add-button`, chromedp.ByQuery),
		chromedp.Click(`#add-button`, chromedp.ByQuery),
		chromedp.WaitVisible(`#menu-upload-files`, chromedp.ByQuery),
		chromedp.Click(`#menu-upload-files`, chromedp.ByQuery),
		chromedp.WaitVisible(`#upload-file-input`, chromedp.ByQuery),
		chromedp.SetUploadFiles(`#upload-file-input`, []string{"/test.jpg"}),
		chromedp.WaitVisible(`.upload-file-list-upload-button`, chromedp.ByQuery),
		chromedp.Click(`.upload-file-list-upload-button`, chromedp.ByQuery),
		chromedp.WaitVisible(`img[alt="test.jpg"]`, chromedp.ByQuery),
	)
	t.Logf("Finished upload flow")

	t.Logf("Starting login flow")
	runWithTimeout(30*time.Second,
		chromedp.Navigate(`https://c2fmzq.org/pwa`),
	)

	runWithTimeout(10*time.Second,
		chromedp.WaitVisible(`#passphrase-input`, chromedp.ByQuery),
		chromedp.SendKeys(`#passphrase-input`, "foo", chromedp.ByQuery),
		chromedp.SendKeys(`#passphrase-input2`, "foo", chromedp.ByQuery),
		chromedp.WaitEnabled(`#set-passphrase-button`, chromedp.ByQuery),
		chromedp.Focus(`#set-passphrase-button`, chromedp.ByQuery),
		chromedp.Click(`#set-passphrase-button`, chromedp.ByQuery),
	)

	runWithTimeout(30*time.Second,
		chromedp.WaitVisible(`input[name=email]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=email]`, username, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=password]`, password, chromedp.ByQuery),
		chromedp.SendKeys(`input[name=server]`, "https://photos.example.com/", chromedp.ByQuery),
		chromedp.WaitVisible(`#login-button`, chromedp.ByQuery),
		chromedp.WaitEnabled(`#login-button`, chromedp.ByQuery),
		chromedp.Click(`#login-button`, chromedp.ByQuery),
		chromedp.WaitVisible(`#gallery img[alt="test.jpg"]`, chromedp.ByQuery),
	)
	t.Logf("Finished login flow")
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
			chromedp.Evaluate(`Array.from(document.querySelectorAll('div.xterm-rows>div')).map(x => x.textContent).join('\n').trim()`, &termContent),
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
	navigateContains(t, ctx, id, "https://mock-backend.example.com/", id)
}

func TestECH(t *testing.T) {
	client := httpClientECH(t)
	resp, err := client.Get("https://photos.example.com/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if got, want := resp.TLS.ECHAccepted, true; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
}
