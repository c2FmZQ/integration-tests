package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

func main() {
	// Wait for services to be ready
	time.Sleep(10 * time.Second)

	runPhotosTests()
	runSSOTests()
	runSSHTermTests()

	fmt.Println("Integration tests passed!")
}

func runPhotosTests() {
	fmt.Println("Running Photos tests...")

	// create context
	ctx, cancel := chromedp.NewRemoteAllocator(context.Background(), "ws://headless-shell:9222")
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx, chromedp.WithLogf(log.Printf))
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

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
		dumpPageContent(ctx)
		log.Fatalf("Register account: %v", err)
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
		dumpPageContent(ctx)
		log.Fatalf("Upload file: %v", err)
	}
	fmt.Println("Photos create account and upload test passed")
}

func runSSHTermTests() {
	fmt.Println("Running SSHTerm tests...")

	// create context
	ctx, cancel := chromedp.NewRemoteAllocator(context.Background(), "ws://headless-shell:9222")
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	url := "https://ssh.example.com"

	// Test sshterm UI
	if err := navigateWithSSO(ctx, url); err != nil {
		dumpPageContent(ctx)
		log.Fatalf("navigate(%s): %v", url, err)
	}
	var termContent string
	want := "Hello bob@example.com"
	// Poll for the terminal content to contain "hello"
	for i := 0; i < 40; i++ {
		log.Printf("poll %d", i)
		if err := chromedp.Run(ctx,
			chromedp.Evaluate(`Array.from(document.querySelectorAll('div.xterm-rows>div')).map(x => x.textContent).join('\n')`, &termContent),
		); err != nil {
			dumpPageContent(ctx)
			log.Fatalf("Failed to get terminal content: %v", err)
		}
		log.Printf("terminal content:\n%s", termContent)
		if strings.Contains(termContent, want) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !strings.Contains(termContent, want) {
		dumpPageContent(ctx)
		log.Fatalf("Unexpected terminal content: %q", termContent)
	}
	fmt.Println("sshterm connect test passed")
}

func runSSOTests() {
	fmt.Println("Running SSO tests...")
	ctx, cancel := chromedp.NewRemoteAllocator(context.Background(), "ws://headless-shell:9222")
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	navigateContains(ctx, "https://www.example.com/.sso/", "bob@example.com")
	navigateContains(ctx, "https://www.example.com/", "Hello")

	fmt.Println("SSO flow test passed")
}

func click(ctx context.Context, selector string) bool {
	defer time.Sleep(500 * time.Millisecond)
	var present bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(function(){
		const el = document.querySelector('`+selector+`');
		if (el) {
			el.click();
			return true;
		}
		return false;
	}())`, &present)); err != nil {
		log.Printf("click(%s): %v", selector, err)
		return false
	}
	if present {
		log.Printf("clicked %s", selector)
	}
	return present
}

func navigateWithSSO(ctx context.Context, url string) error {
	if err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
		return err
	}
	elems := []string{
		`a.button[tkey=login-button]`,
		`button[tkey=sso-login]`,
		`a.user-id-link[href*="bob@example.com"]`,
	}
	for {
		var clicked bool
		for _, e := range elems {
			if click(ctx, e) {
				clicked = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if clicked {
			continue
		}
		break
	}
	return nil
}

func screenshot(ctx context.Context, filename string) {
	var buf []byte
	if err := chromedp.Run(context.WithoutCancel(ctx),
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		log.Fatalf("Failed to take screenshot: %v", err)
	}
	if err := os.WriteFile(filename, buf, 0o644); err != nil {
		log.Fatal(err)
	}
}

func dumpPageContent(ctx context.Context) {
	var pageContent string
	if err := chromedp.Run(context.WithoutCancel(ctx),
		chromedp.WaitReady(`body`),
		chromedp.OuterHTML(`body`, &pageContent, chromedp.ByQuery),
	); err != nil {
		log.Fatalf("OuterHTML(body): %v", err)
	}
	log.Printf("==== PAGE CONTENT ====\n%s\n======================", pageContent)
}

func navigateContains(ctx context.Context, url, content string) {
	if err := navigateWithSSO(ctx, url); err != nil {
		log.Fatalf("navigate(%s): %v", url, err)
	}
	var pageContent string
	if err := chromedp.Run(ctx,
		chromedp.WaitReady(`body`),
		chromedp.OuterHTML(`body`, &pageContent, chromedp.ByQuery),
	); err != nil {
		log.Fatalf("OuterHTML(body): %v", err)
	}
	if !strings.Contains(pageContent, content) {
		screenshot(ctx, "screenshot-navigate-contains.png")
		log.Fatalf("Content = %s, want %s", pageContent, content)
	}
}
