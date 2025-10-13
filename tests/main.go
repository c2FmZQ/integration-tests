package main

import (
	"context"
	"fmt"
	"log"
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

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Test photos UI
	var photosTitle string
	err := chromedp.Run(ctx,
		chromedp.Navigate(`https://photos.example.com`),
		chromedp.Title(&photosTitle),
	)
	if err != nil {
		log.Fatalf("Failed to navigate to photos: %v", err)
	}
	if photosTitle != "c2FmZQ" {
		log.Fatalf("Unexpected photos title: %s", photosTitle)
	}
	fmt.Println("Photos UI is up and running")
}

func runSSHTermTests() {
	fmt.Println("Running SSHTerm tests...")

	// create context
	ctx, cancel := chromedp.NewRemoteAllocator(context.Background(), "ws://headless-shell:9222")
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := "https://sshterm.example.com"

	// Test sshterm UI
	if err := navigateWithSSO(ctx, url); err != nil {
		log.Fatalf("navigate(%s): %v", url, err)
	}
	var sshtermTitle string
	if err := chromedp.Run(ctx,
		chromedp.Title(&sshtermTitle),
	); err != nil {
		log.Fatalf("Failed to navigate to sshterm: %v", err)
	}
	if sshtermTitle != "SSH Terminal" {
		log.Fatalf("Unexpected sshterm title: %q", sshtermTitle)
	}
	fmt.Println("sshterm UI is up and running")
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
	log.Printf("click(%s) = %v", selector, present)
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
		}
		if clicked {
			continue
		}
		break
	}
	return nil
}

func navigateContains(ctx context.Context, url, content string) {
	if err := navigateWithSSO(ctx, url); err != nil {
		log.Fatalf("navigate(%s): %v", url, err)
	}
	var pageContent string
	if err := chromedp.Run(ctx,
		chromedp.OuterHTML(`body`, &pageContent, chromedp.ByQuery),
	); err != nil {
		log.Fatalf("OuterHTML(body): %v", err)
	}
	if !strings.Contains(pageContent, content) {
		log.Fatalf("Content = %s, want %s", pageContent, content)
	}
}
