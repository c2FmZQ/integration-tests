
from playwright.sync_api import sync_playwright
import time

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()

    page.goto("https://photos.example.com")

    page.wait_for_selector("#skip-passphrase-button")
    page.click("#skip-passphrase-button")

    page.wait_for_selector("button.prompt-confirm-button")
    page.click("button.prompt-confirm-button")

    page.wait_for_selector("#register-tab")
    page.click("#register-tab")

    page.wait_for_selector("input[name=email]")
    page.fill("input[name=email]", "test@example.com")
    page.fill("input[name=password]", "password")
    page.fill("input[name=password2]", "password")
    page.click("#login-button")

    page.wait_for_selector("#gallery")

    page.wait_for_selector("#add-button")
    page.click("#add-button")
    page.wait_for_selector("#menu-upload-files")
    page.click("#menu-upload-files")

    page.wait_for_selector("#upload-file-input")
    page.set_input_files("#upload-file-input", "tests/test.jpg")

    page.wait_for_selector(".upload-file-list-upload-button")
    page.click(".upload-file-list-upload-button")

    page.wait_for_selector('img[alt="test.jpg"]')
    page.screenshot(path="jules-scratch/verification/verification.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
