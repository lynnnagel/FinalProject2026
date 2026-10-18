"""Page object for the sign-in page.

Holds every locator and the address, so a change to the markup is fixed
here and not in each test. It exposes actions, not assertions: the tests
say what should happen, the page says what can be done.
"""
from playwright.sync_api import Page


class LoginPage:
    PATH = "/app/login.html"

    def __init__(self, page: Page, base_url: str):
        self.page = page
        self.base_url = base_url
        # The page carries three forms - sign in, register and reset - and
        # they share placeholders. Every locator is scoped to this form, or
        # Playwright stops on a strict mode violation rather than guessing.
        self.form = page.locator("#loginForm")
        self.email = self.form.locator("#loginEmail")
        self.password = self.form.locator("#loginPassword")
        self.submit = self.form.get_by_role("button", name="התחבר")
        self.error = page.locator("#loginError")

    def open(self) -> "LoginPage":
        self.page.goto(self.base_url + self.PATH)
        return self

    def sign_in(self, email: str, password: str) -> None:
        self.email.fill(email)
        self.password.fill(password)
        self.submit.click()
