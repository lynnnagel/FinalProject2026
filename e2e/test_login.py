"""Sign-in, through the browser."""
import re

import pytest
from playwright.sync_api import Page, expect

from pages.login_page import LoginPage


@pytest.fixture
def login_page(page: Page, base_url: str) -> LoginPage:
    return LoginPage(page, base_url).open()


def test_the_sign_in_form_is_shown(login_page):
    expect(login_page.form).to_be_visible()
    expect(login_page.submit).to_be_enabled()


def test_valid_credentials_reach_the_dashboard(login_page, registered_user):
    login_page.sign_in(registered_user["email"], registered_user["password"])

    # expect retries until the browser has followed the redirect. A plain
    # assert on the URL would check once, in the millisecond after the
    # click, before the request has even been answered.
    expect(login_page.page).to_have_url(re.compile(r"dashboard\.html"))


def test_a_wrong_password_keeps_the_user_on_the_page(login_page, registered_user):
    login_page.sign_in(registered_user["email"], "not-the-password")

    expect(login_page.error).to_be_visible()
    expect(login_page.page).to_have_url(re.compile(r"login\.html"))


def test_the_token_is_only_stored_after_a_successful_sign_in(login_page, registered_user):
    assert login_page.page.evaluate("localStorage.getItem('lura_token')") is None

    login_page.sign_in(registered_user["email"], registered_user["password"])
    expect(login_page.page).to_have_url(re.compile(r"dashboard\.html"))

    assert login_page.page.evaluate("localStorage.getItem('lura_token')")
