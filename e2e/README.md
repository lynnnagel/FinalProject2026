# Browser tests

End-to-end tests for the sign-in flow, driven through a real browser with
Playwright.

They are deliberately **outside** `backend/tests/`. The suite in CI runs from
`backend/` against an in-memory database and finishes in under a minute; these
need a running server and a browser, so they stay a separate, deliberate run.

## Running them

```bash
pip install -r e2e/requirements-e2e.txt
playwright install chromium          # once
```

Start the server in one terminal:

```bash
cd backend
uvicorn server:app --port 8000
```

And in another:

```bash
pytest e2e -v                        # headless
pytest e2e -v --headed --slowmo 400  # watch it happen
```

`E2E_BASE_URL` points them somewhere else:

```bash
E2E_BASE_URL=https://staging.example.com pytest e2e
```

## What is covered

| Test | What it proves |
|---|---|
| `test_the_sign_in_form_is_shown` | the page renders and the button is usable |
| `test_valid_credentials_reach_the_dashboard` | the happy path lands on the dashboard |
| `test_a_wrong_password_keeps_the_user_on_the_page` | the error is shown and no redirect happens |
| `test_the_token_is_only_stored_after_a_successful_sign_in` | no token before, a token after |

## Notes on how they are written

**The account is created over the API, not through the form.** A sign-in test
should fail when sign-in breaks, not when the registration form changes - and
the API call takes about fifty milliseconds instead of a few seconds.

**Every locator is scoped to `#loginForm`.** The page holds three forms - sign
in, register and reset - and they share placeholders, so an unscoped locator
matches more than one element and Playwright stops rather than guessing.

**`expect`, never `sleep`.** `expect` retries until the condition holds or the
timeout is reached. A plain assert checks once, in the millisecond after the
click, before the server has answered.

**The page object holds actions, not assertions.** `LoginPage` says what can be
done on the page; the tests say what should happen.
