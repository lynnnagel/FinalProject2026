"""
Static checks on the extension's and the site's JavaScript.

A function was once deleted from content.js while the calls to it
stayed. The file remained syntactically perfect - a syntax check cannot
catch that - and every scan threw a ReferenceError at runtime, which the
surrounding try/catch swallowed. Every message in the inbox showed as
"not scanned" with no hint why.

So these checks verify that every name called as a function is defined
somewhere in the file, that the file parses, and that every element id
the scripts look up exists in the page.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

JS_FILES = [
    ROOT / "extension" / "content.js",
    ROOT / "extension" / "background.js",
    ROOT / "extension" / "popup" / "popup.js",
    ROOT / "frontend" / "js" / "index.js",
    ROOT / "frontend" / "js" / "login.js",
    ROOT / "frontend" / "js" / "dashboard.js",
    ROOT / "frontend" / "js" / "forgot_password.js",
]

# Browser, Chrome and language globals - not defined in the file, so
# there is no reason to expect to find them there.
GLOBALS = {
    "fetch", "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "parseInt", "parseFloat", "encodeURIComponent", "decodeURIComponent",
    "isNaN", "alert", "confirm", "prompt", "structuredClone", "queueMicrotask",
    "requestAnimationFrame", "atob", "btoa",
    # Keywords that look like a call when followed by a bracket
    "if", "for", "while", "switch", "catch", "return", "function", "typeof",
    "await", "new", "delete", "in", "of", "do", "else", "throw", "yield",
    "async",
}

# A name starting with a capital is a constructor or class - Promise,
# Set, Map, MutationObserver, Error. Environment globals, not worth
# maintaining a closed list of.
def is_constructor(name: str) -> bool:
    return name[:1].isupper()


def strip_noise(src: str) -> str:
    """
    Strip comments and string templates.

    Template literals hold CSS - rgba(), translateY(), blur() - which
    looks exactly like a function call. Without this the check fills
    with false alarms and nobody reads it.
    """
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"(?<![:\w])//[^\n]*", " ", src)
    src = re.sub(r"`(?:\\.|[^`\\])*`", " '' ", src, flags=re.S)
    # Plain strings hold CSS too, e.g. 'rgba(0,0,0,.3)'
    src = re.sub(r"'(?:\\.|[^'\\\n])*'", " '' ", src)
    src = re.sub(r'"(?:\\.|[^"\\\n])*"', ' "" ', src)
    return src


def defined_names(src: str) -> set[str]:
    names: set[str] = set()
    names |= set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", src))
    names |= set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)", src))
    names |= set(re.findall(r"\bclass\s+([A-Za-z_$][\w$]*)", src))
    # Function parameters, single-parameter arrow functions included
    for params in re.findall(r"\(([^()]*)\)\s*(?:=>|\{)", src):
        for part in params.split(","):
            token = part.split("=")[0].strip().lstrip(".")
            if re.fullmatch(r"[A-Za-z_$][\w$]*", token):
                names.add(token)
    names |= set(re.findall(r"(?:^|[(,\s])([A-Za-z_$][\w$]*)\s*=>", src))
    # Destructuring:  const { a, b } = ...
    for block in re.findall(r"\{([^{}]*)\}\s*=", src):
        names |= set(re.findall(r"([A-Za-z_$][\w$]*)\s*(?::|,|$)", block))
    return names


def called_names(src: str) -> set[str]:
    # A name followed by a bracket that is not a property access
    return set(re.findall(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(", src))


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_the_file_is_there(path: Path) -> None:
    """
    Every file in the list belongs to the project, so a missing one is
    a failure rather than a reason to skip.

    Written after frontend/js/forgot_password.js went missing from a
    working copy and nobody noticed: the page loaded fine, but the
    "choose a new password" button stopped responding. The checks that
    touch that file skipped silently, because they skip when the file is
    absent - exactly the case they exist to catch.
    """
    assert path.exists(), (
        f"{path.relative_to(ROOT)} does not exist.\n"
        "If it was deleted by mistake:  git restore "
        + str(path.relative_to(ROOT))
    )


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_every_called_function_is_defined(path: Path) -> None:
    if not path.exists():
        pytest.skip("covered by test_the_file_is_there")

    src = strip_noise(path.read_text(encoding="utf-8"))
    missing = sorted(
        name for name in called_names(src) - defined_names(src) - GLOBALS
        if not is_constructor(name)
    )

    assert not missing, (
        f"{path.name}: calls functions that are not defined in the file: "
        f"{', '.join(missing)}\nA name deleted while its calls stayed is not "
        "caught by a syntax check - it only shows at runtime."
    )


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_syntax_is_valid(path: Path) -> None:
    """
    One syntax error disables the whole file: the browser runs none of
    it. In the extension that means no badges at all; in a page, no
    button responds.
    """
    if not path.exists():
        pytest.skip("covered by test_the_file_is_there")
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed - syntax check skipped")

    result = subprocess.run([node, "--check", str(path)],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"{path.name}:\n{result.stderr}"


# ---------------------------------------------------------------------------
# Element ids
#
# The pages and the JS that drives them are two files, and nothing ties
# them together. A renamed or deleted id leaves getElementById returning
# null, and the button simply stops responding - no error in the console
# until something tries to read a property off it.
# ---------------------------------------------------------------------------
PAGES = [
    (ROOT / "frontend" / "js" / "index.js",           ROOT / "frontend" / "index.html"),
    (ROOT / "frontend" / "js" / "login.js",           ROOT / "frontend" / "login.html"),
    (ROOT / "frontend" / "js" / "dashboard.js",       ROOT / "frontend" / "dashboard.html"),
    (ROOT / "frontend" / "js" / "forgot_password.js", ROOT / "frontend" / "forgot_password.html"),
    (ROOT / "extension" / "popup" / "popup.js",       ROOT / "extension" / "popup.html"),
]


@pytest.mark.parametrize("js,html", PAGES, ids=lambda p: p.name)
def test_referenced_ids_exist(js: Path, html: Path) -> None:
    assert js.exists(), f"{js.relative_to(ROOT)} does not exist"
    assert html.exists(), f"{html.relative_to(ROOT)} does not exist"

    js_src = js.read_text(encoding="utf-8")
    html_src = html.read_text(encoding="utf-8")

    wanted = set(re.findall(r"getElementById\(\s*['\"]([\w-]+)['\"]", js_src))
    wanted |= set(re.findall(r"querySelector\(\s*['\"]#([\w-]+)['\"]", js_src))

    # Ids that live in the page, plus ids the script creates itself.
    present = set(re.findall(r"\bid=[\"']([\w-]+)[\"']", html_src))
    present |= set(re.findall(r"\bid=[\"']([\w-]+)[\"']", js_src))
    present |= set(re.findall(r"\.id\s*=\s*['\"]([\w-]+)['\"]", js_src))

    missing = sorted(wanted - present)
    assert not missing, (
        f"{js.name} looks up ids that are not in {html.name}: "
        f"{', '.join(missing)}\ngetElementById returns null and the element "
        "simply stops responding."
    )
