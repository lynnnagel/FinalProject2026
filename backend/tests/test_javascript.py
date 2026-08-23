"""
בדיקות סטטיות לקוד ה-JavaScript של התוסף והאתר.

הרקע: פונקציה בשם scanHeaders נמחקה בטעות מ-content.js בזמן עריכה,
אך הקריאות אליה נשארו. הקובץ נשאר תקין תחבירית לחלוטין — בדיקת תחביר
אינה יכולה לתפוס דבר כזה — וכל סריקה זרקה ReferenceError בזמן ריצה.
ה-try/except שעוטף את הסריקה בלע את השגיאה, ובתיבה כל מייל הופיע
כ"לא נסרק" בלי שום רמז לסיבה.

בדיקת התחביר לבדה לא הספיקה, ולכן הבדיקה כאן מאמתת שכל שם שנקרא
כפונקציה אכן מוגדר איפשהו בקובץ.
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

# גלובלים של הדפדפן, של Chrome ושל השפה. אינם מוגדרים בקובץ עצמו
# ולכן אין לצפות למצוא אותם בו.
GLOBALS = {
    "fetch", "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "parseInt", "parseFloat", "encodeURIComponent", "decodeURIComponent",
    "isNaN", "alert", "confirm", "prompt", "structuredClone", "queueMicrotask",
    "requestAnimationFrame", "atob", "btoa",
    # מילות מפתח שנראות כקריאה כשאחריהן סוגריים
    "if", "for", "while", "switch", "catch", "return", "function", "typeof",
    "await", "new", "delete", "in", "of", "do", "else", "throw", "yield",
    "async",
}

# שם שמתחיל באות גדולה הוא בנאי או מחלקה — Promise, Set, Map,
# MutationObserver, Error. אלה גלובלים של הסביבה, ואין טעם לתחזק
# רשימה סגורה שלהם.
def is_constructor(name: str) -> bool:
    return name[:1].isupper()


def strip_noise(src: str) -> str:
    """
    מסיר הערות ותבניות מחרוזת.

    בתוך template literal יושב CSS — rgba(), translateY(), blur() —
    שנראה בדיוק כמו קריאה לפונקציה. בלי ההסרה הזאת הבדיקה מלאה
    בהתרעות שווא ואיש לא יסתכל בה.
    """
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"(?<![:\w])//[^\n]*", " ", src)
    src = re.sub(r"`(?:\\.|[^`\\])*`", " '' ", src, flags=re.S)
    # גם מחרוזות רגילות מכילות CSS, למשל 'rgba(0,0,0,.3)'
    src = re.sub(r"'(?:\\.|[^'\\\n])*'", " '' ", src)
    src = re.sub(r'"(?:\\.|[^"\\\n])*"', ' "" ', src)
    return src


def defined_names(src: str) -> set[str]:
    names: set[str] = set()
    names |= set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", src))
    names |= set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)", src))
    names |= set(re.findall(r"\bclass\s+([A-Za-z_$][\w$]*)", src))
    # פרמטרים של פונקציות, כולל פונקציות חץ עם פרמטר יחיד
    for params in re.findall(r"\(([^()]*)\)\s*(?:=>|\{)", src):
        for part in params.split(","):
            token = part.split("=")[0].strip().lstrip(".")
            if re.fullmatch(r"[A-Za-z_$][\w$]*", token):
                names.add(token)
    names |= set(re.findall(r"(?:^|[(,\s])([A-Za-z_$][\w$]*)\s*=>", src))
    # פירוק אובייקטים:  const { a, b } = ...
    for block in re.findall(r"\{([^{}]*)\}\s*=", src):
        names |= set(re.findall(r"([A-Za-z_$][\w$]*)\s*(?::|,|$)", block))
    return names


def called_names(src: str) -> set[str]:
    # שם שאחריו סוגריים, שאינו גישה לשדה (אין נקודה לפניו)
    return set(re.findall(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(", src))


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_every_called_function_is_defined(path: Path) -> None:
    if not path.exists():
        pytest.skip(f"{path} לא קיים")

    src = strip_noise(path.read_text(encoding="utf-8"))
    missing = sorted(
        name for name in called_names(src) - defined_names(src) - GLOBALS
        if not is_constructor(name)
    )

    assert not missing, (
        f"{path.name}: נקראות פונקציות שאינן מוגדרות בקובץ: {', '.join(missing)}\n"
        "שם שנמחק בעריכה והקריאות אליו נשארו אינו נתפס בבדיקת תחביר, "
        "והשגיאה מתגלה רק בזמן ריצה."
    )


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_syntax_is_valid(path: Path) -> None:
    """
    שגיאת תחביר אחת משביתה קובץ שלם: הדפדפן אינו מריץ ממנו כלום.
    בתוסף זה אומר שאף תג לא מופיע, ובדף — ששום כפתור לא מגיב.
    """
    if not path.exists():
        pytest.skip(f"{path} לא קיים")
    node = shutil.which("node")
    if not node:
        pytest.skip("node אינו מותקן — בדיקת התחביר מדולגת")

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
    if not (js.exists() and html.exists()):
        pytest.skip(f"{js.name} / {html.name} לא קיימים")

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
        f"{js.name} מחפש מזהים שאינם ב-{html.name}: {', '.join(missing)}\n"
        "getElementById יחזיר null, והאלמנט פשוט לא יגיב."
    )
