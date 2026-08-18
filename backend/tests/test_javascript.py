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
