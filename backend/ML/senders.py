"""
Giving every row in the corpus a sender address.

Why this exists
---------------
Three of the nine rule checks read the sender: the lookalike-pattern
check, the domain-suffix check, and brand impersonation - which carries
the highest score in the engine. Most rows in the English corpora have
no From line, so on those rows the rule engine runs crippled and returns
a score built from four checks instead of seven. Every error recorded by
ML/errors.py lacks a sender.

So the ensemble has never been measured on the input the extension
actually receives, where Gmail always supplies a sender.

Two ways to fix that, and they are not equally good
---------------------------------------------------
1. EXTRACT. Enron and SpamAssassin are raw mail dumps; many rows still
   carry their original headers inside the body text. A sender parsed
   out of the message is real data. It costs nothing and it cannot leak.
   This runs first and takes everything it can get.

2. GENERATE. Only for rows where extraction found nothing.

Generation is dangerous, and the danger has a name
--------------------------------------------------
If phishing rows get sender addresses that look like phishing and
legitimate rows get addresses that look legitimate, the label has been
written into the feature. The rule engine then "detects" it at close to
100%, the ensemble numbers jump, and none of it means anything: the
model would be reading our own generator, not the mail.

That failure is called label leakage, and a synthetic-sender experiment
falls into it by default unless it is designed not to.

Three defences are built in here:

  a. OVERLAPPING DISTRIBUTIONS. Both classes draw a sender from the same
     pools, in similar proportions. Attackers really do send from Gmail;
     real people really do send from Gmail. The largest single pool is
     shared almost evenly (40% / 35%), so the most common sender shape
     carries no information about the label at all.

  b. CONTENT-CONDITIONED, NOT LABEL-CONDITIONED. Where the body names a
     brand, the domain is derived from that brand: the real domain for a
     legitimate row, a lookalike for a phishing one. This is the one
     place where the label does influence the address - and it has to,
     because it is the exact relationship the impersonation rule exists
     to catch, and the one that mirrors how real attacks work. It is
     kept to a minority of rows and reported separately.

  c. A LEAKAGE AUDIT. --audit trains a character n-gram classifier on
     the sender string ALONE and reports how well it recovers the label.
     If that number is high, the generated senders are contaminated and
     every downstream metric measured on them is inflated. The audit is
     run on the extracted senders too, as a control: whatever separation
     real headers carry is the honest reference point.

What may and may not be claimed from the result
-----------------------------------------------
May:      the sender-reading rules now execute on every row; the rules
          behave as designed on realistic addresses; the pipeline has
          been measured end to end on complete inputs.
May not:  any accuracy, recall or precision figure measured on generated
          senders as a product result. Report those separately, labelled
          as synthetic, next to the numbers on real senders.

Usage
-----
    python ML/senders.py --audit                 # audit only, writes nothing
    python ML/senders.py --write                 # fill the splits in place
    python ML/senders.py --write --extract-only  # no generation at all
    python ML/senders.py --report                # coverage by source
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "processed")
SPLITS = ("train", "val", "test")

# Sources whose senders our own generators wrote. Their addresses are
# real strings in the file but they are not evidence about real mail:
# the generator chose them to match the label. They are reported apart
# from headers parsed out of genuine messages.
SYNTHETIC_SOURCES = frozenset({
    "hebrew_generated", "legitimate_generated", "hebrew_translated",
})


# ---------------------------------------------------------------------------
# 1. Extraction - real senders, wherever the corpus still has them
# ---------------------------------------------------------------------------
# This is the part worth investing in. An address parsed out of a message
# is real data: it cannot leak the label, and it costs nothing. Every row
# this recovers is one fewer row that has to be generated.
#
# The corpora carry senders in several shapes, and they are not equally
# trustworthy, so each is tried in order and the method is recorded:
#
#   From:            the header the extension itself reads. Authoritative.
#   From <addr> ...  the mbox separator line - no colon. SpamAssassin is
#                    distributed as mbox files and many rows kept it.
#   Sender:          set when the sender differs from the author.
#   Return-Path:     the envelope sender. Weaker: in phishing it often
#                    differs from From: on purpose, and the extension
#                    never sees it.
#   bare address     a guess, taken only from the opening lines.
_ADDRESS = re.compile(r"[\w.+%-]+@[\w-]+(?:\.[\w-]+)+")

_HEADER_PATTERNS = [
    ("from",        re.compile(r"^from[ \t]*:(.*)$", re.IGNORECASE | re.MULTILINE)),
    ("mbox",        re.compile(r"^from[ \t]+(\S+@\S+)", re.IGNORECASE | re.MULTILINE)),
    ("sender",      re.compile(r"^x?-?sender[ \t]*:(.*)$", re.IGNORECASE | re.MULTILINE)),
    ("return-path", re.compile(r"^return-path[ \t]*:(.*)$", re.IGNORECASE | re.MULTILINE)),
]

# Recipient and routing headers. Addresses found here are specifically
# NOT the sender, and the bare-address fallback has to avoid them - a
# fallback that quietly harvests To: lines would give a large share of
# the corpus the recipient's address and look like a great result.
_RECIPIENT = re.compile(
    r"^(to|cc|bcc|delivered-to|x-original-to|envelope-to|for)[ \t]*:(.*)$",
    re.IGNORECASE | re.MULTILINE)

# The same headers, unanchored, for text whose newlines were collapsed.
# Without this the recipient of a flattened message reads as its sender -
# a silent, systematic error, and the worst kind: it fills the column
# with plausible addresses that are all wrong.
_RECIPIENT_INLINE = re.compile(
    r"\b(?:to|cc|bcc|delivered-to|x-original-to|envelope-to)[ \t]*:[ \t]*<?"
    r"([\w.+%-]+@[\w-]+(?:\.[\w-]+)+)", re.IGNORECASE)

# Infrastructure addresses: real, but they belong to the mailing list or
# the mail server rather than to a person or a brand.
_NOT_A_SENDER = re.compile(
    r"(listmaster|majordomo|owner-|-owner@|-request@|-admin@|-bounces@"
    r"|bounce|postmaster|mailer-daemon|no-?reply-daemon|root@|daemon@)",
    re.IGNORECASE)


def _clean(address: str) -> str:
    """Normalise one address, or return "" if it is not usable."""
    address = address.strip().strip("<>()[]{}\"'.,;:").lower()
    if not address or address.count("@") != 1:
        return ""
    local, _, domain = address.partition("@")
    # A domain needs a dot and a plausible TLD; a local part that long is
    # a parsing accident, not an address.
    if "." not in domain or len(local) > 64 or len(domain) > 255:
        return ""
    if len(domain.rsplit(".", 1)[1]) < 2:
        return ""
    return address


def _header_block(text: str) -> str:
    """
    The leading header region: everything before the first blank line,
    but only when those lines actually look like headers.

    Bounding the search this way matters. A From: line further down is
    part of a quoted reply, and that is a different message's sender -
    taking it would attribute the wrong address to the row.
    """
    lines = text.split("\n", 200)[:200]
    header_like = re.compile(r"^([A-Za-z][\w-]{1,40}[ \t]*:|from[ \t]+\S+@|[ \t]+\S)")
    block = []
    for line in lines:
        if not line.strip():
            break
        if not header_like.match(line) and len(block) > 2:
            break
        block.append(line)
    # Fewer than three header-shaped lines is not a header block.
    return "\n".join(block) if len(block) >= 3 else ""


def extract_sender(text: str, with_method: bool = False):
    """
    The sender recorded in the message, or "" when there is none.

    Returns the address, or (address, method) when with_method is set so
    the report can show which shape each row came from.
    """
    empty = ("", "") if with_method else ""
    if not isinstance(text, str) or "@" not in text:
        return empty

    head = text[:8000]
    block = _header_block(head)
    region = block or "\n".join(head.split("\n", 8)[:8])

    for method, pattern in _HEADER_PATTERNS:
        for raw in pattern.findall(region):
            for candidate in _ADDRESS.findall(raw):
                address = _clean(candidate)
                if address and not _NOT_A_SENDER.search(address):
                    return (address, method) if with_method else address

    # Flattened text. prepare_data.py's clean_text collapses every run of
    # whitespace into a single space, so a message that still carries its
    # headers arrives as one long line and the block above finds nothing.
    # Matching "From:" followed by an address recovers those rows.
    #
    # This is a rescue for data that has already been processed. The real
    # fix is to extract before cleaning - clean_text also deletes
    # <addr@host> as though it were an HTML tag, and no amount of
    # rematching brings those back.
    if not block:
        flat = re.search(
            r"\bfrom[ \t]*:[ \t]*(?:[^<>@\s]{0,60}?[ \t])?<?"
            r"([\w.+%-]+@[\w-]+(?:\.[\w-]+)+)", head[:3000], re.IGNORECASE)
        if flat:
            address = _clean(flat.group(1))
            if address and not _NOT_A_SENDER.search(address):
                return (address, "flat") if with_method else address

    # Fallback: a bare address in the opening lines, as long as it is not
    # one the recipient headers claim.
    recipients = {
        _clean(a)
        for _, raw in _RECIPIENT.findall(region)
        for a in _ADDRESS.findall(raw)
    } | {_clean(a) for a in _RECIPIENT_INLINE.findall(head[:3000])}
    opening = "\n".join(head.split("\n", 6)[:6])
    for candidate in _ADDRESS.findall(opening):
        address = _clean(candidate)
        if address and address not in recipients and not _NOT_A_SENDER.search(address):
            return (address, "bare") if with_method else address
    return empty


# ---------------------------------------------------------------------------
# 2. Generation - only where extraction failed
# ---------------------------------------------------------------------------
# Shared by both classes. This is the anti-leakage core: the single most
# common kind of sender is drawn by phishing and legitimate rows alike.
FREE_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "walla.co.il", "protonmail.com", "mail.com", "bezeqint.net",
]

# Ordinary corporate senders. Neither class owns these either: a real
# company sends from one, and a compromised account is one.
CORPORATE = [
    "acme-industries.com", "northwind-tech.com", "meridian-group.co.il",
    "brightpath.org", "kelvin-analytics.com", "orenstein-law.co.il",
    "havilah-logistics.com", "quartzline.net", "shalev-medical.co.il",
    "fairmont-consulting.com", "delta-systems.co.il", "arbor-health.org",
]

# Local parts. Deliberately identical for both classes - if the name
# before the @ hinted at the label, that alone would be leakage.
LOCAL_PARTS = [
    "info", "contact", "service", "support", "notifications", "team",
    "office", "billing", "accounts", "updates", "hello", "mail",
    "d.cohen", "m.levi", "r.shapiro", "j.parker", "a.mizrahi", "s.klein",
    "n.portal", "e.lavi", "l.nagel", "o.avi",
]

# Cheap or unusual TLDs. Real phishing leans on these, but plenty of
# small legitimate senders use them too, so both classes can draw one.
ODD_TLDS = [".tk", ".xyz", ".top", ".click", ".online", ".site", ".info"]

# How a lookalike is built from a real domain. Straight from what the
# corpus of Hebrew phishing actually did.
def _lookalike(domain: str, r) -> str:
    stem = domain.split(".")[0]
    tail = "." + ".".join(domain.split(".")[1:]) if "." in domain else ".com"
    style = r.randrange(6)
    if style == 0:
        return f"{stem}-secure{tail}"
    if style == 1:
        return f"{stem}-verify{tail}"
    if style == 2:
        return f"secure-{stem}{tail}"
    if style == 3:                       # character substitution
        swapped = (stem.replace("o", "0", 1) if "o" in stem
                   else stem.replace("l", "1", 1) if "l" in stem
                   else stem.replace("i", "1", 1) if "i" in stem
                   else stem + "s")
        return f"{swapped}{tail}"
    if style == 4:                       # right domain, wrong TLD
        return stem + r.choice(ODD_TLDS)
    return f"{stem}{r.choice(['-il', '-support', '-account', 'mail'])}{tail}"


def _brand_in_text(text: str) -> tuple[str, list] | None:
    """The first brand the message names, and the domains it really uses."""
    # Imported here rather than at module scope so prepare_data.py can
    # use extract_sender() without pulling in the detector, which needs
    # a configured SECRET_KEY. Extraction has no need of it.
    from detector import detector

    lowered = text.lower()[:3000]
    for brand, domains in detector.BRAND_DOMAINS.items():
        if brand.lower() in lowered:
            return brand, domains
    return None


# The mixture, as (weight when phishing, weight when legitimate).
#
# Every pool but one is drawn by both classes, at close to the same rate.
# That is deliberate and it is what keeps the audit honest: a classifier
# reading only the address cannot separate the classes on the shape of
# the domain, because both classes produce every shape.
#
# The first version of this file gave each class its own pools - odd
# TLDs only to phishing, no-reply only to legitimate. The audit scored
# AUC 0.835 against 0.500 for real headers, which is textbook leakage,
# and the mixture was rewritten. Keeping the note because the failure is
# the easy one to make here.
#
# "lookalike" is the single exception. A domain wearing a brand's name
# that is not the brand's domain is what impersonation *is*; it cannot
# appear in legitimate mail without ceasing to be legitimate. It is held
# to a ninth of the phishing rows so it informs the data without
# defining it.
POOL_WEIGHTS = {
    "free":           (0.38, 0.34),
    "corporate":      (0.22, 0.26),
    "no-reply":       (0.11, 0.14),
    "odd-tld":        (0.12, 0.10),
    "brand-official": (0.06, 0.16),
    "lookalike":      (0.11, 0.00),
}


def _pick_pool(label: int, has_brand: bool, r) -> str:
    """Draw a pool from the mixture for this class."""
    index = 0 if label == 1 else 1
    weights = {
        name: w[index] for name, w in POOL_WEIGHTS.items()
        # The two brand-derived pools need a brand in the body. Without
        # one their weight falls back to the ordinary corporate pool.
        if w[index] > 0 and (has_brand or name not in ("lookalike", "brand-official"))
    }
    total = sum(weights.values())
    roll = r.random() * total
    running = 0.0
    for name, weight in weights.items():
        running += weight
        if roll <= running:
            return name
    return "corporate"


def generate_sender(text: str, label: int, r) -> tuple[str, str]:
    """
    A sender for one row. Returns (address, which_pool) so the audit can
    report the mixture that was actually produced.

    Both classes draw from the same pools at similar rates; see
    POOL_WEIGHTS for why, and for the one asymmetry that is intended.
    """
    brand = _brand_in_text(text if isinstance(text, str) else "")
    pool = _pick_pool(label, brand is not None, r)
    local = r.choice(LOCAL_PARTS)

    if pool == "free":
        return f"{local}@{r.choice(FREE_PROVIDERS)}", pool
    if pool == "corporate":
        return f"{local}@{r.choice(CORPORATE)}", pool
    if pool == "no-reply":
        # Attackers use no-reply as readily as anyone; it is a habit of
        # bulk mail, not a sign of honesty.
        domain = (r.choice(CORPORATE) if r.random() < 0.7
                  else r.choice(FREE_PROVIDERS))
        return f"{r.choice(['no-reply', 'noreply', 'do-not-reply'])}@{domain}", pool
    if pool == "odd-tld":
        # Small legitimate senders end up on these TLDs too.
        stem = r.choice(CORPORATE).split(".")[0]
        return f"{local}@{stem}{r.choice(ODD_TLDS)}", pool
    if pool == "brand-official":
        return f"{local}@{brand[1][0]}", pool
    return f"{local}@{_lookalike(brand[1][0], r)}", "lookalike"


def _rng_for(text: str, label: int, nonce: int = 0):
    """
    A generator seeded from the row itself, so the same row always gets
    the same address - across runs, across splits, across machines. A
    global seed would reshuffle everything the moment a row is added.

    The whole text is hashed, not a prefix, and near-duplicates get a
    nonce. Seeding on the first 500 characters gave every row sharing an
    opening the identical sender, which on a corpus of templated mail
    collapsed the generated mixture onto a handful of draws.
    """
    import random
    digest = hashlib.sha256(
        f"{label}|{nonce}|{text}".encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


# ---------------------------------------------------------------------------
# 3. The leakage audit
# ---------------------------------------------------------------------------
def audit(df: pd.DataFrame, column: str, title: str) -> float:
    """
    How much of the label can be recovered from the sender string alone?

    Chance is the majority-class rate. A score near chance means the
    address carries no label information. A score near 1.0 means the
    generator wrote the answer into the data.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import make_pipeline

    rows = df[df[column].astype(str).str.contains("@", na=False)]
    if len(rows) < 200 or rows["label"].nunique() < 2:
        print(f"  {title:<34} too few rows to audit ({len(rows)})")
        return float("nan")

    pipeline = make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3),
        LogisticRegression(max_iter=1000, n_jobs=None),
    )
    auc = cross_val_score(pipeline, rows[column], rows["label"],
                          cv=4, scoring="roc_auc").mean()
    majority = max(rows["label"].mean(), 1 - rows["label"].mean())

    # A bucket that is nearly one class cannot serve as a reference. Its
    # AUC rests on a handful of minority rows, and any domain appearing
    # only in the majority class predicts it perfectly - so the number
    # measures the composition of the bucket, not what real senders
    # reveal. Marked rather than quietly compared against.
    flag = "  << one-class, AUC uninformative" if majority > 0.90 else ""
    print(f"  {title:<34} AUC {auc:5.3f}   (n={len(rows):,}, "
          f"majority {majority:.1%}){flag}")
    return float("nan") if majority > 0.90 else auc


def verdict(auc_generated: float, auc_reference: float,
            auc_corpus: float = float("nan")) -> None:
    print()
    if auc_generated == auc_generated:            # not NaN
        if auc_generated < 0.65:
            print("  Senders filled in by this script carry little label")
            print("  information. Numbers measured on them are not inflated")
            print("  by the generator.")
        elif auc_generated < 0.80:
            print("  Senders filled in by this script carry some label")
            print("  information. Report any metric on them separately and")
            print("  say so; do not merge them into the headline numbers.")
        else:
            print("  LEAKAGE in this script's generator. Widen the shared")
            print("  pools in POOL_WEIGHTS before using this data.")

    if auc_reference == auc_reference:
        print(f"\n  Reference: parsed headers score {auc_reference:.3f}. That is")
        print("  the separation genuine mail carries, and the filled-in")
        print("  senders should not score meaningfully above it.")
    else:
        print("\n  No usable reference: the parsed-header rows are nearly all")
        print("  one class, so their AUC says nothing. Chance (0.500) is the")
        print("  only floor available - judge the number above against that.")

    # The corpus generators are a separate matter and a louder one: those
    # rows ship in the training data, so leakage there is not a
    # measurement artefact but a property of what the model learns.
    if auc_corpus == auc_corpus and auc_corpus >= 0.95:
        print(f"\n  WARNING - our own corpus generators score {auc_corpus:.3f}.")
        print("  Their senders encode the label almost perfectly: a legitimate")
        print("  row always gets the brand's real domain and a phishing row")
        print("  never does. Real mail overlaps - attackers send from Gmail and")
        print("  so do real people - so a sender-reading result on those rows")
        print("  reflects the generator's rule, not detection. Either report")
        print("  them apart, or give both classes shared pools in")
        print("  generate_hebrew.py:rnd_sender and regenerate.")


# ---------------------------------------------------------------------------
def load(split: str, data_dir: str) -> pd.DataFrame:
    path = os.path.join(data_dir, f"{split}.csv")
    if not os.path.exists(path):
        sys.exit(f"missing {path} - run ML/prepare_data.py first")
    df = pd.read_csv(path)
    for col in ("sender", "subject"):
        if col not in df.columns:
            df[col] = ""
    df["sender"] = df["sender"].fillna("")
    return df


def fill(df: pd.DataFrame, extract_only: bool) -> pd.DataFrame:
    """Add sender_extracted, sender_generated and sender_filled."""
    text = df["text"].fillna("").astype(str)

    extracted, methods = [], []
    for existing, body in zip(df["sender"].astype(str), text):
        if existing.strip() and "@" in existing:
            extracted.append(existing.strip().lower())
            methods.append("already-present")
            continue
        address, method = extract_sender(body, with_method=True)
        extracted.append(address)
        methods.append(method)
    df["sender_extracted"] = extracted
    df["extract_method"] = methods

    if extract_only:
        df["sender_generated"] = ""
        df["sender_pool"] = ""
    else:
        generated, pools = [], []
        seen: dict[tuple, int] = {}
        for t, lab, have in zip(text, df["label"], df["sender_extracted"]):
            if have:
                generated.append("")
                pools.append("extracted")
                continue
            key = (t, int(lab))
            nonce = seen.get(key, 0)
            seen[key] = nonce + 1
            addr, pool = generate_sender(t, int(lab), _rng_for(t, int(lab), nonce))
            generated.append(addr)
            pools.append(pool)
        df["sender_generated"] = generated
        df["sender_pool"] = pools

    df["sender_filled"] = df["sender_extracted"].where(
        df["sender_extracted"] != "", df["sender_generated"])
    return df


def report(df: pd.DataFrame, split: str) -> None:
    n = len(df)
    orig = int((df["sender"].astype(str).str.contains("@")).sum())
    extr = int((df["sender_extracted"] != "").sum())
    fill_ = int((df["sender_filled"] != "").sum())
    print(f"\n  {split}  ({n:,} rows)")
    print(f"    already had a sender   {orig:>7,}  {orig / n:6.1%}")
    print(f"    after extraction       {extr:>7,}  {extr / n:6.1%}"
          f"   (+{extr - orig:,} recovered from the body)")
    print(f"    after generation       {fill_:>7,}  {fill_ / n:6.1%}")

    # The number that actually matters: addresses from genuine messages,
    # as opposed to ones our own corpus generators wrote. Reporting the
    # two as one figure overstates how much of this is real data.
    if "source" in df.columns:
        genuine = df[(df["sender_extracted"] != "")
                     & (~df["source"].astype(str).isin(SYNTHETIC_SOURCES))]
        print(f"    of those, from real headers "
              f"{len(genuine):>4,}  {len(genuine) / n:6.1%}"
              f"   (the rest our generators wrote)")

    if "source" in df.columns:
        print(f"    {'source':<22}{'rows':>8}{'extracted':>11}")
        for src, grp in df.groupby("source"):
            got = int((grp["sender_extracted"] != "").sum())
            print(f"    {str(src):<22}{len(grp):>8,}{got / len(grp):>10.1%}")

    # Which shape each address came from. A result that leans on the
    # "bare" fallback is weaker than one built from real From: headers,
    # and that difference should be visible rather than averaged away.
    found = df[df["sender_extracted"] != ""]
    if len(found) and "extract_method" in df.columns:
        print(f"    {'how it was found':<22}{'rows':>8}{'share':>11}")
        for method, count in found["extract_method"].value_counts().items():
            print(f"    {str(method):<22}{count:>8,}{count / len(found):>10.1%}")

    # Top domains. If one address dominates, the extraction is picking up
    # a single mailbox owner rather than a spread of real senders.
    if len(found):
        domains = found["sender_extracted"].str.split("@").str[-1]
        top = domains.value_counts().head(5)
        print(f"    top domains: " + ", ".join(
            f"{d} {c / len(found):.0%}" for d, c in top.items()))

    if "sender_pool" in df.columns and (df["sender_pool"] != "").any():
        made = df[df["sender_pool"].isin(
            ["free", "lookalike", "odd-tld", "corporate",
             "brand-official", "no-reply"])]
        if len(made):
            print(f"    generated mixture, phishing vs legitimate:")
            table = pd.crosstab(made["sender_pool"], made["label"],
                                normalize="columns")
            for pool in table.index:
                legit = table.loc[pool, 0] if 0 in table.columns else 0.0
                phish = table.loc[pool, 1] if 1 in table.columns else 0.0
                print(f"      {pool:<18} legit {legit:6.1%}   phishing {phish:6.1%}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data_dir", "--data-dir", dest="data_dir", default=DATA_DIR)
    ap.add_argument("--write", action="store_true",
                    help="save the filled splits back to disk")
    ap.add_argument("--extract-only", action="store_true",
                    help="recover real senders, generate nothing")
    ap.add_argument("--audit", action="store_true",
                    help="measure label leakage in the addresses")
    ap.add_argument("--report", action="store_true", help="coverage only")
    ap.add_argument("--sample", type=int, default=0, metavar="N",
                    help="print N extracted addresses per method, to eyeball")
    args = ap.parse_args()

    if not any((args.write, args.audit, args.report)):
        args.report = args.audit = True

    frames = {}
    for split in SPLITS:
        df = fill(load(split, args.data_dir), args.extract_only)
        frames[split] = df
        if args.report or args.write:
            report(df, split)

    if args.sample:
        print("\n" + "=" * 74)
        print("  Extracted addresses, by method - read these before trusting them")
        print("=" * 74)
        combined = pd.concat(frames.values(), ignore_index=True)
        found = combined[combined["sender_extracted"] != ""]
        for method in found["extract_method"].unique():
            rows = found[found["extract_method"] == method]
            print(f"\n  {method}  ({len(rows):,} rows)")
            for _, row in rows.head(args.sample).iterrows():
                label = "phishing" if row["label"] == 1 else "legit   "
                print(f"    {label}  {row['sender_extracted']}")

    if args.audit:
        print("\n" + "=" * 74)
        print("  Leakage audit - can the label be read from the address alone?")
        print("=" * 74)
        combined = pd.concat(frames.values(), ignore_index=True)

        # "Already present" covers two different things and they must not
        # be audited together. Enron and SpamAssassin senders were parsed
        # out of real headers by prepare_data.py. The Hebrew and
        # legitimate corpora are written by our own generators, which
        # give phishing rows phishing-shaped addresses on purpose - so
        # they carry label information by construction.
        #
        # Averaged into one bucket they inflate the reference this audit
        # compares against, and the comparison stops meaning anything.
        source = combined.get("source", pd.Series("", index=combined.index))
        is_synthetic = source.astype(str).isin(SYNTHETIC_SOURCES)

        has_address = combined["sender_extracted"] != ""
        real = combined[has_address & ~is_synthetic].copy()
        ours = combined[has_address & is_synthetic].copy()
        generated = combined[(~has_address)
                             & (combined["sender_generated"] != "")].copy()

        auc_r = audit(real, "sender_extracted", "real headers (parsed)")
        auc_c = audit(ours, "sender_extracted", "our own corpus generators")
        auc_g = audit(generated, "sender_generated", "filled in by this script")
        audit(combined, "sender_filled", "everything together")
        verdict(auc_g, auc_r, auc_c)

    if args.write:
        for split, df in frames.items():
            df["sender"] = df["sender_filled"]
            keep = [c for c in ("sender", "subject", "text", "label", "source",
                                "sender_pool") if c in df.columns]
            path = os.path.join(args.data_dir, f"{split}.csv")
            df[keep].to_csv(path, index=False)
            print(f"  wrote {path}")
        print("\n  Re-measure with:  python ML/evaluate.py --split test")
        print("  Numbers on generated senders are synthetic. Report them")
        print("  separately from the numbers on real ones.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
