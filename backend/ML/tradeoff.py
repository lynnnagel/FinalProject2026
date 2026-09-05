"""
The recall / precision trade-off, measured at the base rate of a real inbox.

Why this is a separate script from evaluate.py --sweep
------------------------------------------------------
That sweep reports accuracy and F1 on the test split, where phishing is
48.6% of the mail. Both numbers are close to 99% at every threshold, so
the sweep looks like a flat plateau and there is no visible trade-off to
reason about.

A real inbox is around 1% phishing, and at that rate the two metrics
behave completely differently:

    recall, FPR   unchanged. Both are class-conditional - they are
                  measured within one class, so the mix between classes
                  cannot move them.
    precision     collapses. The false alarms are drawn from a pool
                  ~99x larger than the true detections.

So the honest way to choose a threshold is to measure recall and FPR on
the test split, which the split can support, and then project precision
to the base rate the product will actually meet. That projection is
exact, not a simulation:

    precision(b) = b*TPR / ( b*TPR + (1-b)*FPR )

This script does the projection at every threshold and prints the curve.
It also solves the inverse question - what FPR a precision target needs -
because that turns "improve precision" into a number to aim at.

    python ML/tradeoff.py                        # sweep + PR curve at 1%
    python ML/tradeoff.py --pr-svg               # write figs/pr-curve.svg
    python ML/tradeoff.py --base-rate 0.02
    python ML/tradeoff.py --target-precision 0.8
    python ML/tradeoff.py --csv figs/tradeoff.csv    # data for the graph
    python ML/tradeoff.py --no-bert                  # rules only, fast

A note on reading the PR curve for this system
----------------------------------------------
The usual curve sweeps smoothly from high precision at low recall down
to low precision at high recall. This one will not: recall is roughly
99.3% at every cut-off between 40 and 80, so nearly the whole operating
range collapses into a short segment near the right-hand edge, with the
interesting variation happening above 80 where no measurement existed
before this script. That shape is a property of a bimodal score
distribution, and it is the finding - not a defect in the plot.

Average precision is reported at the projected base rate, so it is
comparable to the 0.01 a random classifier would score there, and NOT
comparable to an AP computed on the balanced corpus.

What the curve showed when this was written
-------------------------------------------
Between thresholds 40 and 80 recall moves by 0.02 points - from 99.29%
to 99.27% - while precision at 1% moves from 49.3% to 67.4%. That is
not the usual trade-off shape, and it is worth understanding rather than
smoothing over: the score distribution is bimodal, so almost no message
sits between 40 and 80 and moving the cut-off through that range
reclassifies very few of them.

Two things follow. Raising the threshold is nearly free, so it should be
raised. And the threshold is a weak lever: reaching 80% precision at a
1% base rate needs the false alarms cut from 44 to 19, which no cut-off
in the measured range delivers. That requires new evidence of
legitimacy, not a different cut-off.
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import (                                              # noqa: E402
    PHISHING_THRESHOLD, CORROBORATION_FLOOR, bands_for,
)
from ML.calibrate import load_split                               # noqa: E402
from ML.evaluate import score_rows                                # noqa: E402


def confusion_at(scores, rule_scores, y, t, apply_ceiling: bool):
    """
    TP/FP/TN/FN at cut-off t.

    The uncorroborated ceiling is derived from t rather than held fixed.
    Holding it fixed while moving the threshold made every cut-off above
    the ceiling look like a collapse - a bug in the earlier sweep, not a
    property of the data.
    """
    cap = bands_for(t)[2] - 1
    tp = fp = tn = fn = 0
    for score, rule, truth in zip(scores, rule_scores, y):
        if apply_ceiling and rule < CORROBORATION_FLOOR:
            score = min(score, cap)
        pred = 1 if score >= t else 0
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def precision_at(tpr: float, fpr: float, base_rate: float) -> float:
    """Precision the measured TPR and FPR would give at this base rate."""
    detections = base_rate * tpr
    false_alarms = (1 - base_rate) * fpr
    return detections / (detections + false_alarms) if detections + false_alarms else 0.0


def fpr_needed(tpr: float, base_rate: float, target: float) -> float:
    """The FPR a precision target requires. The inverse of the above."""
    return base_rate * tpr * (1 - target) / ((1 - base_rate) * target)


def pr_curve(scores, rule_scores, y, base_rate, apply_ceiling):
    """
    The precision-recall curve at one base rate, one point per cut-off.

    Swept from 100 down to 0 so recall rises along the curve, which is
    the direction average precision is summed in.
    """
    positives = sum(y)
    negatives = len(y) - positives
    points = []
    for t in range(100, -1, -1):
        tp, fp, tn, fn = confusion_at(scores, rule_scores, y, t, apply_ceiling)
        recall = tp / positives if positives else 0.0
        fpr = fp / negatives if negatives else 0.0
        # No detections at all: precision is undefined. Convention is to
        # carry the previous value rather than plot a hole.
        precision = (precision_at(recall, fpr, base_rate) if tp
                     else (points[-1]["precision"] if points else 1.0))
        points.append({"threshold": t, "recall": recall, "precision": precision,
                       "fpr": fpr, "tp": tp, "fp": fp, "fn": fn})
    return points


def average_precision(points) -> float:
    """
    Area under the PR curve, summed as sum (R_n - R_n-1) * P_n.

    The step-wise form, not the trapezoid: interpolating between
    operating points credits the classifier with performance it was
    never measured at.
    """
    total, previous_recall = 0.0, 0.0
    for p in points:
        total += (p["recall"] - previous_recall) * p["precision"]
        previous_recall = p["recall"]
    return total


def write_svg(path, points, base_rate, operating, ap_score, split_name):
    """
    The curve as a standalone SVG.

    Written by hand rather than through a plotting library: the project
    has no matplotlib dependency, and adding one so a single figure can
    be drawn would be a poor trade. SVG also scales into the report
    without going fuzzy.
    """
    W, H = 620, 430
    M = {"l": 66, "t": 26, "r": 22, "b": 62}
    pw, ph = W - M["l"] - M["r"], H - M["t"] - M["b"]
    sx = lambda r: M["l"] + r * pw
    sy = lambda p: M["t"] + ph - p * ph

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="Arial, Helvetica, sans-serif">',
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
    ]

    for i in range(6):
        v = i / 5
        gy, gx = sy(v), sx(v)
        parts.append(f'<line x1="{M["l"]}" y1="{gy:.1f}" x2="{M["l"] + pw}" '
                     f'y2="{gy:.1f}" stroke="#EAE7F2" stroke-width="1"/>')
        parts.append(f'<text x="{M["l"] - 9}" y="{gy + 4:.1f}" text-anchor="end" '
                     f'font-size="11" fill="#A9A5BC">{v * 100:.0f}%</text>')
        parts.append(f'<text x="{gx:.1f}" y="{M["t"] + ph + 18}" '
                     f'text-anchor="middle" font-size="11" '
                     f'fill="#A9A5BC">{v * 100:.0f}%</text>')

    # A classifier guessing at random scores precision equal to the base
    # rate, whatever its recall. Without this line on the chart there is
    # nothing to judge the curve against.
    by = sy(base_rate)
    parts.append(f'<line x1="{M["l"]}" y1="{by:.1f}" x2="{M["l"] + pw}" '
                 f'y2="{by:.1f}" stroke="#C9C4D8" stroke-width="1.4" '
                 f'stroke-dasharray="5 4"/>')
    parts.append(f'<text x="{M["l"] + pw - 4}" y="{by - 7:.1f}" text-anchor="end" '
                 f'font-size="10.5" fill="#8B87A0">ניחוש אקראי — '
                 f'{base_rate * 100:g}%</text>')

    path_d = " ".join(
        ("M" if i == 0 else "L") + f"{sx(p['recall']):.1f} {sy(p['precision']):.1f}"
        for i, p in enumerate(points))
    parts.append(f'<path d="{path_d}" fill="none" stroke="#6B3FE0" '
                 f'stroke-width="2.6" stroke-linejoin="round"/>')

    if operating:
        ox, oy = sx(operating["recall"]), sy(operating["precision"])
        parts.append(f'<circle cx="{ox:.1f}" cy="{oy:.1f}" r="5.5" fill="#D98A00"/>')
        parts.append(f'<circle cx="{ox:.1f}" cy="{oy:.1f}" r="10" fill="none" '
                     f'stroke="#D98A00" stroke-width="1.3" opacity="0.4"/>')
        label = (f'סף {operating["threshold"]} — recall '
                 f'{operating["recall"] * 100:.1f}%, precision '
                 f'{operating["precision"] * 100:.1f}%')
        anchor, dx = ("end", -14) if operating["recall"] > 0.5 else ("start", 14)
        parts.append(f'<text x="{ox + dx:.1f}" y="{oy - 12:.1f}" '
                     f'text-anchor="{anchor}" font-size="11.5" fill="#16141F" '
                     f'font-weight="bold">{label}</text>')

    parts += [
        f'<line x1="{M["l"]}" y1="{M["t"] + ph}" x2="{M["l"] + pw}" '
        f'y2="{M["t"] + ph}" stroke="#CFCADC" stroke-width="1.2"/>',
        f'<text x="{M["l"] + pw / 2}" y="{H - 24}" text-anchor="middle" '
        f'font-size="12.5" fill="#4A4660">Recall</text>',
        f'<text transform="rotate(-90 16 {M["t"] + ph / 2})" x="16" '
        f'y="{M["t"] + ph / 2}" text-anchor="middle" font-size="12.5" '
        f'fill="#4A4660">Precision</text>',
        f'<text x="{M["l"]}" y="{M["t"] - 9}" font-size="12.5" fill="#16141F" '
        f'font-weight="bold">עקומת Precision-Recall · שיעור בסיס '
        f'{base_rate * 100:g}% · AP={ap_score:.3f}</text>',
        f'<text x="{M["l"] + pw}" y="{M["t"] - 9}" text-anchor="end" '
        f'font-size="10.5" fill="#A9A5BC">{split_name}</text>',
        '</svg>',
    ]

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(parts))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    # load_split() appends "processed" itself, and evaluate.py spells the
    # flag with an underscore. Both spellings are accepted so a command
    # copied from either script works.
    ap.add_argument("--data_dir", "--data-dir", dest="data_dir",
                    default="ML/data")
    ap.add_argument("--split", default="test")
    ap.add_argument("--base-rate", type=float, default=0.01,
                    help="phishing share of a real inbox (default 0.01)")
    ap.add_argument("--target-precision", type=float, default=0.80)
    ap.add_argument("--no-bert", action="store_true")
    ap.add_argument("--bert-only", action="store_true")
    ap.add_argument("--csv", help="write the threshold sweep for plotting")
    ap.add_argument("--step", type=int, default=2)
    ap.add_argument("--pr-svg", nargs="?", const="figs/pr-curve.svg",
                    help="write the precision-recall curve as an SVG")
    ap.add_argument("--pr-csv", help="write the PR curve points")
    args = ap.parse_args()

    df = load_split(args.data_dir, args.split)
    y = df["label"].tolist()
    positives, negatives = sum(y), len(y) - sum(y)
    print(f"  {args.split}: {len(df):,} rows, {positives:,} phishing "
          f"({positives / len(df):.1%}), {negatives:,} legitimate")
    print(f"  projecting precision to a base rate of {args.base_rate:.1%}\n")

    apply_ceiling = not (args.bert_only or args.no_bert)
    scores, rule_scores = score_rows(
        df, use_bert=not args.no_bert, bert_only=args.bert_only,
        uncapped=apply_ceiling,
    )

    print("=" * 78)
    print(f"  Threshold sweep - recall and FPR measured, precision projected")
    print("=" * 78)
    print(f"  {'thr':>4} {'FP':>5} {'FN':>5} {'recall':>8} {'FPR':>8}"
          f" {'prec@br':>9} {'F1@br':>7} {'alarms/1k':>10} {'caught/1k':>10}")
    print("  " + "-" * 74)

    rows = []
    for t in range(20, 100, args.step):
        tp, fp, tn, fn = confusion_at(scores, rule_scores, y, t, apply_ceiling)
        tpr = tp / positives if positives else 0.0
        fpr = fp / negatives if negatives else 0.0
        prec = precision_at(tpr, fpr, args.base_rate)
        f1 = 2 * prec * tpr / (prec + tpr) if prec + tpr else 0.0
        rows.append({
            "threshold": t, "fp": fp, "fn": fn, "recall": tpr, "fpr": fpr,
            "precision_at_base_rate": prec, "f1_at_base_rate": f1,
            "false_alarms_per_1000": fpr * 1000 * (1 - args.base_rate),
            "caught_per_1000": tpr * 1000 * args.base_rate,
        })
        marker = "  <- current" if t <= PHISHING_THRESHOLD < t + args.step else ""
        print(f"  {t:>4} {fp:>5} {fn:>5} {tpr * 100:>7.2f}% {fpr * 100:>7.3f}%"
              f" {prec * 100:>8.1f}% {f1:>7.3f}"
              f" {fpr * 1000 * (1 - args.base_rate):>10.2f}"
              f" {tpr * 1000 * args.base_rate:>10.2f}{marker}")

    # ---------------------------------------------------------------
    best_f1 = max(rows, key=lambda r: r["f1_at_base_rate"])
    hit = next((r for r in rows
                if r["precision_at_base_rate"] >= args.target_precision), None)
    current = min(rows, key=lambda r: abs(r["threshold"] - PHISHING_THRESHOLD))

    print("\n" + "=" * 78)
    print("  What the curve says")
    print("=" * 78)
    print(f"  current threshold {PHISHING_THRESHOLD}: recall "
          f"{current['recall'] * 100:.2f}%, precision "
          f"{current['precision_at_base_rate'] * 100:.1f}% at "
          f"{args.base_rate:.1%}")
    print(f"  best F1 at {args.base_rate:.1%}: threshold {best_f1['threshold']}"
          f" (recall {best_f1['recall'] * 100:.2f}%, precision "
          f"{best_f1['precision_at_base_rate'] * 100:.1f}%)")

    if hit:
        cost = current["recall"] - hit["recall"]
        print(f"  {args.target_precision:.0%} precision is reached at threshold "
              f"{hit['threshold']}, costing {cost * 100:.2f} points of recall")
    else:
        needed = fpr_needed(current["recall"], args.base_rate, args.target_precision)
        print(f"  {args.target_precision:.0%} precision is NOT reachable by moving"
              f" the threshold.")
        print(f"  It needs FPR {needed * 100:.3f}% "
              f"({needed * negatives:.0f} false alarms out of {negatives:,});"
              f" the best any cut-off gives is "
              f"{min(r['fpr'] for r in rows) * 100:.3f}% "
              f"({min(r['fp'] for r in rows)}).")
        print(f"  That is a structural limit, not a calibration one: it needs new")
        print(f"  evidence of legitimacy - a verified sender, a known "
              f"correspondent - not a different cut-off.")

    # The shape of the curve is itself a finding worth stating.
    span_recall = max(r["recall"] for r in rows) - min(r["recall"] for r in rows)
    if span_recall < 0.02:
        print(f"\n  Note: recall varies by only {span_recall * 100:.2f} points across"
              f" the whole sweep.")
        print("  The score distribution is bimodal - few messages sit between the")
        print("  cut-offs - so raising the threshold costs almost no recall.")

    # ---------------------------------------------------------------
    # The precision-recall curve. Swept at every integer cut-off rather
    # than the coarse step above, because the curve is the shape and a
    # coarse sweep hides it.
    curve = pr_curve(scores, rule_scores, y, args.base_rate, apply_ceiling)
    ap_score = average_precision(curve)
    operating = min(curve, key=lambda p: abs(p["threshold"] - PHISHING_THRESHOLD))

    print("\n" + "=" * 78)
    print(f"  Precision-Recall curve at a {args.base_rate:.1%} base rate")
    print("=" * 78)
    print(f"  average precision (AP)   {ap_score:.4f}")
    print(f"  a random classifier      {args.base_rate:.4f}"
          f"   ({ap_score / args.base_rate:.0f}x better)")
    print(f"  operating point          threshold {operating['threshold']}, "
          f"recall {operating['recall'] * 100:.2f}%, "
          f"precision {operating['precision'] * 100:.1f}%")

    # The cheapest cut-off that still reaches each recall target. On a
    # bimodal score distribution most targets land on the same point, so
    # repeats are dropped - six identical rows say less than two
    # different ones.
    print(f"\n  {'recall':>8} {'precision':>10} {'threshold':>10}")
    print("  " + "-" * 30)
    shown = set()
    for target in (0.50, 0.80, 0.90, 0.95, 0.98, 0.99, 0.992, 0.993, 0.994):
        point = next((p for p in curve if p["recall"] >= target), None)
        if point and point["threshold"] not in shown:
            shown.add(point["threshold"])
            print(f"  {point['recall'] * 100:>7.2f}% {point['precision'] * 100:>9.1f}%"
                  f" {point['threshold']:>10}")
    if len(shown) < 3:
        print("  (recall is nearly constant, so most targets share one cut-off)")

    if args.csv:
        os.makedirs(os.path.dirname(os.path.abspath(args.csv)), exist_ok=True)
        pd.DataFrame(rows).to_csv(args.csv, index=False)
        print(f"\n  wrote {args.csv}")

    if args.pr_csv:
        os.makedirs(os.path.dirname(os.path.abspath(args.pr_csv)), exist_ok=True)
        pd.DataFrame(curve).to_csv(args.pr_csv, index=False)
        print(f"  wrote {args.pr_csv}")

    if args.pr_svg:
        os.makedirs(os.path.dirname(os.path.abspath(args.pr_svg)), exist_ok=True)
        write_svg(args.pr_svg, curve, args.base_rate, operating, ap_score,
                  f"{args.split} · {len(df):,} rows")
        print(f"  wrote {args.pr_svg}")


if __name__ == "__main__":
    main()
