#!/usr/bin/env python3
"""
passwordmerger.py

Merges password CSV exports from Apple Passwords, Dashlane, and Google
Password Manager into a single CSV formatted for import back into Apple
Passwords. Deduplicates by (URL, username), keeping the most recently
modified entry where a modification date is available, and flags any
same-login entries that have DIFFERENT passwords across sources so you
can resolve them by hand instead of silently picking one.

USAGE
    python3 passwordmerger.py --apple apple.csv --dashlane dashlane.csv \
        --google google.csv --out merged_for_apple_import.csv

    You can omit any source you don't have. Output columns match Apple's
    expected import format: Title,URL,Username,Password,Notes,OTPAuth

WHERE TO GET EACH EXPORT
    Apple Passwords:  Settings/Preferences -> Passwords -> ... -> Export
    Dashlane:         Settings -> Export -> Unsecured Archive (CSV)
    Google:           passwords.google.com -> Settings -> Export

WHAT THIS DOES NOT DO
    It does not check whether any password still "works" on the live
    site -- that isn't something a script can safely or legitimately do.
    After importing, use Apple Passwords' built-in Security
    Recommendations (or Dashlane/Google's Password Health Checkup)
    to flag reused, weak, or breached passwords.
"""

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Each password manager exports slightly different column names. Map the
# ones we care about to a common internal schema:
#   title, url, username, password, notes, otpauth, modified
# ---------------------------------------------------------------------------

COLUMN_MAP = {
    "apple": {
        "title": ["Title"],
        "url": ["URL"],
        "username": ["Username"],
        "password": ["Password"],
        "notes": ["Notes"],
        "otpauth": ["OTPAuth"],
        "modified": [],  # Apple export has no modified date
    },
    "dashlane": {
        "title": ["title", "name"],
        "url": ["url"],
        "username": ["username", "email", "login"],
        "password": ["password"],
        "notes": ["note", "notes"],
        "otpauth": ["otpSecret", "otpauth"],
        "modified": ["lastUpdateDate", "modified"],
    },
    "google": {
        "title": ["name"],
        "url": ["url"],
        "username": ["username"],
        "password": ["password"],
        "notes": ["note"],
        "otpauth": [],
        "modified": [],  # Google export has no modified date either
    },
}


def pick(row, candidates):
    for c in candidates:
        if c in row and row[c]:
            return row[c].strip()
    return ""


def normalize_url(url):
    """Reduce a URL to a bare registrable-ish domain for matching purposes."""
    if not url:
        return ""
    url = url.strip().lower()
    if "://" not in url:
        url = "https://" + url
    try:
        netloc = urlparse(url).netloc
    except Exception:
        netloc = url
    netloc = netloc.replace("www.", "")
    return netloc


def load_csv(path, source):
    """Load one export file into the common schema. Returns list of dicts."""
    cmap = COLUMN_MAP[source]
    rows = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for raw in reader:
                entry = {
                    "title": pick(raw, cmap["title"]),
                    "url": pick(raw, cmap["url"]),
                    "username": pick(raw, cmap["username"]),
                    "password": pick(raw, cmap["password"]),
                    "notes": pick(raw, cmap["notes"]),
                    "otpauth": pick(raw, cmap["otpauth"]),
                    "modified": pick(raw, cmap["modified"]),
                    "source": source,
                }
                if entry["password"]:  # skip empty/broken rows
                    rows.append(entry)
    except FileNotFoundError:
        print(f"  [skip] {source}: file not found at {path}", file=sys.stderr)
    return rows


def parse_date(s):
    if not s:
        return datetime.min
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(s[: len(fmt) + 2], fmt)
        except ValueError:
            continue
    return datetime.min


def main():
    ap = argparse.ArgumentParser(description="Merge password manager CSV exports")
    ap.add_argument("--apple")
    ap.add_argument("--dashlane")
    ap.add_argument("--google")
    ap.add_argument("--out", default="merged_for_apple_import.csv")
    args = ap.parse_args()

    all_rows = []
    if args.apple:
        all_rows += load_csv(args.apple, "apple")
    if args.dashlane:
        all_rows += load_csv(args.dashlane, "dashlane")
    if args.google:
        all_rows += load_csv(args.google, "google")

    if not all_rows:
        print("No input rows loaded. Pass at least one of --apple/--dashlane/--google.")
        sys.exit(1)

    print(f"Loaded {len(all_rows)} total entries from {sum(1 for a in (args.apple, args.dashlane, args.google) if a)} file(s).")

    # Group by (normalized URL, username)
    groups = defaultdict(list)
    for r in all_rows:
        key = (normalize_url(r["url"]), r["username"].lower().strip())
        groups[key].append(r)

    merged = []
    conflicts = []

    for key, entries in groups.items():
        if len(entries) == 1:
            merged.append(entries[0])
            continue

        # Multiple entries for the same login -- check if passwords agree
        distinct_passwords = {e["password"] for e in entries}

        # Pick the "winner" by most recent modified date if we have one,
        # otherwise just take the first (prefer apple > dashlane > google
        # as a tiebreak since apple is the destination)
        source_priority = {"apple": 0, "dashlane": 1, "google": 2}
        entries_sorted = sorted(
            entries,
            key=lambda e: (-parse_date(e["modified"]).timestamp() if parse_date(e["modified"]) != datetime.min else 0,
                            source_priority.get(e["source"], 9)),
        )
        winner = entries_sorted[0]
        merged.append(winner)

        if len(distinct_passwords) > 1:
            conflicts.append((key, entries))

    # Write merged output in Apple's import format
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Title", "URL", "Username", "Password", "Notes", "OTPAuth"])
        for r in merged:
            title = r["title"] or normalize_url(r["url"]) or r["url"]
            writer.writerow([title, r["url"], r["username"], r["password"], r["notes"], r["otpauth"]])

    print(f"\nWrote {len(merged)} deduplicated entries to {args.out}")
    print(f"Dropped {len(all_rows) - len(merged)} duplicate entries.")

    if conflicts:
        conflict_path = args.out.replace(".csv", "_CONFLICTS.csv")
        with open(conflict_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Username", "Source", "Password", "Modified"])
            for key, entries in conflicts:
                for e in entries:
                    writer.writerow([e["url"], e["username"], e["source"], e["password"], e["modified"]])
        print(f"\n⚠ {len(conflicts)} logins had DIFFERENT passwords across sources.")
        print(f"  These were auto-resolved to one value in the merged file, but you")
        print(f"  should double check them: {conflict_path}")
    else:
        print("\nNo password conflicts detected across sources.")

    print(f"\nNext steps:")
    print(f"  1. Review {conflict_path if conflicts else '(no conflicts file needed)'}")
    print(f"  2. In Apple Passwords: Settings -> ... -> Import Passwords -> select {args.out}")
    print(f"  3. Run Apple Passwords' Security Recommendations to flag weak/reused/breached logins")


if __name__ == "__main__":
    main()
