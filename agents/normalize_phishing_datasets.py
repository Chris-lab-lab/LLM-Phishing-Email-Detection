#!/usr/bin/env python3
"""
normalize_phishing_datasets.py

Unified dataset normalization script for three CSV inputs:
- emails.csv
- Nazario_5.csv
- Phising_Email.csv

What it does:
- Loads arbitrary CSVs and attempts to locate Subject/Body/From/Label/Raw header columns
- Extracts URLs from body text
- Parses RFC-822 style raw email text when available to recover headers/body
- Normalizes labels to {"phishing","legitimate","unknown"}
- Deduplicates (simple hash of subject+body+from)
- Saves outputs:
    - normalized_dataset.json  (list of normalized samples)
    - normalized_dataset.csv   (tabular view)
    - train.json / test.json   (80/20 split)

Usage:
    python normalize_phishing_datasets.py --files emails.csv Nazario_5.csv Phising_Email.csv

Dependencies: pandas (recommended). The script will still run without pandas but with degraded convenience.
"""

import argparse
import csv
import json
import os
import random
import re
import sys
from email import message_from_string
from typing import Dict, List, Optional

try:
    import pandas as pd
except Exception:
    pd = None

URL_REGEX = re.compile(r"https?://[^\s)\"]+|www\.[^\s)\"]+", flags=re.IGNORECASE)

# Candidate column names for common fields (case-insensitive)
SUBJECT_CANDIDATES = ["subject", "title", "mail_subject", "email_subject"]
BODY_CANDIDATES = ["body", "message", "text", "content", "email_body", "raw_body", "mail_body"]
FROM_CANDIDATES = ["from", "sender", "from_address", "email_from"]
LABEL_CANDIDATES = ["label", "class", "is_phishing", "target", "y", "category"]
RAW_CANDIDATES = ["raw", "raw_email", "eml", "message_raw", "full_message", "original_message"]

# Common label normalization map (lowercased)
LABEL_MAP = {
    "phishing": "phishing",
    "phish": "phishing",
    "malicious": "phishing",
    "spam_phishing": "phishing",
    "1": "phishing",
    "true": "phishing",
    "legitimate": "legitimate",
    "ham": "legitimate",
    "not_phishing": "legitimate",
    "0": "legitimate",
    "false": "legitimate",
}


def find_column(df_columns: List[str], candidates: List[str]) -> Optional[str]:
    """Find first matching column name from a list of candidates (case-insensitive)."""
    lower_to_orig = {c.lower(): c for c in df_columns}
    for cand in candidates:
        for col_lower, col_orig in lower_to_orig.items():
            if cand.lower() == col_lower:
                return col_orig
    # fuzzy: match if candidate substring in column name
    for cand in candidates:
        for col_lower, col_orig in lower_to_orig.items():
            if cand.lower() in col_lower:
                return col_orig
    return None


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = URL_REGEX.findall(text)
    # normalize: remove trailing punctuation
    cleaned = [u.rstrip('.,;:') for u in urls]
    return cleaned


def parse_raw_email(raw: str) -> Dict[str, Optional[str]]:
    """Attempt to parse a raw RFC-822 email stored as a string using the email module."""
    if not raw or not isinstance(raw, str):
        return {"subject": None, "body": None, "from": None, "headers": None}
    try:
        msg = message_from_string(raw)
        subject = msg.get('Subject')
        fromhdr = msg.get('From')
        # get first non-empty payload for body
        body = None
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == 'text/plain':
                    try:
                        body = part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='replace')
                        break
                    except Exception:
                        payload = part.get_payload()
                        if isinstance(payload, str):
                            body = payload
                            break
        else:
            try:
                body = msg.get_payload(decode=True).decode(msg.get_content_charset('utf-8'), errors='replace')
            except Exception:
                body = msg.get_payload()
        headers = dict(msg.items())
        return {"subject": subject, "body": body, "from": fromhdr, "headers": headers}
    except Exception:
        return {"subject": None, "body": None, "from": None, "headers": None}


def normalize_label(raw_label: Optional[str], source_hint: Optional[str] = None) -> str:
    if raw_label is None:
        # use filename hint if available
        if source_hint and 'nazario' in source_hint.lower():
            return 'phishing'
        return 'unknown'
    lab = str(raw_label).strip().lower()
    if lab in LABEL_MAP:
        return LABEL_MAP[lab]
    # heuristics
    if any(k in lab for k in ['phish', 'fraud', 'malicious', 'scam']):
        return 'phishing'
    if any(k in lab for k in ['legit', 'ham', 'not', 'normal']):
        return 'legitimate'
    return 'unknown'


def simple_hash(s: str) -> str:
    # small stable hash for deduping
    import hashlib
    return hashlib.sha1(s.encode('utf-8', errors='ignore')).hexdigest()


def normalize_df_like(obj, source_name: str = None) -> List[Dict]:
    """Take a pandas.DataFrame-like object or list-of-dicts and return list of normalized records."""
    rows = []
    if pd is not None and isinstance(obj, pd.DataFrame):
        df = obj
        cols = list(df.columns)
        subj_col = find_column(cols, SUBJECT_CANDIDATES)
        body_col = find_column(cols, BODY_CANDIDATES)
        from_col = find_column(cols, FROM_CANDIDATES)
        label_col = find_column(cols, LABEL_CANDIDATES)
        raw_col = find_column(cols, RAW_CANDIDATES)

        for _, r in df.iterrows():
            raw_label = r[label_col] if label_col and label_col in df.columns else None
            label = normalize_label(raw_label, source_hint=source_name)

            # attempt priority: explicit subject/body -> raw eml parse -> heuristics
            subject = r[subj_col] if subj_col and subj_col in df.columns else None
            body = r[body_col] if body_col and body_col in df.columns else None
            sender = r[from_col] if from_col and from_col in df.columns else None

            # if raw exists, try parsing it
            if raw_col and raw_col in df.columns and (not subject or not body):
                parsed = parse_raw_email(r[raw_col])
                subject = subject or parsed.get('subject')
                body = body or parsed.get('body')
                sender = sender or parsed.get('from')

            # if body is bytes -> decode
            if isinstance(body, (bytes, bytearray)):
                try:
                    body = body.decode('utf-8', errors='replace')
                except Exception:
                    body = str(body)

            if isinstance(subject, (bytes, bytearray)):
                try:
                    subject = subject.decode('utf-8', errors='replace')
                except Exception:
                    subject = str(subject)

            body_text = (subject or '') + '\n\n' + (body or '')
            urls = extract_urls(body_text)

            rec = {
                'subject': subject or '',
                'body': body or '',
                'urls': urls,
                'metadata': {
                    'from': sender or '',
                    'source': source_name or ''
                },
                'label': label
            }
            rows.append(rec)
    else:
        # assume list of dicts
        iterable = obj
        for r in iterable:
            subj = r.get('subject') or r.get('Subject') or r.get('title')
            body = r.get('body') or r.get('message') or r.get('content') or r.get('text')
            raw = r.get('raw') or r.get('eml')
            sender = r.get('from') or r.get('sender')
            label = normalize_label(r.get('label') or r.get('class'), source_hint=source_name)
            if raw and (not subj or not body):
                parsed = parse_raw_email(raw)
                subj = subj or parsed.get('subject')
                body = body or parsed.get('body')
                sender = sender or parsed.get('from')
            urls = extract_urls((subj or '') + '\n\n' + (body or ''))
            rows.append({
                'subject': subj or '',
                'body': body or '',
                'urls': urls,
                'metadata': {'from': sender or '', 'source': source_name or ''},
                'label': label
            })
    return rows


def load_csv_autodetect(path: str):
    """Load CSV using pandas if available, else via csv.DictReader."""
    if pd is not None:
        try:
            df = pd.read_csv(path, dtype=object, encoding='utf-8', on_bad_lines='skip')
            return df
        except Exception:
            try:
                df = pd.read_csv(path, dtype=object, encoding='latin-1', on_bad_lines='skip')
                return df
            except Exception as e:
                print(f"[warning] pandas failed to read {path}: {e}")
    # fallback to csv module
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            rows.append(r)
    return rows


def dedupe_records(records: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for r in records:
        key = (r.get('subject','') or '') + '||' + (r.get('body','') or '') + '||' + (r.get('metadata',{}).get('from','') or '')
        h = simple_hash(key)
        if h in seen:
            continue
        seen.add(h)
        out.append(r)
    return out


def train_test_split(records: List[Dict], test_frac: float = 0.2, seed: int = 42):
    random.Random(seed).shuffle(records)
    n_test = int(len(records) * test_frac)
    test = records[:n_test]
    train = records[n_test:]
    return train, test


def save_json(path: str, obj):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)


def save_csv(path: str, records: List[Dict]):
    # flatten to rows for CSV
    if not records:
        return
    keys = ['subject', 'body', 'urls', 'label', 'metadata.from', 'metadata.source']
    with open(path, 'w', encoding='utf-8', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow(keys)
        for r in records:
            writer.writerow([
                r.get('subject',''),
                r.get('body',''),
                '|'.join(r.get('urls',[])),
                r.get('label',''),
                r.get('metadata',{}).get('from',''),
                r.get('metadata',{}).get('source','')
            ])


def main(file_paths: List[str]):
    all_records = []
    for p in file_paths:
        if not os.path.exists(p):
            print(f"[warning] file not found: {p}")
            continue
        print(f"Loading {p}...")
        raw = load_csv_autodetect(p)
        print(f"  loaded {len(raw) if hasattr(raw,'__len__') else 0} rows (approx)")
        rows = normalize_df_like(raw, source_name=os.path.basename(p))
        print(f"  normalized -> {len(rows)} records")
        # if filename strongly indicates phishing-only dataset, force label
        if 'nazario' in p.lower() or 'phish' in p.lower():
            for r in rows:
                # do not override explicit legitimate labels, but if unknown -> phishing
                if r.get('label','unknown') == 'unknown':
                    r['label'] = 'phishing'
        all_records.extend(rows)

    print(f"Total before dedupe: {len(all_records)}")
    records = dedupe_records(all_records)
    print(f"After dedupe: {len(records)}")

    # summary counts
    from collections import Counter
    counts = Counter([r.get('label','unknown') for r in records])
    print("Label distribution:")
    for k,v in counts.items():
        print(f"  {k}: {v}")

    # save normalized dataset
    save_json('normalized_dataset.json', records)
    save_csv('normalized_dataset.csv', records)
    print("Saved normalized_dataset.json and normalized_dataset.csv")

    # train/test split
    train, test = train_test_split(records, test_frac=0.2)
    save_json('train.json', train)
    save_json('test.json', test)
    print(f"Saved train.json ({len(train)}) and test.json ({len(test)})")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Normalize phishing datasets into unified JSON/CSV')
    parser.add_argument('--files', nargs='+', required=False, default=['emails.csv','Nazario_5.csv','Phising_Email.csv'], help='CSV file paths to normalize')
    args = parser.parse_args()
    main(args.files)
