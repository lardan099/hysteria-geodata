#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path


LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_domain(value: str) -> str | None:
    value = value.strip().strip("\"'").strip().rstrip(".")
    if not value or "\ufffd" in value or any(character.isspace() for character in value):
        return None

    if value.startswith("*."):
        value = value[2:]
    value = value.lstrip(".")

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(value) > 253:
        return None

    labels = value.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        return None

    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    seen: set[str] = set()
    kept = 0
    duplicates = 0
    rejected = 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.input.open("r", encoding="utf-8", errors="replace") as source:
        with args.output.open("w", encoding="utf-8", newline="\n") as destination:
            for raw_line in source:
                line = raw_line.strip()
                if not line or line.startswith(("#", "!")):
                    continue

                domain = normalize_domain(line)
                if domain is None:
                    rejected += 1
                    continue
                if domain in seen:
                    duplicates += 1
                    continue

                seen.add(domain)
                destination.write(domain + "\n")
                kept += 1

    print(
        f"{args.input}: kept={kept} duplicates={duplicates} rejected={rejected}",
        file=sys.stderr,
    )
    if kept == 0:
        print(f"{args.input}: no valid domains found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
