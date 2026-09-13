"""Export tool user agents from profile YAML files into a hunting CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILES_DIR = REPO_ROOT / "Profiles"
DEFAULT_OUTPUT = REPO_ROOT / "Indicator Lists" / "UserAgents.csv"


def collect_user_agents(profiles_dir: Path) -> list[tuple[str, str]]:
    rows: set[tuple[str, str]] = set()

    for profile_path in sorted(profiles_dir.glob("*.y*ml")):
        with profile_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        tool_name = (data.get("tool") or {}).get("name") or profile_path.stem
        for user_agent in data.get("user_agents") or []:
            user_agent = str(user_agent).strip()
            if user_agent:
                rows.add((str(tool_name), user_agent))

    return sorted(rows)


def write_csv(rows: list[tuple[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
        writer.writerow(["Toolname", "UserAgent"])
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles-dir", type=Path, default=DEFAULT_PROFILES_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    rows = collect_user_agents(args.profiles_dir)
    write_csv(rows, args.output)
    print(f"Wrote {len(rows)} user agent entries to {args.output}")


if __name__ == "__main__":
    main()
