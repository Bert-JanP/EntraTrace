#!/usr/bin/env python3
"""Extract API endpoint behavior from attack tool source code into YAML."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


SUPPORTED_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".py",
    ".js",
    ".ts",
    ".go",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".java",
    ".rb",
    ".php",
    ".sh",
    ".json",
    ".psd1",
    ".yml",
    ".yaml",
    ".toml",
    ".xml",
    ".rs",
    ".kt",
    ".kts",
    ".swift",
    ".bat",
    ".cmd",
    ".ipynb",
}

SKIP_DIRS = {
    ".git",
    ".github",
    "node_modules",
    "dist",
    "build",
    "bin",
    "obj",
    "venv",
    ".venv",
    "__pycache__",
}

URL_PATTERN = re.compile(
    r"(?:https?://|//)[A-Za-z0-9._~:/?#\[\]{}@!$&'()*+,;=%-]+", re.IGNORECASE
)
HOST_LITERAL_PATTERN = re.compile(
    r"(?i)(https?://)?(graph\.microsoft\.com|graph\.windows\.net|management\.azure\.com)"
)
API_PATH_FRAGMENT_PATTERN = re.compile(
    r"['\"](/?(?:v1\.0|beta|subscriptions|providers|tenants|users|groups|domains|sites|drives|directoryObjects|policies|roleManagement)[^'\"\s]{1,260})['\"]",
    re.IGNORECASE,
)
API_CONTEXT_PATTERN = re.compile(r"(?i)uri|url|endpoint|graph|api|rest|resource|path|request")
UA_HEADER_PATTERN = re.compile(
    r"(?i)(?:['\"]user-agent['\"]\s*[:=]\s*[fF]?['\"]([^'\"]{3,250})['\"]|\buser[_-]?agent\b\s*=\s*[fF]?['\"]([^'\"]{3,250})['\"]|\b-UserAgent\b\s+[\"']([^\"']{3,250})[\"'])"
)

FAMILY_BY_HOST = {
    "graph.microsoft.com": "microsoft_graph",
    "graph.windows.net": "azure_ad_graph",
    "management.azure.com": "azure_resource_manager",
}

DISPLAY_NAME = {
    "microsoft_graph": "Microsoft Graph",
    "azure_ad_graph": "Azure AD Graph",
    "azure_resource_manager": "Azure Resource Manager",
}

KNOWN_API_HOSTS = set(FAMILY_BY_HOST)
GRAPH_PATH_PREFIXES = (
    "v1.0/",
    "beta/",
    "users",
    "groups",
    "domains",
    "sites",
    "drives",
    "directoryobjects",
    "policies",
    "rolemanagement",
    "applications",
    "serviceprincipals",
    "devices",
    "organization",
    "auditlogs",
    "signin",
    "signins",
    "reports",
    "security",
    "identity",
    "teams",
    "chats",
    "messages",
    "calendar",
    "me",
    "communications",
    "print",
    "education",
)
ARM_PATH_PREFIXES = ("subscriptions/", "providers/", "tenants/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract API endpoints from source code and save a YAML behavior profile."
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--repo",
        help="Repository URL (for example https://github.com/org/repo) or local path",
    )
    source_group.add_argument(
        "--all-profiles",
        action="store_true",
        help="Update every YAML profile in --output-dir using its repository_url",
    )
    parser.add_argument("--tool-name", default=None, help="Override inferred tool name")
    parser.add_argument(
        "--output-dir",
        default="api-behavior-agent/profiles",
        help="Directory for generated YAML profiles",
    )
    parser.add_argument(
        "--last-checked-utc",
        default=None,
        help="Override timestamp in UTC (example: 2026-07-22T10:00:00Z)",
    )
    parser.add_argument(
        "--include-non-api-urls",
        action="store_true",
        help="Include all URLs (default keeps likely API URLs only)",
    )
    parser.add_argument(
        "--no-clone",
        action="store_true",
        help="Treat --repo as local path even if it looks like a URL",
    )
    return parser.parse_args()




def read_profile_source(profile_path: Path) -> tuple[str, str]:
    text = profile_path.read_text(encoding="utf-8")
    name_match = re.search(
        r'^  name:\s*["\']?([^"\'\r\n]+)["\']?\s*$', text, re.MULTILINE
    )
    repo_match = re.search(
        r'^  repository_url:\s*["\']([^"\']+)["\']\s*$', text, re.MULTILINE
    )
    if not name_match or not repo_match:
        raise ValueError("profile must contain tool.name and tool.repository_url")
    return name_match.group(1).strip(), repo_match.group(1).strip()


def now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def normalize_url(raw: str) -> str:
    url = raw.strip()
    while url and url[-1] in ").,;]>'\"":
        url = url[:-1]
    return url


def has_balanced_pair(value: str, start: str, end: str) -> bool:
    depth = 0
    i = 0
    max_i = len(value)
    start_len = len(start)
    end_len = len(end)
    while i < max_i:
        if value.startswith(start, i):
            depth += 1
            i += start_len
            continue
        if value.startswith(end, i):
            depth -= 1
            if depth < 0:
                return False
            i += end_len
            continue
        i += 1
    return depth == 0


def sanitize_endpoint(endpoint: str) -> str:
    value = normalize_url(endpoint)
    if not value:
        return ""
    if value.count("https://") + value.count("http://") > 1:
        return ""
    if "','http" in value or '","http' in value:
        return ""
    if value.count("{") != value.count("}"):
        return ""
    if not has_balanced_pair(value, "$(", ")"):
        return ""
    if not has_balanced_pair(value, "(", ")"):
        return ""
    return value


def safe_urlparse(url: str):
    try:
        return urlparse(url)
    except ValueError:
        return None


def classify_family(url: str) -> tuple[str, str]:
    parsed = safe_urlparse(url)
    host = ((parsed.netloc if parsed else "") or "").lower()
    family = FAMILY_BY_HOST.get(host, "other")

    if family == "other" and parsed:
        normalized_path = (parsed.path or "").lower().lstrip("/")
        if normalized_path.startswith(ARM_PATH_PREFIXES):
            family = "azure_resource_manager"
        elif normalized_path.startswith(GRAPH_PATH_PREFIXES):
            family = "microsoft_graph"

    return family, host


def infer_name_from_repo(repo: str) -> str:
    raw = repo.rstrip("/")
    tail = raw.split("/")[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail or "unknown-tool"


def is_repo_url(value: str) -> bool:
    return value.lower().startswith("http://") or value.lower().startswith("https://")


def prepare_source(repo: str, no_clone: bool) -> tuple[Path, str, Path | None]:
    if is_repo_url(repo) and not no_clone:
        temp_dir = Path(tempfile.mkdtemp(prefix="api-behavior-agent-"))
        clone_dir = temp_dir / "repo"
        cmd = ["git", "clone", "--depth", "1", repo, str(clone_dir)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as ex:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise SystemExit(f"Failed to clone repo: {repo}\n{ex.stderr.strip()}") from ex
        return clone_dir.resolve(), repo, temp_dir

    source_root = Path(repo).expanduser().resolve()
    if not source_root.exists() or not source_root.is_dir():
        raise SystemExit(f"Local repo path does not exist or is not a directory: {source_root}")
    return source_root, source_root.as_posix(), None


def resource_hint(url: str) -> str:
    parsed = safe_urlparse(url)
    path = ((parsed.path if parsed else "") or "").strip("/")
    if not path:
        return "root"
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "root"
    if parts[0] in {"v1.0", "beta"} and len(parts) > 1:
        return normalize_resource(parts[1])
    if parts[0].startswith("{") and len(parts) > 1:
        return normalize_resource(parts[1])
    return normalize_resource(parts[0])


def normalize_resource(value: str) -> str:
    token = value.strip()
    if not token:
        return "root"
    if token.startswith("{") or token.startswith("$") or token.startswith("%"):
        return token
    return token.lower()


def canonicalize_url(url: str) -> str:
    parsed = safe_urlparse(url)
    if parsed is None:
        return ""

    scheme = (parsed.scheme or "https").lower()
    host = (parsed.netloc or "").lower()
    if not host:
        return ""

    path = parsed.path or ""
    path = re.sub(r"/{2,}", "/", path)
    if host in KNOWN_API_HOSTS and path:
        path = normalize_known_api_path(path)
    if path not in {"", "/"} and path.endswith("/"):
        path = path.rstrip("/")
    if path == "/" and not parsed.query:
        path = ""

    return urlunparse((scheme, host, path, "", parsed.query, ""))


def normalize_known_api_path(path: str) -> str:
    parts = path.split("/")
    normalized_parts: list[str] = []
    for part in parts:
        if not part:
            normalized_parts.append(part)
            continue
        if any(marker in part for marker in ["$", "%", "{", "}", "(", ")", "[", "]"]):
            normalized_parts.append(part)
            continue
        normalized_parts.append(part.lower())
    return "/".join(normalized_parts)


def is_likely_api_url(url: str) -> bool:
    parsed = safe_urlparse(url)
    if parsed is None:
        return False
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    if host in {"learn.microsoft.com", "docs.microsoft.com", "github.com"}:
        return False
    if "*" in host:
        return False
    if host.endswith(".git") or path.endswith(".git"):
        return False

    if host in KNOWN_API_HOSTS:
        return True
    if "api-version=" in query:
        return True
    if "/api/" in path or path.endswith("/api"):
        return True
    if "/graphql" in path:
        return True
    if any(token in path for token in ["/oauth", "/token", "/v1/", "/v2/", "/v3/"]):
        return True
    if host.startswith("api.") or ".api." in host:
        return True
    return False


def is_likely_api_path(path: str) -> bool:
    candidate = path.strip()
    if not candidate:
        return False
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return False
    if any(ch.isspace() for ch in candidate):
        return False
    if any(token in candidate for token in [",omitempty", " exported to "]):
        return False
    normalized = candidate.lower().lstrip("/")
    prefixes = (
        "v1.0/",
        "beta/",
        "subscriptions/",
        "providers/",
        "tenants/",
        "users",
        "groups",
        "domains",
        "sites",
        "drives",
        "directoryobjects",
        "policies",
        "rolemanagement",
        "applications",
        "serviceprincipals",
        "devices",
        "organization",
        "auditlogs",
        "signin",
        "signins",
        "reports",
        "security",
        "identity",
        "teams",
        "chats",
        "messages",
        "calendar",
        "me",
        "communications",
        "print",
        "education",
    )
    if not normalized.startswith(prefixes):
        return False
    if "/" not in normalized and "?" not in normalized:
        return False
    return True


def normalize_api_path(path: str) -> str:
    value = path.strip().strip("\"'")
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if not value.startswith("/"):
        value = f"/{value}"
    while value and value[-1] in ").,;]>'\"":
        value = value[:-1]
    return value


def infer_hosts_from_path(path_value: str) -> list[str]:
    normalized = path_value.lower().lstrip("/")
    if normalized.startswith(ARM_PATH_PREFIXES):
        return ["https://management.azure.com"]
    if normalized.startswith(GRAPH_PATH_PREFIXES):
        return ["https://graph.microsoft.com", "https://graph.windows.net"]
    return []


def pick_hosts_for_path(path_value: str, host_candidates: set[str]) -> list[str]:
    normalized = path_value.lower().lstrip("/")

    if normalized.startswith(ARM_PATH_PREFIXES):
        preferred = [h for h in host_candidates if "management.azure.com" in h]
        if preferred:
            return sorted(set(preferred))
    if normalized.startswith(GRAPH_PATH_PREFIXES):
        preferred = [h for h in host_candidates if "graph.microsoft.com" in h or "graph.windows.net" in h]
        if preferred:
            return sorted(set(preferred))

    if host_candidates:
        return sorted(host_candidates)

    return infer_hosts_from_path(path_value)


def extract_user_agents_from_line(line: str) -> list[str]:
    values: list[str] = []
    for match in UA_HEADER_PATTERN.finditer(line):
        candidate = next((group for group in match.groups() if group), "").strip()
        if not candidate:
            continue
        if any(ch in candidate for ch in ["{", "}"]):
            continue
        if len(candidate) < 3 or len(candidate) > 250:
            continue
        values.append(candidate)
    return values


def scan_source(
    source_root: Path, include_non_api_urls: bool
) -> tuple[dict[str, dict[str, Any]], int, int, list[str]]:
    endpoint_map: dict[str, dict[str, Any]] = {}
    files_scanned = 0
    total_mentions = 0
    user_agents: set[str] = set()
    file_host_candidates: dict[str, set[str]] = {}
    file_path_fragments: dict[str, set[str]] = {}

    def record_endpoint(endpoint: str, mentions: int = 1) -> None:
        nonlocal total_mentions
        sanitized = sanitize_endpoint(endpoint)
        canonical = canonicalize_url(sanitized)
        if not canonical:
            return
        if not include_non_api_urls and not is_likely_api_url(canonical):
            return
        total_mentions += mentions
        family, host = classify_family(canonical)
        hint = resource_hint(canonical)
        current = endpoint_map.setdefault(
            canonical,
            {
                "family": family,
                "host": host,
                "resource_hint": hint,
                "mentions": 0,
            },
        )
        current["mentions"] += mentions

    for path in source_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        files_scanned += 1

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_file = str(path.relative_to(source_root)).replace("\\", "/")
        file_hosts = file_host_candidates.setdefault(rel_file, set())
        file_paths = file_path_fragments.setdefault(rel_file, set())
        for line_no, line in enumerate(text.splitlines(), start=1):
            for user_agent in extract_user_agents_from_line(line):
                user_agents.add(user_agent)

            for host_match in HOST_LITERAL_PATTERN.finditer(line):
                scheme = (host_match.group(1) or "https://").lower()
                host = host_match.group(2).lower()
                file_hosts.add(f"{scheme}{host}")

            if API_CONTEXT_PATTERN.search(line):
                for path_match in API_PATH_FRAGMENT_PATTERN.finditer(line):
                    path_candidate = normalize_api_path(path_match.group(1))
                    if is_likely_api_path(path_candidate):
                        file_paths.add(path_candidate)

            for match in URL_PATTERN.findall(line):
                endpoint = normalize_url(match)
                record_endpoint(endpoint, mentions=1)

    global_known_hosts: set[str] = set()
    for endpoint, details in endpoint_map.items():
        host = details.get("host", "")
        if host in {"graph.microsoft.com", "graph.windows.net", "management.azure.com"}:
            parsed = safe_urlparse(endpoint)
            scheme = (parsed.scheme if parsed and parsed.scheme else "https").lower()
            global_known_hosts.add(f"{scheme}://{host}")

    for rel_file, paths in file_path_fragments.items():
        if not paths:
            continue
        host_candidates = file_host_candidates.get(rel_file, set()) or global_known_hosts
        for path_value in sorted(paths):
            selected_hosts = pick_hosts_for_path(path_value, host_candidates)
            for host_base in selected_hosts:
                full_endpoint = f"{host_base.rstrip('/')}{path_value}"
                record_endpoint(full_endpoint, mentions=1)

    return endpoint_map, files_scanned, total_mentions, sorted(user_agents)


def build_profile(
    tool_name: str,
    repo_link: str,
    endpoint_map: dict[str, dict[str, Any]],
    user_agents: list[str],
    files_scanned: int,
    total_mentions: int,
    last_checked_utc: str,
    last_update_utc: str,
) -> dict[str, Any]:
    apis: dict[str, Any] = {
        "microsoft_graph": {"host": "graph.microsoft.com", "endpoints": [], "resources": []},
        "azure_ad_graph": {"host": "graph.windows.net", "endpoints": [], "resources": []},
        "azure_resource_manager": {
            "host": "management.azure.com",
            "endpoints": [],
            "resources": [],
        },
        "other_apis": [],
    }

    other_by_host: dict[str, dict[str, Any]] = {}
    family_counts: dict[str, int] = {}

    for endpoint in sorted(endpoint_map):
        data = endpoint_map[endpoint]
        family = data["family"]
        host = data["host"]
        hint = data["resource_hint"]
        family_counts[family] = family_counts.get(family, 0) + 1

        if family in {"microsoft_graph", "azure_ad_graph", "azure_resource_manager"}:
            apis[family]["endpoints"].append(endpoint)
            if hint not in apis[family]["resources"]:
                apis[family]["resources"].append(hint)
        else:
            bucket = other_by_host.setdefault(
                host or "unknown-host",
                {"host": host or "unknown-host", "endpoints": [], "resources": []},
            )
            bucket["endpoints"].append(endpoint)
            if hint not in bucket["resources"]:
                bucket["resources"].append(hint)

    apis["other_apis"] = list(other_by_host.values())

    family_summary = []
    for family, count in sorted(family_counts.items(), key=lambda item: (-item[1], item[0])):
        if family == "other":
            family_summary.append({"family": "other", "host": "multiple", "unique_endpoints": count})
        else:
            family_summary.append(
                {
                    "family": family,
                    "display_name": DISPLAY_NAME.get(family, family),
                    "host": apis[family]["host"],
                    "unique_endpoints": count,
                }
            )

    return {
        "version": "1.0",
        "tool": {
            "name": tool_name,
            "repository_url": repo_link,
        },
        "last_checked_utc": last_checked_utc,
        "last_update_utc": last_update_utc,
        "user_agents": user_agents,
        "summary": {
            "total_unique_endpoints": len(endpoint_map),
            "total_endpoint_mentions": total_mentions,
            "files_scanned": files_scanned,
            "api_families": family_summary,
        },
        "apis": apis,
    }


def scalar_to_yaml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=True)


def to_yaml(data: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(data, dict):
        if not data:
            return f"{prefix}{{}}"
        lines = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                if isinstance(value, dict) and not value:
                    lines.append(f"{prefix}{key}: {{}}")
                elif isinstance(value, list) and not value:
                    lines.append(f"{prefix}{key}: []")
                else:
                    lines.append(f"{prefix}{key}:")
                    lines.append(to_yaml(value, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {scalar_to_yaml(value)}")
        return "\n".join(lines)
    if isinstance(data, list):
        if not data:
            return f"{prefix}[]"
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(to_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}- {scalar_to_yaml(item)}")
        return "\n".join(lines)
    return f"{prefix}{scalar_to_yaml(data)}"


def slugify(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip())
    cleaned = cleaned.strip("-").lower()
    return cleaned or "unknown-tool"


def main() -> None:
    args = parse_args()
    timestamp = args.last_checked_utc or now_utc_iso()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.all_profiles:
        jobs: list[tuple[str, str, Path]] = []
        for profile_path in sorted(output_dir.glob("*.y*ml")):
            try:
                tool_name, repo_link = read_profile_source(profile_path)
            except (OSError, ValueError) as ex:
                print(f"Skipping {profile_path}: {ex}")
                continue
            jobs.append((tool_name, repo_link, profile_path))
    else:
        jobs = [
            (
                args.tool_name or infer_name_from_repo(args.repo),
                args.repo,
                output_dir / f"{slugify(args.tool_name or infer_name_from_repo(args.repo))}.yaml",
            )
        ]

    failures = 0
    for tool_name, repo_link, output_path in jobs:
        temp_root = None
        try:
            source_root, repo_link, temp_root = prepare_source(repo_link, args.no_clone)
            endpoint_map, files_scanned, total_mentions, user_agents = scan_source(
                source_root, include_non_api_urls=args.include_non_api_urls
            )
            profile = build_profile(
                tool_name=tool_name,
                repo_link=repo_link,
                endpoint_map=endpoint_map,
                user_agents=user_agents,
                files_scanned=files_scanned,
                total_mentions=total_mentions,
                last_checked_utc=timestamp,
                last_update_utc=timestamp,
            )
            output_path.write_text(to_yaml(profile) + "\n", encoding="utf-8")
            print(
                f"Profile written: {output_path} "
                f"({profile['summary']['total_unique_endpoints']} unique endpoints)"
            )
        except (OSError, ValueError, SystemExit) as ex:
            failures += 1
            print(f"Failed {tool_name} ({repo_link}): {ex}")
        finally:
            if temp_root:
                shutil.rmtree(temp_root, ignore_errors=True)

    if failures:
        raise SystemExit(f"{failures} profile(s) failed to update")


if __name__ == "__main__":
    main()
