"""Command line interface. Exit 0: no HIGH findings, 1: HIGH, 2: scan error."""
import argparse
import json
from pathlib import Path
import sys
from .config import load_config
from .engine import file_allowed, scan_stdin, scan_text

IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}


def scan_path(path, config):
    if not path.exists() or path.is_symlink():
        raise ValueError("Scan target is missing or is a symbolic link")
    root = path if path.is_dir() else path.parent
    files = []
    skipped = 0
    def walk(directory):
        nonlocal skipped
        for child in sorted(directory.iterdir()):
            relative = child.relative_to(root).as_posix()
            if child.is_symlink() or file_allowed(relative, config):
                skipped += 1
            elif child.is_dir():
                if child.name not in IGNORED_DIRS:
                    walk(child)
                else:
                    skipped += 1
            elif child.is_file():
                files.append(child)
    if path.is_dir():
        walk(path)
    else:
        files.append(path)
    findings = []
    scanned = 0
    for file in files:
        name = file.relative_to(root).as_posix()
        if file_allowed(name, config) or file.name == ".secretsweeprc.json":
            skipped += 1
            continue
        data = file.read_bytes()
        if b"\x00" in data:
            skipped += 1
            continue
        findings.extend(scan_text(data.decode("utf-8", errors="replace"), name, config))
        scanned += 1
    return findings, scanned, skipped


def main(argv=None):
    parser = argparse.ArgumentParser(prog="secretsweep")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a file, directory, or stdin (-)")
    scan.add_argument("path")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--config", type=Path)
    scan.add_argument("--entropy-threshold", type=float)
    args = parser.parse_args(argv)
    try:
        target = Path(args.path)
        config_path = args.config
        if config_path is None:
            base = Path.cwd() if args.path == "-" else (target if target.is_dir() else target.parent)
            candidate = base / ".secretsweeprc.json"
            if candidate.exists():
                config_path = candidate
        config = load_config(config_path)
        if args.entropy_threshold is not None:
            if not 0 < args.entropy_threshold <= 8:
                raise ValueError("Entropy threshold must be greater than 0 and at most 8")
            config.entropy_threshold = args.entropy_threshold
        if args.path == "-":
            findings = scan_stdin(sys.stdin.read(), config)
            scanned, skipped = 1, 0
        else:
            findings, scanned, skipped = scan_path(target, config)
        high = sum(f.severity == "HIGH" for f in findings)
        if args.format == "json":
            print(json.dumps({"schema_version": 1, "findings": [f.to_dict() for f in findings],
                              "summary": {"findings": len(findings), "high": high, "scanned": scanned, "skipped": skipped}}, ensure_ascii=True))
        else:
            for f in findings:
                # JSON escaping prevents terminal control characters in filenames or custom matches.
                print(f"{json.dumps(f.file)}:{f.line}: {f.severity} {f.pattern} {json.dumps(f.snippet)}")
            print(f"{len(findings)} findings ({high} HIGH); {scanned} scanned, {skipped} skipped")
        return 1 if high else 0
    except (OSError, ValueError, RecursionError):
        print("SecretSweep: scan failed; check target, configuration, permissions, or diff syntax", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
