#!/usr/bin/env python3
"""ZipFerry — audit a ZIP archive from its metadata before it is opened.

Metadata only: never extracts, never decompresses, never writes.
"""
import argparse
import json
import sys
import zipfile

VERSION = "1.0.0"
EXECUTABLE_EXTS = {".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".jar"}
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
ERROR_CODES = {"unsafe-path", "duplicate-entry", "case-collision", "high-ratio", "total-size", "too-many-entries"}


def ext_of(name):
    low = name.lower()
    for ext in (".tar.gz",):
        if low.endswith(ext):
            return ext
    dot = low.rfind(".")
    return low[dot:] if dot >= 0 else ""


def is_unsafe(name):
    if not name or "\x00" in name or "\\" in name:
        return True
    if name.startswith("/") or name.startswith("//"):
        return True
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return True
    parts = name.split("/")
    if ".." in parts:
        return True
    return False


def audit_archive(path, opts):
    """Return (stats dict, findings list) or raise ValueError for exit-2."""
    try:
        zf = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(str(exc))
    findings = []  # dicts: code, severity, entry_index, label, detail
    with zf:
        infos = zf.infolist()
    entries = 0
    files = 0
    total = 0

    def label(idx, info):
        if opts["fingerprint_only"]:
            return f"entry #{idx + 1} (crc {info.CRC & 0xFFFFFFFF:08x})"
        return info.filename

    def add(code, idx, info, detail=""):
        findings.append({
            "code": code,
            "severity": "error" if code in ERROR_CODES else "warning",
            "entry": idx + 1 if idx is not None else None,
            "label": label(idx, info) if info is not None else None,
            "detail": detail,
        })

    seen = {}
    folded = {}
    for idx, info in enumerate(infos):
        entries += 1
        name = info.filename
        is_dir = name.endswith("/")
        if is_unsafe(name):
            add("unsafe-path", idx, info)
        if name in seen:
            add("duplicate-entry", idx, info, f"first at entry #{seen[name] + 1}")
        else:
            seen[name] = idx
        key = name.casefold()
        if key in folded and folded[key] != name:
            add("case-collision", idx, info, f"collides with entry #{seen.get(folded[key], idx) + 1 if folded[key] in seen else '?'}")
        else:
            folded.setdefault(key, name)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            add("symlink", idx, info)
        if info.flag_bits & 0x1:
            add("encrypted-entry", idx, info)
        if is_dir:
            continue
        files += 1
        total += info.file_size
        if info.file_size == 0:
            add("empty-file", idx, info)
        ratio_denom = max(1, info.compress_size)
        if info.file_size > 0 and info.file_size / ratio_denom > opts["max_ratio"]:
            add("high-ratio", idx, info, f"ratio {info.file_size / ratio_denom:.1f} > {opts['max_ratio']}")
        ext = ext_of(name)
        if ext in EXECUTABLE_EXTS:
            add("executable-entry", idx, info)
        if ext in ARCHIVE_EXTS or name.lower().endswith(".tar.gz"):
            add("nested-archive", idx, info)
    if total > opts["max_total"]:
        findings.append({"code": "total-size", "severity": "error", "entry": None,
                         "label": None, "detail": f"declared {total} > {opts['max_total']}"})
    if entries > opts["max_entries"]:
        findings.append({"code": "too-many-entries", "severity": "error", "entry": None,
                         "label": None, "detail": f"{entries} > {opts['max_entries']}"})
    stats = {"archive": path, "entries": entries, "files": files, "declared_bytes": total}
    return stats, findings


def main(argv=None):
    ap = argparse.ArgumentParser(prog="zipferry", description="Audit ZIP archives from metadata only — never extracts or decompresses.")
    ap.add_argument("--version", action="version", version=f"zipferry {VERSION}")
    sub = ap.add_subparsers(dest="command")
    a = sub.add_parser("audit")
    a.add_argument("archives", nargs="+")
    a.add_argument("--json", action="store_true")
    a.add_argument("--max-examples", type=int, default=10)
    a.add_argument("--fingerprint-only", action="store_true")
    a.add_argument("--max-ratio", type=float, default=100)
    a.add_argument("--max-total", type=int, default=1073741824)
    a.add_argument("--max-entries", type=int, default=10000)
    args = ap.parse_args(argv)
    if args.command != "audit":
        ap.print_usage(sys.stderr)
        return 2
    if args.max_examples < 0 or args.max_ratio <= 0 or args.max_total < 0 or args.max_entries < 0:
        print("zipferry: invalid limits", file=sys.stderr)
        return 2
    opts = {"fingerprint_only": args.fingerprint_only, "max_ratio": args.max_ratio,
            "max_total": args.max_total, "max_entries": args.max_entries}
    all_stats = []
    all_findings = []  # (archive_label, finding)
    for path in args.archives:
        try:
            stats, findings = audit_archive(path, opts)
        except ValueError as exc:
            print(f"zipferry: cannot audit {path}: {exc}", file=sys.stderr)
            return 2
        all_stats.append(stats)
        for f in findings:
            all_findings.append((path, f))
    errors = sum(1 for _, f in all_findings if f["severity"] == "error")
    warnings = sum(1 for _, f in all_findings if f["severity"] == "warning")
    totals = {"archives": len(all_stats),
              "entries": sum(s["entries"] for s in all_stats),
              "files": sum(s["files"] for s in all_stats),
              "declared_bytes": sum(s["declared_bytes"] for s in all_stats),
              "errors": errors, "warnings": warnings}
    if args.json:
        # cap per code
        shown, suppressed = [], 0
        per = {}
        for path, f in sorted(all_findings, key=lambda x: (x[1]["code"], x[1]["entry"] or 0)):
            c = per.get(f["code"], 0)
            if c < args.max_examples:
                shown.append({"archive": path, **f})
                per[f["code"]] = c + 1
            else:
                suppressed += 1
        print(json.dumps({"archives": all_stats, "findings": shown,
                          "suppressed": suppressed, "summary": totals},
                         indent=1, sort_keys=True))
    else:
        for s in all_stats:
            print(f"archive: {s['archive']} ({s['entries']} entries, {s['files']} files, {s['declared_bytes']} bytes declared)")
        per = {}
        suppressed_by = {}
        for path, f in sorted(all_findings, key=lambda x: (x[1]["code"], x[1]["entry"] or 0)):
            c = per.get(f["code"], 0)
            if c < args.max_examples:
                loc = f" {f['label']}" if f["label"] else ""
                det = f" ({f['detail']})" if f["detail"] else ""
                print(f"{f['severity']}: {f['code']}:{loc}{det} [{path}]")
                per[f["code"]] = c + 1
            else:
                suppressed_by[f["code"]] = suppressed_by.get(f["code"], 0) + 1
        for code in sorted(suppressed_by):
            print(f"note: {suppressed_by[code]} more {code} finding(s) suppressed by --max-examples")
        print(f"zipferry: {totals['archives']} archives, {totals['entries']} entries, {totals['files']} files, {totals['declared_bytes']} bytes declared, {errors} errors, {warnings} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
