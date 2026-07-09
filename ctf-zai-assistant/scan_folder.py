import argparse
import html
import json
import sys
from pathlib import Path

from ctf_assistant import CTFAssistant
from file_analyzer import analyze_uploaded_files, format_analysis_for_prompt, group_flag_candidates
from flag_extractor import dedupe_candidates, rank_final_flag_candidates, select_best_final_flag
from ghidra_analyzer import analyze_with_ghidra
from symbolic_analyzer import analyze_with_angr
from xor_analyzer import analyze_xor


DEFAULT_JSON_REPORT = Path("reports/result.json")
DEFAULT_HTML_REPORT = Path("reports/result.html")
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
DEFAULT_IGNORES = {
    "reports",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".idea",
    ".vscode",
}
# File types that suggest a binary needs manual reversing rather than the
# flag simply being missing. Used to pick between exit codes 1 and 3.
BINARY_TYPE_MARKERS = ("ELF", "PE executable", "Mach-O", "Android DEX")

# Exit codes for --only-flag mode.
EXIT_FLAG_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_SCANNER_ERROR = 2
EXIT_NEEDS_REVERSING = 3

DEFAULT_TARGET_FOLDER = "samples"
SAMPLES_README_TEXT = """Put your CTF challenge files here.

Examples:
- reversing binary: chall, legacyopt, main.exe
- output file: output.txt, encrypted.dat
- forensic file: image.png, dump.bin, capture.pcap

Then run:

python scan_folder.py .\\samples --only-flag
python scan_folder.py .\\samples --only-flag --xor
python scan_folder.py .\\samples --only-flag --all-advanced
"""


def parse_ignore_list(value):
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def should_ignore(path, root, ignored_names):
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    return any(part in ignored_names for part in relative.parts)


def collect_files(folder, max_size, ignored_names):
    """Recursively collect readable files under a folder."""
    uploaded_files = []
    skipped_files = []
    root = Path(folder)

    if root.name in ignored_names:
        skipped_files.append({
            "path": str(root),
            "reason": "root folder is ignored by folder/file ignore rules",
        })
        return uploaded_files, skipped_files

    for path in sorted(root.rglob("*")):
        if should_ignore(path, root, ignored_names):
            if path.is_file():
                skipped_files.append({"path": str(path), "reason": "ignored by folder/file ignore rules"})
            continue
        if not path.is_file():
            continue

        try:
            size = path.stat().st_size
        except OSError as error:
            skipped_files.append({"path": str(path), "reason": str(error)})
            continue

        if size > max_size:
            skipped_files.append({
                "path": str(path),
                "reason": f"skipped because size {size} > max-size {max_size}",
            })
            continue

        try:
            uploaded_files.append({
                "filename": str(path),
                "content": path.read_bytes(),
            })
        except OSError as error:
            skipped_files.append({"path": str(path), "reason": str(error)})

    return uploaded_files, skipped_files


def sort_candidates(candidates):
    return sorted(
        candidates,
        key=lambda item: (
            CONFIDENCE_ORDER.get(item["confidence"], 9),
            item["value"].lower(),
        ),
    )


def print_candidate_group(title, candidates, max_items=25):
    print(f"\n[{title}]")
    if not candidates:
        print("  none")
        return

    for index, candidate in enumerate(candidates[:max_items], start=1):
        print(f"{index}. {candidate['value']}")
        print(f"   source: {candidate.get('source', 'unknown')}")
        print(f"   transform: {candidate.get('transform', 'unknown')}")
        print(f"   reason: {candidate.get('reason', '')}")
    if len(candidates) > max_items:
        print(f"   ... {len(candidates) - max_items} more hidden in the report")


def print_no_flag_hints(analysis):
    print("\n[-] No direct flag candidate found.")
    print("\nPossible reason:")
    print("- The flag is encrypted.")
    print("- The flag is generated at runtime.")
    print("- The flag is hidden behind input validation.")
    print("- The binary may need reversing.")

    suspicious = []
    for report in analysis.get("file_reports", []):
        for item in report.get("suspicious_strings", [])[:20]:
            suspicious.append(f"{report['filename']}: {item}")

    print("\nSuggested next steps:")
    if suspicious:
        print("- Check these suspicious strings first:")
        for item in suspicious[:10]:
            print(f"  - {item}")
    print("- Open likely binaries in Ghidra or IDA.")
    print("- Look for main/check/verify/decrypt/xor/strcmp/memcmp functions.")
    print("- Compare output files with binary validation or decode logic.")


def print_advanced_results(advanced):
    xor_candidates = advanced.get("xor", {}).get("candidates", [])
    if xor_candidates:
        print_candidate_group("XOR CANDIDATES", xor_candidates)

    ghidra = advanced.get("ghidra")
    if ghidra:
        print("\n[GHIDRA]")
        if ghidra.get("error"):
            print(f"  {ghidra['error']}")
        for item in ghidra.get("files", [])[:10]:
            analysis = item.get("analysis", {})
            suspicious = analysis.get("suspicious_functions", [])
            print(f"  {item['filename']}: suspicious functions={len(suspicious)}")

    angr = advanced.get("angr")
    if angr:
        print("\n[ANGR]")
        if angr.get("error"):
            print(f"  {angr['error']}")
        for item in angr.get("files", [])[:10]:
            print(
                f"  {item['filename']}: success markers={item.get('success_markers', [])}, "
                f"failure markers={item.get('failure_markers', [])}"
            )


def build_ai_prompt(analysis):
    evidence = format_analysis_for_prompt(analysis)
    return f"""
This is an authorized CTF folder scan. Use the local evidence to rank possible
flags or suggest the next reversing steps.

Do not ask the user to run cat, xxd, strings, file, readelf, or objdump. The
scanner already collected equivalent evidence below.

Local evidence:
{evidence}

Answer in Korean. Put the most likely flag candidate first if one exists.
If no candidate is reliable, explain why and give short evidence-based next steps.
""".strip()


def run_ai_analysis(analysis, no_ai):
    if no_ai:
        return ""

    assistant = CTFAssistant()
    if not assistant.is_ready():
        return ""

    answer = assistant.ask(build_ai_prompt(analysis))
    return answer or ""


def run_advanced(uploaded_files, args):
    advanced = {}
    if args.all_advanced:
        args.xor = True
        args.ghidra = True
        args.angr = True
        args.z3_helper = True

    if args.xor:
        advanced["xor"] = analyze_xor(uploaded_files)
    if args.ghidra:
        advanced["ghidra"] = analyze_with_ghidra(uploaded_files)
    if args.angr:
        advanced["angr"] = analyze_with_angr(uploaded_files)
    if args.z3_helper:
        try:
            import z3  # noqa: F401
            advanced["z3_helper"] = {"available": True, "note": "z3-solver is installed."}
        except ImportError:
            advanced["z3_helper"] = {
                "available": False,
                "note": "z3-solver is not installed. Install requirements-advanced.txt.",
            }

    return advanced


def collect_advanced_candidates(advanced):
    candidates = []
    if advanced.get("xor"):
        candidates.extend(advanced["xor"].get("candidates", []))
    if advanced.get("angr"):
        candidates.extend(advanced["angr"].get("candidates", []))
    return dedupe_candidates(candidates)


def write_json_report(path, report):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return True, ""
    except OSError as error:
        return False, str(error)


def render_candidate_html(title, candidates):
    rows = []
    for candidate in candidates:
        rows.append(
            "<tr>"
            f"<td>{html.escape(candidate['value'])}</td>"
            f"<td>{html.escape(candidate.get('source', ''))}</td>"
            f"<td>{html.escape(candidate.get('transform', ''))}</td>"
            f"<td>{html.escape(candidate.get('reason', ''))}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan=\"4\">none</td></tr>"
    return f"""
<h2>{html.escape(title)}</h2>
<table>
  <tr><th>Value</th><th>Source</th><th>Transform</th><th>Reason</th></tr>
  {body}
</table>
"""


def render_html_report(report):
    grouped = group_flag_candidates(report["analysis"]["flag_candidates"])
    files = report["analysis"].get("file_reports", [])
    file_sections = []

    for item in files:
        file_sections.append(f"""
<section>
  <h3>{html.escape(item['filename'])}</h3>
  <p><strong>Size:</strong> {item['size']} bytes</p>
  <p><strong>SHA-256:</strong> {html.escape(item['sha256'])}</p>
  <p><strong>Type:</strong> {html.escape(item['file_type'])}</p>
  <h4>Text Preview</h4>
  <pre>{html.escape(item.get('text_preview') or '')}</pre>
  <h4>Hex Preview</h4>
  <pre>{html.escape(item.get('hex_preview') or '')}</pre>
  <h4>Suspicious Strings</h4>
  <pre>{html.escape(chr(10).join(item.get('suspicious_strings', [])))}</pre>
  <h4>Extracted Strings</h4>
  <pre>{html.escape(chr(10).join(item.get('ascii_strings', [])[:100]))}</pre>
</section>
""")

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CTF Folder Flag Extractor Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #101114; color: #f1f3f5; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
    th, td {{ border: 1px solid #394150; padding: 8px; vertical-align: top; }}
    th {{ background: #1d2430; }}
    section {{ border: 1px solid #394150; padding: 12px; margin: 14px 0; border-radius: 6px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #0b0d10; padding: 10px; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>CTF Folder Flag Extractor Report</h1>
  <p><strong>Folder:</strong> {html.escape(report['folder'])}</p>
  <p><strong>Files scanned:</strong> {report['files_scanned']}</p>
  <p><strong>Candidates found:</strong> {len(report['analysis']['flag_candidates'])}</p>
  {render_candidate_html("High Confidence", grouped["high"])}
  {render_candidate_html("Medium Confidence", grouped["medium"])}
  {render_candidate_html("Low / Suspicious", grouped["low"])}
  <h2>Advanced Results</h2>
  <pre>{html.escape(json.dumps(report.get('advanced', {}), ensure_ascii=False, indent=2)[:12000])}</pre>
  <h2>AI Analysis</h2>
  <pre>{html.escape(report.get('ai_analysis') or 'AI analysis disabled or unavailable.')}</pre>
  <h2>Per-file Evidence</h2>
  {''.join(file_sections)}
</body>
</html>"""


def write_html_report(path, report):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html_report(report), encoding="utf-8")
        return True, ""
    except OSError as error:
        return False, str(error)


def has_binary_evidence(analysis):
    """True when scanned files include binaries that likely need reversing."""
    for report in analysis.get("file_reports", []):
        file_type = report.get("file_type", "")
        if any(marker in file_type for marker in BINARY_TYPE_MARKERS):
            return True
    return False


def not_found_exit_code(analysis):
    return EXIT_NEEDS_REVERSING if has_binary_evidence(analysis) else EXIT_NOT_FOUND


def display_path(path):
    """Render a path Windows-PowerShell style for user-facing messages."""
    path = Path(path)
    if path.is_absolute():
        return str(path)
    return f".\\{path}"


def init_samples():
    """Create samples/, reports/, and samples/README.txt for a fresh start."""
    samples_dir = Path(DEFAULT_TARGET_FOLDER)
    reports_dir = Path("reports")
    readme_path = samples_dir / "README.txt"

    samples_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    readme_path.write_text(SAMPLES_README_TEXT, encoding="utf-8")

    print(f"[+] Created folder: {display_path(samples_dir)}")
    print(f"[+] Created folder: {display_path(reports_dir)}")
    print(f"[+] Wrote: {display_path(readme_path)}")
    print(f"\nPut your CTF challenge files into {display_path(samples_dir)}, then run:")
    print("  python scan_folder.py --only-flag")
    print("  python scan_folder.py --only-flag --xor")
    print("  python scan_folder.py --only-flag --all-advanced")


def handle_missing_folder(folder, only_flag):
    """Auto-create a missing target folder with friendly guidance, then exit.

    Exits 1 either way: there is nothing to scan yet, so this is the same
    "no reliable flag" outcome as a real scan that found nothing.
    """
    if only_flag:
        folder.mkdir(parents=True, exist_ok=True)
        print("NOT_FOUND")
        raise SystemExit(EXIT_NOT_FOUND)

    display = display_path(folder)
    print("[-] Target folder does not exist.")
    folder.mkdir(parents=True, exist_ok=True)
    print(f"[+] Created folder: {display}")
    print(f"[!] Put your CTF challenge files into {display} and run again.")
    print("\nExample:")
    print(f"  python scan_folder.py {display} --only-flag")
    print(f"  python scan_folder.py {display} --only-flag --xor")
    print(f"  python scan_folder.py {display} --only-flag --all-advanced")
    raise SystemExit(EXIT_NOT_FOUND)


def handle_no_files(folder, only_flag):
    """Print guidance and exit when the target folder has nothing to scan."""
    if only_flag:
        print("NOT_FOUND")
        raise SystemExit(EXIT_NOT_FOUND)

    display = display_path(folder)
    print(f"[-] No files found in {display}")
    print(
        "[!] Put challenge files such as chall, output.txt, flag.txt, image.png, "
        "dump.bin into the folder and run again."
    )
    raise SystemExit(EXIT_NOT_FOUND)


def run_only_flag_mode(candidates, analysis, all_flags):
    """Print exactly the answer-only output for --only-flag and exit.

    Never prints analysis, evidence, markdown, or confidence text - only the
    flag value(s), or NOT_FOUND when nothing is reliable enough.
    """
    if all_flags:
        reliable = rank_final_flag_candidates(candidates)
        if not reliable:
            print("NOT_FOUND")
            raise SystemExit(not_found_exit_code(analysis))
        for candidate in reliable:
            print(candidate["value"])
        raise SystemExit(EXIT_FLAG_FOUND)

    best = select_best_final_flag(candidates)
    if best is None:
        print("NOT_FOUND")
        raise SystemExit(not_found_exit_code(analysis))

    print(best["value"])
    raise SystemExit(EXIT_FLAG_FOUND)


def main():
    parser = argparse.ArgumentParser(description="Automatic folder-based CTF flag extractor.")
    parser.add_argument(
        "folder",
        nargs="?",
        default=DEFAULT_TARGET_FOLDER,
        help=f"Folder containing CTF challenge files. Defaults to .\\{DEFAULT_TARGET_FOLDER}.",
    )
    parser.add_argument(
        "--init-samples",
        action="store_true",
        help="Create samples/ and reports/ folders plus samples/README.txt, then exit.",
    )
    parser.add_argument("--json", default=str(DEFAULT_JSON_REPORT), help="Path to JSON report.")
    parser.add_argument("--html", default=str(DEFAULT_HTML_REPORT), help="Path to HTML report.")
    parser.add_argument("--max-size", type=int, default=50_000_000, help="Skip files larger than this many bytes.")
    parser.add_argument("--no-ai", action="store_true", help="Disable optional Z.AI analysis.")
    parser.add_argument("--include-reports", action="store_true", help="Do not ignore the reports folder.")
    parser.add_argument("--ignore", default="", help="Comma-separated folder/file names to ignore in addition to defaults.")
    parser.add_argument("--xor", action="store_true", help="Run optional XOR brute-force analysis.")
    parser.add_argument("--ghidra", action="store_true", help="Run optional Ghidra headless analysis.")
    parser.add_argument("--angr", action="store_true", help="Run optional angr precheck/automation.")
    parser.add_argument("--z3-helper", action="store_true", help="Report z3 helper availability.")
    parser.add_argument("--all-advanced", action="store_true", help="Enable XOR, Ghidra, angr, and z3 helper checks.")
    parser.add_argument(
        "--only-flag",
        action="store_true",
        help="Print only the final flag (or NOT_FOUND) and suppress all other terminal output.",
    )
    parser.add_argument(
        "--all-flags",
        action="store_true",
        help="With --only-flag, print every reliable flag candidate (best first) instead of only the best one.",
    )
    args = parser.parse_args()

    if args.init_samples:
        init_samples()
        raise SystemExit(EXIT_FLAG_FOUND)

    only_flag = args.only_flag
    folder = Path(args.folder)

    if folder.exists() and not folder.is_dir():
        message = f"[-] {display_path(folder)} exists but is not a directory."
        print(message, file=sys.stderr if only_flag else sys.stdout)
        raise SystemExit(EXIT_SCANNER_ERROR)

    if not folder.exists():
        handle_missing_folder(folder, only_flag)
        return  # unreachable: handle_missing_folder always raises SystemExit

    if not only_flag:
        print("=== CTF Folder Flag Extractor ===\n")
        print(f"[+] Folder: {folder}")

    ignored_names = set(DEFAULT_IGNORES)
    if args.include_reports:
        ignored_names.discard("reports")
    ignored_names.update(parse_ignore_list(args.ignore))

    try:
        uploaded_files, skipped_files = collect_files(folder, args.max_size, ignored_names)
    except Exception as error:
        print(f"[!] Scanner error: {error}", file=sys.stderr if only_flag else sys.stdout)
        raise SystemExit(EXIT_SCANNER_ERROR)

    if not uploaded_files:
        handle_no_files(folder, only_flag)
        return  # unreachable: handle_no_files always raises SystemExit

    try:
        analysis = analyze_uploaded_files(uploaded_files)
        advanced = run_advanced(uploaded_files, args)
        advanced_candidates = collect_advanced_candidates(advanced)
        candidates = sort_candidates(dedupe_candidates(analysis["flag_candidates"] + advanced_candidates))
        grouped = group_flag_candidates(candidates)
    except Exception as error:
        print(f"[!] Scanner error: {error}", file=sys.stderr if only_flag else sys.stdout)
        raise SystemExit(EXIT_SCANNER_ERROR)

    if only_flag:
        run_only_flag_mode(candidates, analysis, args.all_flags)
        return  # unreachable: run_only_flag_mode always raises SystemExit

    print(f"[+] Files scanned: {len(uploaded_files)}")
    print(f"[+] Files skipped: {len(skipped_files)}")
    print(f"[+] Candidates found: {len(candidates)}")

    if candidates:
        print_candidate_group("HIGH", grouped["high"])
        print_candidate_group("MEDIUM", grouped["medium"])
        print_candidate_group("LOW / SUSPICIOUS", grouped["low"])
    else:
        print_no_flag_hints(analysis)

    if advanced:
        print_advanced_results(advanced)

    ai_analysis = run_ai_analysis(analysis, args.no_ai)
    if ai_analysis:
        print("\n[AI ANALYSIS]")
        print(ai_analysis)

    report = {
        "folder": str(folder),
        "files_scanned": len(uploaded_files),
        "files_skipped": skipped_files,
        "candidates": candidates,
        "analysis": analysis,
        "advanced": advanced,
        "ai_analysis": ai_analysis,
    }

    json_ok, json_error = write_json_report(Path(args.json), report)
    html_ok, html_error = write_html_report(Path(args.html), report)
    if json_ok:
        print(f"\n[+] JSON report saved: {args.json}")
    else:
        print(f"\n[!] JSON report could not be saved: {json_error}")
    if html_ok:
        print(f"[+] HTML report saved: {args.html}")
    else:
        print(f"[!] HTML report could not be saved: {html_error}")

    print("\n=== Scan Summary ===")
    print(f"Files scanned: {len(uploaded_files)}")
    print(f"Files skipped: {len(skipped_files)}")
    print(f"High-confidence flags: {len(grouped['high'])}")
    print(f"Medium-confidence candidates: {len(grouped['medium'])}")
    print(f"Low-confidence suspicious strings: {len(grouped['low'])}")
    print(f"JSON report: {args.json if json_ok else 'not saved'}")
    print(f"HTML report: {args.html if html_ok else 'not saved'}")
    print(f"AI analysis: {'enabled' if ai_analysis else 'disabled or unavailable'}")


if __name__ == "__main__":
    main()
