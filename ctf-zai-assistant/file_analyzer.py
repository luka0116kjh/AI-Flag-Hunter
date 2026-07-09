import base64
import binascii
import codecs
import hashlib
import os
import re
import subprocess
import tempfile
import urllib.parse
from collections import Counter

from flag_extractor import dedupe_candidates, find_flag_candidates, group_flag_candidates


MAX_TEXT_PREVIEW = 20000
MAX_STRINGS = 250
MAX_STRINGS_DISPLAY = 100
MAX_HEX_PREVIEW_BYTES = 512
MAX_TOOL_OUTPUT = 12000
SUSPICIOUS_KEYWORDS = [
    "flag",
    "ctf",
    "key",
    "secret",
    "answer",
    "password",
    "token",
    "encrypt",
    "decrypt",
    "encode",
    "decode",
    "xor",
    "check",
    "verify",
    "strcmp",
    "memcmp",
]
ELF_MACHINE_TYPES = {
    0x03: "Intel 80386",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}
ELF_TYPES = {
    1: "REL relocatable",
    2: "EXEC executable",
    3: "DYN shared object/PIE",
    4: "CORE core file",
}


def truncate_text(text, max_output=MAX_TOOL_OUTPUT):
    """Limit long output and add a clear truncation note."""
    if text is None:
        return ""
    if len(text) <= max_output:
        return text
    return text[:max_output] + f"\n...[truncated to {max_output} characters]"


def limit_lines(items, max_lines=MAX_STRINGS_DISPLAY):
    """Limit a list and add a marker when there is more data."""
    if len(items) <= max_lines:
        return items
    return items[:max_lines] + [f"...[truncated, {len(items) - max_lines} more line(s)]"]


def run_command(cmd, timeout=5, max_output=MAX_TOOL_OUTPUT):
    """Run a local inspection command safely with timeout and output limits."""
    result = {
        "command": cmd,
        "success": False,
        "stdout": "",
        "stderr": "",
        "error": "",
    }

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            check=False,
        )
        result["success"] = completed.returncode == 0
        result["stdout"] = truncate_text(completed.stdout, max_output)
        result["stderr"] = truncate_text(completed.stderr, max_output)
        if completed.returncode != 0:
            result["error"] = f"Command exited with code {completed.returncode}."
    except FileNotFoundError:
        result["error"] = "Tool not found on this system."
    except subprocess.TimeoutExpired:
        result["error"] = f"Command timed out after {timeout} seconds."
    except Exception as error:
        result["error"] = str(error)

    return result


def sha256_bytes(data):
    """Return the SHA-256 hash of uploaded bytes."""
    return hashlib.sha256(data).hexdigest()


def detect_file_type(data):
    """Detect common reversing challenge file types from magic bytes."""
    if data.startswith(b"\x7fELF"):
        return "ELF executable/shared object"
    if data.startswith(b"MZ"):
        return "Windows PE executable/DLL"
    if data.startswith(b"\xca\xfe\xba\xbe") or data.startswith(b"\xfe\xed\xfa"):
        return "Mach-O or Java class style magic"
    if data.startswith(b"dex\n"):
        return "Android DEX"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP/JAR/APK/archive"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if data.startswith(b"%PDF"):
        return "PDF document"
    return "Unknown or raw data"


def hex_preview(data, max_bytes=MAX_HEX_PREVIEW_BYTES):
    """Return an xxd-like hex preview."""
    lines = []
    preview = data[:max_bytes]

    for offset in range(0, len(preview), 16):
        chunk = preview[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}: {hex_part:<47}  {ascii_part}")

    if len(data) > max_bytes:
        lines.append(f"...[truncated, showing first {max_bytes} bytes of {len(data)}]")

    return "\n".join(lines)


def decode_text_variants(data):
    """Try common text decodings used in CTF evidence files."""
    variants = {}
    for encoding in ("utf-8", "latin-1", "utf-16le"):
        try:
            decoded = data.decode(encoding)
            variants[encoding] = truncate_text(decoded, MAX_TEXT_PREVIEW)
        except UnicodeDecodeError:
            variants[encoding] = ""
    return variants


def looks_like_hex_string(text):
    compact = re.sub(r"\s+", "", text)
    return len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact)


def looks_like_base64(text):
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 8 or len(compact) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) is not None


def printable_ratio(data):
    if not data:
        return 1.0
    printable = sum(1 for byte in data if byte in b"\r\n\t" or 32 <= byte <= 126)
    return printable / len(data)


def detect_possible_encodings(data, decoded_variants):
    """Detect and preview common CTF encodings without assuming they are final."""
    candidates = []
    text = decoded_variants.get("utf-8") or decoded_variants.get("latin-1") or ""
    stripped = text.strip()

    if looks_like_hex_string(stripped):
        compact = re.sub(r"\s+", "", stripped)
        try:
            decoded = binascii.unhexlify(compact)
            decoded_text = decoded.decode("utf-8", errors="replace")
            candidates.append({
                "type": "hex",
                "confidence": "medium",
                "reason": "Content is an even-length hex string.",
                "preview": truncate_text(decoded_text, 4000),
                "raw": decoded,
            })
        except (binascii.Error, ValueError):
            pass

    if looks_like_base64(stripped):
        compact = re.sub(r"\s+", "", stripped)
        try:
            decoded = base64.b64decode(compact, validate=True)
            decoded_text = decoded.decode("utf-8", errors="replace")
            if printable_ratio(decoded) > 0.70 or find_flag_candidates(decoded_text):
                candidates.append({
                    "type": "base64",
                    "confidence": "medium",
                    "reason": "Content matches base64 character set and decodes to mostly printable data.",
                    "preview": truncate_text(decoded_text, 4000),
                    "raw": decoded,
                })
        except (binascii.Error, ValueError):
            pass

    if "%" in stripped:
        unquoted = urllib.parse.unquote(stripped)
        if unquoted != stripped:
            candidates.append({
                "type": "url_encoding",
                "confidence": "low",
                "reason": "Content contains percent-encoded sequences.",
                "preview": truncate_text(unquoted, 4000),
                "raw": unquoted.encode("utf-8", errors="replace"),
            })

    if re.search(r"[A-Za-z]", stripped):
        rot13 = codecs.decode(stripped, "rot_13")
        if rot13 != stripped and any(keyword in rot13.lower() for keyword in SUSPICIOUS_KEYWORDS):
            candidates.append({
                "type": "rot13",
                "confidence": "low",
                "reason": "ROT13 result contains CTF/suspicious keywords.",
                "preview": truncate_text(rot13, 4000),
                "raw": rot13.encode("utf-8", errors="replace"),
            })

    if printable_ratio(data) < 0.35 and len(set(data)) > 16:
        candidates.append({
            "type": "xor_or_encrypted_binary",
            "confidence": "low",
            "reason": "Low printable ratio with varied bytes; may be XOR/encrypted/compressed data.",
            "preview": byte_histogram(data),
            "raw": b"",
        })

    return candidates


def suspicious_strings_from(strings):
    """Collect strings containing CTF-relevant keywords."""
    results = []
    for item in strings:
        lower = item.lower()
        if any(keyword in lower for keyword in SUSPICIOUS_KEYWORDS):
            results.append(item)
    return limit_lines(list(dict.fromkeys(results)), MAX_STRINGS_DISPLAY)


def parse_elf_header(data):
    """Parse basic ELF metadata directly from bytes."""
    if not data.startswith(b"\x7fELF") or len(data) < 0x40:
        return {}

    elf_class = data[4]
    endian_id = data[5]
    is_64 = elf_class == 2
    endian = "little" if endian_id == 1 else "big" if endian_id == 2 else "unknown"
    byteorder = "little" if endian == "little" else "big"

    def read_int(offset, size):
        return int.from_bytes(data[offset:offset + size], byteorder=byteorder)

    if elf_class not in (1, 2) or endian == "unknown":
        return {
            "architecture": "unknown",
            "bits": "unknown",
            "endianness": endian,
        }

    elf_type = read_int(0x10, 2)
    machine = read_int(0x12, 2)
    entry = read_int(0x18, 8 if is_64 else 4)

    return {
        "architecture": ELF_MACHINE_TYPES.get(machine, f"machine 0x{machine:x}"),
        "bits": "64-bit" if is_64 else "32-bit",
        "endianness": endian,
        "elf_type": ELF_TYPES.get(elf_type, f"type {elf_type}"),
        "entry_point": f"0x{entry:x}",
    }


def parse_section_names(readelf_sections):
    sections = []
    for line in readelf_sections.splitlines():
        match = re.search(r"\[\s*\d+\]\s+([.\w$-]+)\s+", line)
        if match:
            sections.append(match.group(1))
    return sections[:100]


def parse_symbol_names(symbol_output):
    symbols = []
    imports = []
    functions = []
    for line in symbol_output.splitlines():
        if not line.strip() or "Num:" in line:
            continue
        parts = line.split()
        if len(parts) < 8:
            continue
        symbol_type = parts[3]
        section = parts[6]
        name = parts[7].split("@")[0]
        if not name or name == "UND":
            continue
        symbols.append(name)
        if section == "UND":
            imports.append(name)
        if symbol_type == "FUNC":
            functions.append(name)
    return {
        "symbols": limit_lines(list(dict.fromkeys(symbols)), 200),
        "imports": limit_lines(list(dict.fromkeys(imports)), 200),
        "functions": limit_lines(list(dict.fromkeys(functions)), 200),
    }


def analyze_elf_with_tools(path, data):
    """Collect ELF metadata using Python parsing plus optional local tools."""
    tool_outputs = {}
    elf_info = parse_elf_header(data)

    commands = {
        "file": ["file", path],
        "readelf_header": ["readelf", "-h", path],
        "readelf_sections": ["readelf", "-S", path],
        "readelf_symbols": ["readelf", "-Ws", path],
        "objdump_symbols": ["objdump", "-t", path],
    }

    for name, cmd in commands.items():
        output = run_command(cmd, timeout=5, max_output=MAX_TOOL_OUTPUT)
        tool_outputs[name] = output

    section_text = tool_outputs["readelf_sections"]["stdout"]
    symbol_text = tool_outputs["readelf_symbols"]["stdout"]
    symbol_data = parse_symbol_names(symbol_text)

    elf_info.update({
        "sections": parse_section_names(section_text),
        "symbols": symbol_data["symbols"],
        "imports": symbol_data["imports"],
        "functions": symbol_data["functions"],
        "stripped": "unknown",
        "security": {},
    })

    all_symbol_names = "\n".join(symbol_data["symbols"])
    if symbol_data["symbols"]:
        elf_info["stripped"] = "likely not stripped"
    elif ".symtab" not in section_text:
        elf_info["stripped"] = "likely stripped"

    sections = set(elf_info["sections"])
    elf_info["security"] = {
        "nx_hint": "GNU_STACK executable" if "GNU_STACK" in section_text and "RWE" in section_text else "NX likely enabled or unknown",
        "pie_hint": "PIE/shared object" if "DYN" in elf_info.get("elf_type", "") else "non-PIE executable or unknown",
        "canary_hint": "__stack_chk_fail present" if "__stack_chk_fail" in all_symbol_names else "no __stack_chk_fail symbol observed",
        "relro_hint": "RELRO sections present" if ".got" in sections or ".got.plt" in sections else "RELRO unknown",
    }

    return elf_info, tool_outputs


def extract_ascii_strings(data, min_length=4):
    """Extract printable ASCII strings like the Unix strings command."""
    strings = []
    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode("ascii", errors="replace"))
            current = bytearray()

    if len(current) >= min_length:
        strings.append(current.decode("ascii", errors="replace"))

    return strings


def extract_utf16le_strings(data, min_length=4):
    """Extract simple UTF-16LE printable strings often found in Windows binaries."""
    strings = []
    current = []

    for index in range(0, len(data) - 1, 2):
        code = data[index] | (data[index + 1] << 8)
        if 32 <= code <= 126:
            current.append(chr(code))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def likely_text(data):
    """Heuristically decide whether the upload is mostly text/source code."""
    if not data:
        return True

    sample = data[:4096]
    printable = sum(
        1 for byte in sample if byte in b"\r\n\t" or 32 <= byte <= 126
    )
    return printable / len(sample) > 0.85


def summarize_strings(strings):
    """Keep high-signal strings near the top while limiting prompt size."""
    interesting_words = (
        "flag",
        "ctf",
        "correct",
        "wrong",
        "password",
        "serial",
        "key",
        "xor",
        "encrypt",
        "decrypt",
        "base64",
        "debug",
        "license",
        "success",
        "fail",
    )

    unique = list(dict.fromkeys(strings))
    interesting = [
        item for item in unique if any(word in item.lower() for word in interesting_words)
    ]
    remaining = [item for item in unique if item not in interesting]
    return (interesting + remaining)[:MAX_STRINGS]


def byte_histogram(data):
    """Return a tiny byte histogram summary useful for packed/encrypted guesses."""
    if not data:
        return "empty file"

    counter = Counter(data)
    unique_count = len(counter)
    null_ratio = data.count(0) / len(data)
    printable_ratio = sum(1 for byte in data if 32 <= byte <= 126) / len(data)
    return (
        f"unique_bytes={unique_count}, "
        f"null_ratio={null_ratio:.3f}, "
        f"printable_ascii_ratio={printable_ratio:.3f}"
    )


def analyze_uploaded_file(filename, data):
    """Create a compact local analysis report for the AI model."""
    ascii_strings = extract_ascii_strings(data)
    utf16_strings = extract_utf16le_strings(data)
    decoded_variants = decode_text_variants(data)
    decoded_candidates = detect_possible_encodings(data, decoded_variants)
    tool_outputs = {}
    elf_info = {}

    text_preview = ""
    if likely_text(data):
        text_preview = decoded_variants.get("utf-8") or decoded_variants.get("latin-1", "")

    suffix = os.path.splitext(filename)[1] or ".bin"
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name
        tool_outputs["file"] = run_command(["file", temp_path], timeout=5, max_output=4000)
        tool_outputs["strings"] = run_command(["strings", temp_path], timeout=5, max_output=MAX_TOOL_OUTPUT)
        if data.startswith(b"\x7fELF"):
            elf_info, elf_tool_outputs = analyze_elf_with_tools(temp_path, data)
            tool_outputs.update(elf_tool_outputs)
    finally:
        if "temp_path" in locals():
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    decoded_flag_sources = []
    for candidate in decoded_candidates:
        preview = candidate.get("preview", "")
        raw = candidate.get("raw", b"")
        if preview:
            decoded_flag_sources.append((f"decoded {candidate['type']} preview", preview))
        if raw:
            decoded_flag_sources.append((f"decoded {candidate['type']} strings", extract_ascii_strings(raw)))

    flag_candidates = find_candidates_in_sources(
        [
            ("ASCII strings", ascii_strings),
            ("UTF-16LE strings", utf16_strings),
            ("decoded text preview", text_preview),
            *decoded_flag_sources,
        ]
    )

    return {
        "filename": filename,
        "size": len(data),
        "sha256": sha256_bytes(data),
        "file_type": detect_file_type(data),
        "byte_summary": byte_histogram(data),
        "executable_permissions": "not preserved by browser upload",
        "text_previews": decoded_variants,
        "text_preview": text_preview,
        "hex_preview": hex_preview(data),
        "decoded_candidates": [
            {
                "type": item["type"],
                "confidence": item["confidence"],
                "reason": item["reason"],
                "preview": item["preview"],
            }
            for item in decoded_candidates
        ],
        "flag_candidates": flag_candidates[:80],
        "ascii_strings": summarize_strings(ascii_strings),
        "utf16le_strings": summarize_strings(utf16_strings),
        "suspicious_strings": suspicious_strings_from(ascii_strings + utf16_strings),
        "elf_info": elf_info,
        "tool_outputs": tool_outputs,
    }


def analyze_uploaded_files(uploaded_files):
    """Analyze multiple uploaded files and combine their flag evidence."""
    file_reports = []
    all_candidates = []
    total_size = 0

    for uploaded_file in uploaded_files:
        report = analyze_uploaded_file(uploaded_file["filename"], uploaded_file["content"])
        file_reports.append(report)
        total_size += report["size"]

        for candidate in report["flag_candidates"]:
            candidate = dict(candidate)
            candidate["source"] = f"{report['filename']} / {candidate.get('source', 'unknown source')}"
            all_candidates.append(candidate)

    return {
        "filename": f"{len(file_reports)} uploaded file(s)",
        "size": total_size,
        "sha256": "multiple files",
        "file_type": "folder/multiple files",
        "byte_summary": f"files={len(file_reports)}, total_size={total_size} bytes",
        "flag_candidates": dedupe_candidates(all_candidates)[:120],
        "ascii_strings": [],
        "utf16le_strings": [],
        "suspicious_strings": [],
        "text_preview": "",
        "text_previews": {},
        "hex_preview": "",
        "decoded_candidates": [],
        "elf_info": {},
        "tool_outputs": {},
        "file_reports": file_reports,
    }


def find_candidates_in_sources(sources):
    """Scan multiple decoded sources using the shared flag extractor."""
    all_candidates = []

    for source_name, values in sources:
        if isinstance(values, str):
            chunks = [values]
        else:
            chunks = values

        for chunk in chunks:
            all_candidates.extend(
                find_flag_candidates(
                    chunk,
                    source=source_name,
                    transform=source_name,
                )
            )

    return dedupe_candidates(all_candidates)


def format_candidate(candidate):
    """Format one candidate object for text output."""
    source = candidate.get("source", "unknown source")
    transform = candidate.get("transform", "unknown transform")
    return (
        f"- value: {candidate['value']}\n"
        f"  confidence: {candidate['confidence']}\n"
        f"  matched pattern: {candidate['pattern_name']}\n"
        f"  source: {source}\n"
        f"  transform: {transform}\n"
        f"  reason: {candidate['reason']}"
    )


def format_tool_result(name, result):
    """Format one subprocess result for prompt/UI evidence."""
    if not result:
        return f"{name}: not run"
    command = " ".join(result.get("command", []))
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    error = result.get("error", "")
    parts = [
        f"{name}",
        f"command: {command}",
        f"success: {result.get('success')}",
    ]
    if error:
        parts.append(f"error: {error}")
    if stdout:
        parts.append("stdout:\n" + stdout)
    if stderr:
        parts.append("stderr:\n" + stderr)
    return "\n".join(parts)


def append_file_evidence(lines, report, include_full=False):
    """Append concrete local evidence for one uploaded file."""
    lines.extend([
        f"\n=== File Evidence: {report['filename']} ===",
        f"Size: {report['size']} bytes",
        f"SHA-256: {report['sha256']}",
        f"Detected type: {report['file_type']}",
        f"Byte summary: {report['byte_summary']}",
        f"Executable permissions: {report.get('executable_permissions', 'unknown')}",
    ])

    if report.get("text_preview"):
        lines.append("\ncat-style text preview:")
        lines.append(truncate_text(report["text_preview"], 4000))

    if report.get("hex_preview"):
        lines.append("\nxxd-style hex preview:")
        lines.append(report["hex_preview"])

    if report.get("decoded_candidates"):
        lines.append("\nPossible decoded forms:")
        for item in report["decoded_candidates"][:10]:
            lines.append(
                f"- {item['type']} ({item['confidence']}): {item['reason']}\n"
                f"  preview: {truncate_text(item['preview'], 1000)}"
            )

    if report.get("flag_candidates"):
        lines.append("\nDetected flag candidates in this file:")
        lines.extend(format_candidate(item) for item in report["flag_candidates"][:30])

    if report.get("suspicious_strings"):
        lines.append("\nSuspicious strings:")
        lines.extend(f"- {item}" for item in report["suspicious_strings"][:MAX_STRINGS_DISPLAY])

    if report.get("ascii_strings"):
        lines.append("\nPrintable strings, first 100 high-signal entries:")
        lines.extend(f"- {item}" for item in limit_lines(report["ascii_strings"], MAX_STRINGS_DISPLAY))

    if report.get("utf16le_strings"):
        lines.append("\nUTF-16LE strings, first 100 high-signal entries:")
        lines.extend(f"- {item}" for item in limit_lines(report["utf16le_strings"], MAX_STRINGS_DISPLAY))

    if report.get("elf_info"):
        elf_info = report["elf_info"]
        lines.append("\nELF metadata:")
        for key in ("architecture", "bits", "endianness", "elf_type", "entry_point", "stripped"):
            if key in elf_info:
                lines.append(f"- {key}: {elf_info[key]}")
        if elf_info.get("security"):
            lines.append("- security hints:")
            for key, value in elf_info["security"].items():
                lines.append(f"  - {key}: {value}")
        if elf_info.get("sections"):
            lines.append("- sections: " + ", ".join(elf_info["sections"][:80]))
        if elf_info.get("imports"):
            lines.append("- imports: " + ", ".join(elf_info["imports"][:80]))
        if elf_info.get("functions"):
            lines.append("- functions: " + ", ".join(elf_info["functions"][:80]))

    tool_outputs = report.get("tool_outputs", {})
    if tool_outputs:
        lines.append("\nTool outputs:")
        for name in ("file", "readelf_header", "readelf_sections", "readelf_symbols", "objdump_symbols", "strings"):
            if name in tool_outputs:
                lines.append(format_tool_result(name, tool_outputs[name]))
                if not include_full and name in ("readelf_symbols", "objdump_symbols", "strings"):
                    lines[-1] = truncate_text(lines[-1], 4000)


def format_analysis_for_prompt(analysis):
    """Render local file analysis into text that fits well in an LLM prompt."""
    lines = [
        f"Filename: {analysis['filename']}",
        f"Size: {analysis['size']} bytes",
        f"SHA-256: {analysis['sha256']}",
        f"Detected type: {analysis['file_type']}",
        f"Byte summary: {analysis['byte_summary']}",
    ]

    grouped_candidates = group_flag_candidates(analysis["flag_candidates"])
    if analysis["flag_candidates"]:
        lines.append("\nHigh-confidence flag candidates:")
        if grouped_candidates["high"]:
            lines.extend(format_candidate(item) for item in grouped_candidates["high"])
        else:
            lines.append("- none")

        lines.append("\nMedium-confidence flag candidates:")
        if grouped_candidates["medium"]:
            lines.extend(format_candidate(item) for item in grouped_candidates["medium"])
        else:
            lines.append("- none")

        lines.append("\nLow-confidence suspicious strings:")
        if grouped_candidates["low"]:
            lines.extend(format_candidate(item) for item in grouped_candidates["low"][:30])
        else:
            lines.append("- none")
    else:
        lines.append(
            "\nFlag candidates: none found. The flag may be generated dynamically or hidden behind logic."
        )

    if analysis.get("file_reports"):
        lines.append("\nUploaded file summary:")
        for report in analysis["file_reports"][:50]:
            lines.append(
                f"- {report['filename']} | {report['size']} bytes | "
                f"{report['file_type']} | sha256={report['sha256']}"
            )
        if len(analysis["file_reports"]) > 50:
            lines.append(f"- ... {len(analysis['file_reports']) - 50} more file(s)")

        lines.append(
            "\nConcrete local evidence follows. Do not ask the user to run cat, xxd, strings, file, readelf, or objdump for these uploaded files; those results are already included below."
        )
        for report in analysis["file_reports"][:12]:
            append_file_evidence(lines, report)
        if len(analysis["file_reports"]) > 12:
            lines.append(f"\n...[file evidence truncated, {len(analysis['file_reports']) - 12} more file(s)]")

    if analysis["ascii_strings"]:
        lines.append("\nHigh-signal ASCII strings:")
        lines.extend(f"- {item}" for item in analysis["ascii_strings"])

    if analysis["utf16le_strings"]:
        lines.append("\nHigh-signal UTF-16LE strings:")
        lines.extend(f"- {item}" for item in analysis["utf16le_strings"])

    if analysis["text_preview"]:
        lines.append("\nText/source preview:")
        lines.append(analysis["text_preview"])

    if not analysis.get("file_reports"):
        append_file_evidence(lines, analysis, include_full=True)

    return "\n".join(lines)
