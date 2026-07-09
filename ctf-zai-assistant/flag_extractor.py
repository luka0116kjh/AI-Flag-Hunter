import re


MAX_CANDIDATE_LENGTH = 250
KNOWN_FLAG_PREFIXES = [
    "flag",
    "ctf",
    "picoCTF",
    "DH",
    "dreamhack",
    "HACK",
    "HACK2026",
    "GHAS",
    "kisec",
    "sunrin",
    "seccon",
    "codegate",
    "hitcon",
    "zer0pts",
    "corctf",
    "uiuctf",
    "ictf",
    "wargame",
]
SUSPICIOUS_KEYWORDS = [
    "flag",
    "ctf",
    "key",
    "secret",
    "answer",
    "password",
    "token",
    "decrypt",
    "encrypt",
    "xor",
]
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def build_known_prefix_pattern():
    prefixes = sorted(KNOWN_FLAG_PREFIXES, key=len, reverse=True)
    escaped = "|".join(re.escape(prefix) for prefix in prefixes)
    return re.compile(
        rf"\b(?:{escaped})\{{[^{{}}\r\n]{{1,200}}\}}",
        re.IGNORECASE,
    )


KNOWN_PREFIX_PATTERN = build_known_prefix_pattern()
GENERIC_BRACE_PATTERN = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9_-]{1,30}\{[^{}\r\n]{1,200}\}"
)
SUSPICIOUS_KEYWORD_PATTERN = re.compile(
    r"(?i)(?:flag|ctf|key|secret|answer|password|token|decrypt|encrypt|xor)"
)


def is_mostly_printable(value):
    """Reject binary-looking candidates and accidental huge matches."""
    if not value or len(value) > MAX_CANDIDATE_LENGTH:
        return False
    if "\r" in value or "\n" in value:
        return False

    printable = sum(1 for char in value if char.isprintable())
    return printable / len(value) > 0.95


def make_candidate(value, confidence, pattern_name, source, transform, reason):
    return {
        "value": value,
        "confidence": confidence,
        "pattern_name": pattern_name,
        "source": source,
        "transform": transform,
        "reason": reason,
    }


def dedupe_candidates(candidates):
    """Deduplicate and keep the highest-confidence result for each value."""
    deduped = {}

    for candidate in candidates:
        value = candidate["value"]
        if not is_mostly_printable(value):
            continue

        key = value.lower()
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = candidate
            continue

        current_rank = CONFIDENCE_RANK[candidate["confidence"]]
        existing_rank = CONFIDENCE_RANK[existing["confidence"]]
        if current_rank > existing_rank:
            deduped[key] = candidate
        elif current_rank == existing_rank:
            if candidate.get("source") and candidate["source"] not in existing.get("source", ""):
                existing["source"] = f"{existing.get('source', '')}, {candidate['source']}".strip(", ")
            if candidate.get("transform") and candidate["transform"] not in existing.get("transform", ""):
                existing["transform"] = f"{existing.get('transform', '')}, {candidate['transform']}".strip(", ")
            if candidate["reason"] not in existing["reason"]:
                existing["reason"] = f"{existing['reason']} Also matched: {candidate['reason']}"

    return sorted(
        deduped.values(),
        key=lambda item: (-CONFIDENCE_RANK[item["confidence"]], item["value"].lower()),
    )


def find_flag_candidates(text, source="", transform="raw"):
    """Find CTF-style flags and suspicious strings in text."""
    candidates = []
    if not text:
        return candidates

    for match in KNOWN_PREFIX_PATTERN.finditer(text):
        candidates.append(
            make_candidate(
                value=match.group(0),
                confidence="high",
                pattern_name="known_ctf_prefix_braces",
                source=source,
                transform=transform,
                reason="Known CTF flag prefix followed by {...}.",
            )
        )

    for match in GENERIC_BRACE_PATTERN.finditer(text):
        candidates.append(
            make_candidate(
                value=match.group(0),
                confidence="medium",
                pattern_name="generic_prefix_braces",
                source=source,
                transform=transform,
                reason="Unknown prefix followed by {...}; common custom CTF flag shape.",
            )
        )

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or len(stripped) > MAX_CANDIDATE_LENGTH:
            continue
        if not is_mostly_printable(stripped):
            continue
        keyword_match = SUSPICIOUS_KEYWORD_PATTERN.search(stripped)
        if keyword_match:
            candidates.append(
                make_candidate(
                    value=stripped,
                    confidence="low",
                    pattern_name="suspicious_keyword_string",
                    source=source,
                    transform=transform,
                    reason=f"Contains suspicious keyword '{keyword_match.group(0)}'.",
                )
            )

    return dedupe_candidates(candidates)


def group_flag_candidates(candidates):
    grouped = {"high": [], "medium": [], "low": []}
    for candidate in candidates:
        grouped[candidate["confidence"]].append(candidate)
    return grouped


# --- Answer-only mode: pick the single most reliable flag, or nothing. ---
#
# Priority order (lower tier = printed first when several candidates qualify).
# This is deliberately platform-agnostic: tier 1 is driven by KNOWN_FLAG_PREFIXES
# above (flag, ctf, picoCTF, DH, dreamhack, HACK, HACK2026, GHAS, seccon,
# codegate, hitcon, zer0pts, corctf, uiuctf, kisec, sunrin, ictf, wargame, ...),
# matched case-insensitively, not hardcoded to any single format like `DH{...}`.
#   1. known CTF prefix, however it was found (direct, decoded, XOR, angr/z3/Ghidra)
#   2. no known prefix, but successfully recovered by a decoder (hex/base64/
#      url/rot13), XOR brute force, or angr/z3/Ghidra-supported evidence
#   3. no known prefix, medium-confidence generic `prefix{...}` match found
#      directly (e.g. ooo{...}, abc{...}, team123{...}, customctf{...})
FLAG_SHAPE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}\{[^{}\r\n]{1,200}\}$")
XOR_TRANSFORM_MARKERS = ("single_byte_xor", "common_key_xor", "known_prefix_xor")
ADVANCED_TRANSFORM_MARKERS = ("angr", "ghidra", "z3")


def _is_flag_shaped(value):
    """Reject anything that is not a clean `prefix{...}` string.

    This is what keeps noise like "secret_key_table", "password", or report
    titles out of answer-only mode even if they matched a suspicious keyword.
    """
    return bool(FLAG_SHAPE_PATTERN.match((value or "").strip()))


def _matches_known_prefix(value):
    """True for any prefix in KNOWN_FLAG_PREFIXES, not just DH/flag/ctf.

    Checked directly against the value (not just pattern_name) so it also
    catches known-prefix flags recovered by XOR/decode/angr, whose value may
    not have been tagged with the "known_ctf_prefix_braces" pattern name.
    """
    return bool(KNOWN_PREFIX_PATTERN.fullmatch((value or "").strip()))


def _final_answer_tier(candidate):
    """Return the priority tier (1 best .. 3 worst) for a final-answer
    candidate, or None if it is not reliable enough to ever be printed.
    """
    if candidate.get("pattern_name") == "suspicious_keyword_string":
        return None
    if candidate.get("confidence") == "low":
        return None

    value = candidate.get("value")
    if not _is_flag_shaped(value):
        return None

    confidence = candidate.get("confidence")
    pattern_name = candidate.get("pattern_name", "")
    transform = (candidate.get("transform") or "").lower()

    if _matches_known_prefix(value) or pattern_name == "known_ctf_prefix_braces":
        return 1

    is_xor = any(marker in transform for marker in XOR_TRANSFORM_MARKERS)
    is_advanced = any(marker in transform for marker in ADVANCED_TRANSFORM_MARKERS)
    is_decoded = "decoded" in transform
    if is_xor or is_advanced or is_decoded:
        return 2

    if confidence == "medium" and pattern_name == "generic_prefix_braces":
        return 3
    return None


def rank_final_flag_candidates(candidates):
    """Deduplicate and rank candidates that are reliable enough to be printed
    as a final CTF answer, best first. Never invents a value; only ranks and
    filters candidates that were already detected locally, decoded, or
    recovered by XOR/angr/z3/Ghidra.
    """
    ranked = []
    for candidate in dedupe_candidates(candidates):
        tier = _final_answer_tier(candidate)
        if tier is None:
            continue
        ranked.append((tier, len(candidate["value"]), candidate["value"].lower(), candidate))

    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in ranked]


def select_best_final_flag(candidates: list[dict]) -> dict | None:
    """Pick the single best candidate for answer-only CLI output, or None.

    See `rank_final_flag_candidates` for the ranking/rejection rules.
    """
    ranked = rank_final_flag_candidates(candidates)
    return ranked[0] if ranked else None
