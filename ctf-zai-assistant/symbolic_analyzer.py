from flag_extractor import dedupe_candidates, find_flag_candidates


SUCCESS_MARKERS = [b"Correct", b"Success", b"Win", b"Good", b"flag"]
FAILURE_MARKERS = [b"Wrong", b"Fail", b"Invalid", b"Nope"]


def analyze_with_angr(uploaded_files, timeout=60):
    try:
        import angr  # noqa: F401
        import claripy  # noqa: F401
    except ImportError:
        return {
            "enabled": False,
            "error": "angr is not installed. Install requirements-advanced.txt.",
            "files": [],
        }

    # Keep this intentionally conservative. Full angr automation can be slow and
    # binary-specific, so the first version reports viable targets and evidence.
    files = []
    all_candidates = []
    for uploaded_file in uploaded_files:
        data = uploaded_file["content"]
        success_hits = [marker.decode() for marker in SUCCESS_MARKERS if marker in data]
        failure_hits = [marker.decode() for marker in FAILURE_MARKERS if marker in data]
        text = data.decode("utf-8", errors="replace")
        candidates = find_flag_candidates(text, source=uploaded_file["filename"], transform="angr_precheck")
        all_candidates.extend(candidates)
        files.append({
            "filename": uploaded_file["filename"],
            "success_markers": success_hits,
            "failure_markers": failure_hits,
            "candidates": candidates,
            "note": "angr installed; automatic path search is left conservative to avoid long runs on arbitrary binaries.",
        })

    return {
        "enabled": True,
        "files": files,
        "candidates": dedupe_candidates(all_candidates),
    }
