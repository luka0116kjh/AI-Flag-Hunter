from flag_extractor import dedupe_candidates, find_flag_candidates


KNOWN_PREFIXES = [b"flag{", b"ctf{", b"picoCTF{", b"DH{", b"HACK2026{", b"GHAS{"]
COMMON_KEYS = [
    b"key",
    b"flag",
    b"ctf",
    b"secret",
    b"dreamhack",
    b"xor",
]


def printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for byte in data if byte in b"\r\n\t" or 32 <= byte <= 126)
    return printable / len(data)


def xor_with_key(data, key):
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def is_reasonable_xor_candidate(candidate):
    value = candidate["value"]
    if len(value) > 120:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    if "{" in value and "}" in value:
        inside = value[value.find("{") + 1:value.rfind("}")]
        if len(inside) < 3:
            return False
        sane = sum(1 for char in inside if char.isalnum() or char in "_-@!#$%^&*+=:;,.?/|~")
        return sane / len(inside) > 0.80
    return candidate["confidence"] == "low"


def filter_xor_candidates(candidates):
    return [candidate for candidate in candidates if is_reasonable_xor_candidate(candidate)]


def single_byte_xor(data, source):
    results = []
    for key in range(256):
        decoded = bytes(byte ^ key for byte in data)
        text = decoded.decode("utf-8", errors="replace")
        candidates = filter_xor_candidates(
            find_flag_candidates(text, source=source, transform=f"single_byte_xor:0x{key:02x}")
        )
        if candidates:
            results.append({
                "method": "single_byte_xor",
                "key": f"0x{key:02x}",
                "preview": text[:500],
                "candidates": candidates,
            })
    return results


def common_key_xor(data, source):
    results = []
    for key in COMMON_KEYS:
        decoded = xor_with_key(data, key)
        text = decoded.decode("utf-8", errors="replace")
        candidates = filter_xor_candidates(
            find_flag_candidates(text, source=source, transform=f"common_key_xor:{key.decode()}")
        )
        if candidates:
            results.append({
                "method": "common_key_xor",
                "key": key.decode(),
                "preview": text[:500],
                "candidates": candidates,
            })
    return results


def known_prefix_xor(data, source):
    results = []
    max_key_length = 16

    for prefix in KNOWN_PREFIXES:
        for offset in range(0, min(len(data), 64)):
            if offset + len(prefix) > len(data):
                continue
            key_stream = bytes(data[offset + index] ^ prefix[index] for index in range(len(prefix)))
            for key_length in range(1, min(max_key_length, len(key_stream)) + 1):
                key = key_stream[:key_length]
                decoded = xor_with_key(data[offset:], key)
                text = decoded.decode("utf-8", errors="replace")
                candidates = filter_xor_candidates(
                    find_flag_candidates(
                        text,
                        source=source,
                        transform=f"known_prefix_xor:key={key.hex()}:offset={offset}",
                    )
                )
                if candidates and printable_ratio(decoded[:200]) > 0.70:
                    results.append({
                        "method": "known_prefix_xor",
                        "key": key.hex(),
                        "offset": offset,
                        "prefix": prefix.decode("ascii", errors="replace"),
                        "preview": text[:500],
                        "candidates": candidates,
                    })

    return results


def analyze_xor_for_file(filename, data):
    if not data or len(data) > 2_000_000:
        return {
            "filename": filename,
            "results": [],
            "note": "Skipped XOR analysis for empty or very large file.",
        }

    results = []
    results.extend(single_byte_xor(data, filename))
    results.extend(common_key_xor(data, filename))
    results.extend(known_prefix_xor(data, filename))

    all_candidates = []
    for result in results:
        all_candidates.extend(result["candidates"])

    return {
        "filename": filename,
        "results": results[:50],
        "candidates": dedupe_candidates(all_candidates),
    }


def analyze_xor(uploaded_files):
    file_results = []
    all_candidates = []

    for uploaded_file in uploaded_files:
        result = analyze_xor_for_file(uploaded_file["filename"], uploaded_file["content"])
        file_results.append(result)
        all_candidates.extend(result.get("candidates", []))

    return {
        "files": file_results,
        "candidates": dedupe_candidates(all_candidates),
    }
