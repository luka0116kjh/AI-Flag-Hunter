# CTF Z.AI Assistant

[English](README.md) | [한국어](README_KO.md)

---

A Python assistant for CTF challenge solving. It includes a terminal CLI and a small web UI. It uses the Z.AI API through the OpenAI SDK-compatible interface and helps with vulnerability analysis, attack points, solving strategy, payload ideas, script drafts, and reversing-focused file analysis.

The assistant is designed for progressive disclosure, so you can ask for:

- `hint only`
- `reveal a little more`
- `show final exploit`

Use it only for CTFs, wargames, local labs, and authorized security testing.

## Installation

```bash
cd ctf-zai-assistant
python -m venv .venv
```

Activate the virtual environment.

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## `.env` Setup

Copy the example file:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and add your Z.AI API key:

```env
ZAI_API_KEY=your_real_zai_api_key_here
ZAI_BASE_URL=https://api.z.ai/api/paas/v4/
ZAI_MODEL=glm-5.2
```

Do not upload `.env` or your API key to GitHub.

For the NVIDIA OpenAI-compatible endpoint, use:

```env
ZAI_API_KEY=your_nvidia_api_key_here
ZAI_BASE_URL=https://integrate.api.nvidia.com/v1
ZAI_MODEL=z-ai/glm-5.2
```

Never hardcode API keys in Python files. If a key is pasted into chat, committed, or shared, revoke it and create a new one.

## How to Run

First time setup, then answer-only scan:

```powershell
python scan_folder.py --init-samples
python scan_folder.py --only-flag
```

Automatic folder scanner:

```bash
python scan_folder.py ./samples
```

Optional report paths and limits:

```bash
python scan_folder.py --init-samples
python scan_folder.py ./samples --json reports/result.json
python scan_folder.py ./samples --html reports/result.html
python scan_folder.py ./samples --max-size 50000000
python scan_folder.py ./samples --no-ai
python scan_folder.py ./samples --include-reports
python scan_folder.py ./samples --ignore reports,.git,__pycache__
python scan_folder.py ./samples --xor
python scan_folder.py ./samples --ghidra
python scan_folder.py ./samples --angr
python scan_folder.py ./samples --z3-helper
python scan_folder.py ./samples --all-advanced
```

Terminal CLI:

```bash
python main.py
```

Web UI for folder-based flag extraction:

```bash
python web_app.py
```

Open:

```text
http://127.0.0.1:8000
```

The tool uses:

- API base URL: `https://api.z.ai/api/paas/v4/`
- Default model: `glm-5.2`

You can override both values with `ZAI_BASE_URL` and `ZAI_MODEL` in `.env`.

## Usage Example

```text
=== CTF Z.AI Assistant ===

Challenge name: Dreamhack rao
Category: pwn
Environment: local / nc host port
Provided files/materials: rao.c, rao binary
My current progress: checksec done, NX enabled, PIE disabled
Request: Analyze the attack points first
```

After the first analysis, continue with follow-up questions:

```text
hint only
reveal a little more
show final exploit
Why did my payload crash?
Suggest a pwntools script draft
```

## Web UI File Analysis

The web UI is intentionally simple. Choose the CTF category, upload the challenge folder, and press `Flag 추출`. Chrome and Edge support folder selection through the browser file picker. It performs safe local extraction first:

- file type guess from magic bytes for each file
- file size and SHA-256 for each file
- cat-style text preview for text/raw data files
- xxd-style hex preview for the first 512 bytes
- ASCII strings
- UTF-16LE strings
- possible decoded forms, including hex, base64, URL encoding, ROT13, and XOR-looking binary data hints
- suspicious keyword detection
- ELF metadata extraction when applicable
- optional local tool outputs from `file`, `strings`, `readelf`, and `objdump` when those tools are installed
- flexible CTF flag candidate detection
- text/source preview for source-like files

The assistant sends this real local evidence to Z.AI. It should not ask you to manually run basic commands such as `cat output.txt`, `xxd output.txt`, `strings binary`, or `readelf -s binary` for uploaded files, because the web UI already performs equivalent inspections automatically.

Flag detection is not limited to only a few hardcoded formats. It uses configurable patterns with multiple confidence levels.

Examples it can detect:

- `flag{test}`
- `DH{test}`
- `picoCTF{test}`
- `ooo{test}`
- `HACK2026{test}`

Confidence levels:

- High confidence: known CTF prefix such as `flag`, `ctf`, `picoCTF`, `DH`, `dreamhack`, `seccon`, `codegate`, `hitcon`, `zer0pts`, `corctf`, `uiuctf`, `ictf`, or `wargame`.
- Medium confidence: unknown prefix but CTF-like `{...}` structure, such as `ooo{test}` or `team123{test}`.
- Low confidence: suspicious strings containing words such as `flag`, `ctf`, `key`, `secret`, `answer`, `password`, or `token`, but not confirmed as a final flag.

Then it sends the extracted evidence from the folder to Z.AI and asks for a concise analysis. If a flag is directly visible or strongly inferable, the answer includes:

```text
Flag candidate: ...
Confidence: High/Medium/Low
Evidence: ...
```

If the uploaded evidence is not enough to recover the flag, the assistant explains the next exact steps for Ghidra, IDA, gdb, angr, or z3.

If the flag is stored as a plain string or a simple encoded value, the local analyzer may find it directly. If the flag is encrypted, generated dynamically, or checked through binary logic, the AI analysis will use the extracted strings, decoded previews, ELF sections, symbols, imports, suspicious functions, and tool outputs to suggest the next reversing steps.

API analysis consumes tokens. Large files or files with many extracted strings can use a lot of context, so repeatedly analyzing the same challenge about five times may quickly reduce a free or limited token balance. Check the local candidates first, then rerun AI analysis only when needed.

Check the **Answer only / Flag only** box before submitting to skip all of that. It shows one large result box with just the flag:

```text
DH{example_flag}
```

or, when nothing reliable was found:

```text
NOT_FOUND
```

This mode uses the same local-evidence-only ranking as `scan_folder.py --only-flag` (`select_best_final_flag()`), does not call the AI at all, and never guesses. The full report (local evidence, strings, ELF metadata, tool outputs) is still generated underneath — click **Show details** to expand it.

## Folder Scanner

`scan_folder.py` is the fastest way to use the project as an automatic CTF flag extractor.

### Quick Start

First run, set up the folders:

```powershell
python scan_folder.py --init-samples
```

This creates `samples/`, `reports/`, and `samples/README.txt`. Drop your challenge files into `samples/`, then run:

```powershell
python scan_folder.py --only-flag
```

or, with advanced recovery enabled:

```powershell
python scan_folder.py --only-flag --all-advanced
```

The `folder` argument is optional and defaults to `.\samples`, so `python scan_folder.py --only-flag` is the same as `python scan_folder.py .\samples --only-flag`. You can still point at any other folder by passing it explicitly:

```bash
python scan_folder.py ./samples
```

If the target folder does not exist yet, the scanner creates it automatically instead of failing, prints a friendly reminder to add files, and exits with code `1` (nothing to scan yet, not an error):

```text
[-] Target folder does not exist.
[+] Created folder: .\samples
[!] Put your CTF challenge files into .\samples and run again.

Example:
  python scan_folder.py .\samples --only-flag
  python scan_folder.py .\samples --only-flag --xor
  python scan_folder.py .\samples --only-flag --all-advanced
```

If the folder exists but has no files in it, it prints a similar reminder instead of a full (empty) report:

```text
[-] No files found in .\samples
[!] Put challenge files such as chall, output.txt, flag.txt, image.png, dump.bin into the folder and run again.
```

In `--only-flag` mode both of these cases just print `NOT_FOUND` (exit `1`) to keep the single-line output contract - the friendlier multi-line guidance above only shows in normal mode.

Example folder:

```text
samples/
├── legacyopt
├── output.txt
├── chall
├── encrypted.dat
└── image.png
```

The scanner recursively analyzes every file and prints likely flags first:

```text
=== CTF Folder Flag Extractor ===

[+] Folder: ./samples
[+] Files scanned: 5
[+] Candidates found: 3

[HIGH]
1. DH{example_flag}
   source: legacyopt / ASCII strings
   transform: ASCII strings
   reason: Known CTF flag prefix followed by {...}.
```

It also writes:

- `reports/result.json`
- `reports/result.html`

The JSON report contains scanned files, hashes, metadata, strings preview, decoded outputs, flag candidates, suspicious strings, and optional AI analysis. The HTML report shows the same information in a browser-friendly format.

The scanner ignores generated and development folders by default:

- `reports`
- `.git`
- `__pycache__`
- `.venv`
- `venv`
- `node_modules`
- `dist`
- `build`
- `.idea`
- `.vscode`

Use `--include-reports` if you intentionally want to scan generated reports. Use `--ignore name1,name2` to add more ignored names.

Supported direct extraction cases:

- the flag exists as a plain string
- the flag exists in UTF-16LE
- the flag is simply encoded as hex, base64, URL encoding, or ROT13
- the flag appears in output files

Cases where direct extraction may fail:

- the flag is encrypted
- the flag is generated dynamically
- the binary is packed or obfuscated
- the flag requires solving input constraints
- the flag is produced only after executing the program correctly

In those cases, the scanner still extracts local evidence and prints useful reversing hints. If `ZAI_API_KEY` is configured and `--no-ai` is not used, it also sends the extracted evidence to Z.AI for ranking and next-step guidance. The AI prompt explicitly tells the model not to ask you to manually run `cat`, `xxd`, `strings`, `file`, `readelf`, or `objdump` when those results are already collected.

### Scanner Modes

Fast local scan without AI:

```bash
python scan_folder.py ./samples --no-ai
```

Local scan plus Z.AI analysis:

```bash
python scan_folder.py ./samples
```

XOR mode:

```bash
python scan_folder.py ./samples --xor
```

This tries single-byte XOR, common-key XOR, and repeating-key XOR guesses using known flag prefixes.

Ghidra mode:

```bash
python scan_folder.py ./samples --ghidra
```

Set `GHIDRA_HEADLESS_PATH` first:

```env
GHIDRA_HEADLESS_PATH=C:\path\to\ghidra\support\analyzeHeadless.bat
```

This mode extracts function-level evidence, imports, suspicious functions, and keyword references through Ghidra headless when available.

angr mode:

```bash
python scan_folder.py ./samples --angr
```

Install advanced dependencies first:

```bash
pip install -r requirements-advanced.txt
```

This mode performs a conservative angr precheck for success/failure strings and candidate extraction. It skips gracefully if angr is missing.

All advanced checks:

```bash
python scan_folder.py ./samples --all-advanced
```

This enables XOR, Ghidra, angr, and z3 helper availability checks. Advanced features are optional and only run when requested, so basic mode stays fast.

The z3 helper module provides reusable helpers for simple XOR and arithmetic byte constraints, plus a template generator for pseudocode-like constraints.

You can check z3 availability with:

```bash
python scan_folder.py ./samples --z3-helper
```

### Answer-Only Mode (`--only-flag`)

`--only-flag` is for CTF competition speed. Instead of the full report, it prints exactly one line:

```bash
python scan_folder.py .\samples --only-flag
python scan_folder.py .\samples --only-flag --xor
python scan_folder.py .\samples --only-flag --all-advanced
python scan_folder.py .\samples --only-flag --no-ai
```

If a reliable flag is found:

```text
DH{example_flag}
```

If not:

```text
NOT_FOUND
```

`--only-flag` suppresses the banner, scan summary, local evidence, and AI analysis output entirely (the AI is not even called, since it is never used to pick the final answer). It never guesses or hallucinates a flag: a value is only printed when it was actually detected from local evidence or successfully recovered by a decoder, XOR brute force, angr, z3, or Ghidra. Low-confidence suspicious strings (things like `password`, `token`, or `secret_key_table`) are never printed as a final answer.

For encrypted or logic-generated flags where nothing can be directly extracted, `--only-flag` prints `NOT_FOUND`. Use `--all-advanced` or the normal report mode (without `--only-flag`) to get reversing hints and evidence for those cases.

`--only-flag` is not tied to any single flag format like `DH{...}`. It recognizes any clean `prefix{...}` string, and ranks it by how it was found, not by which prefix it uses:

1. **Known CTF prefix**, however it was found (plain string, decoded, XOR, angr/z3/Ghidra) - e.g. `DH{...}`, `flag{...}`, `FLAG{...}`, `ctf{...}`, `CTF{...}`, `picoCTF{...}`, `dreamhack{...}`, `HACK{...}`, `HACK2026{...}`, `GHAS{...}`, `seccon{...}`, `codegate{...}`, `hitcon{...}`, `zer0pts{...}`, `corctf{...}`, `uiuctf{...}`, `kisec{...}`, `sunrin{...}`, `ictf{...}`, `wargame{...}` (case-insensitive; see `KNOWN_FLAG_PREFIXES` in `flag_extractor.py`)
2. **No known prefix, but successfully recovered** by a decoder (hex/base64/URL/ROT13), XOR brute force, or angr/z3/Ghidra-supported evidence
3. **No known prefix, generic `prefix{...}` match found directly** - e.g. `ooo{...}`, `abc{...}`, `team123{...}`, `customctf{...}`

A known-prefix match always outranks a same-tier generic match, and ties within a tier prefer the shorter, cleaner value. Low-confidence suspicious strings, report titles, and anything not shaped like `prefix{...}` (`secret_key_table`, `password`, `token`, `CTF Folder Flag Extractor Report`, ...) are rejected outright and never printed as a final answer.

Add `--all-flags` to print every reliable candidate instead of only the best one, best first, one per line:

```bash
python scan_folder.py .\samples --only-flag --all-flags
```

```text
DH{flag_one}
picoCTF{flag_two}
flag{flag_three}
ooo{flag_four}
```

`select_best_final_flag()` in `flag_extractor.py` implements the ranking: it deduplicates candidates, rejects low-confidence/suspicious non-flag strings, prefers known CTF prefixes and shorter clean matches, and returns `None` when nothing is reliable enough. `rank_final_flag_candidates()` returns the full ordered list used by `--all-flags`.

Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0`  | a reliable flag was found and printed |
| `1`  | no reliable flag found |
| `2`  | scanner error (bad folder, unexpected exception) |
| `3`  | no reliable flag found, and binary files in the folder suggest it needs reversing |

## Category Workflow

### Web

Provide the URL only if it is a CTF or authorized lab. Include request/response examples, source code, cookies, headers, and your Burp Suite findings. Ask for SQLi, XSS, SSRF, auth bypass, file upload, path traversal, SSTI, or deserialization attack points.

Useful prompts:

- `hint only: what endpoint should I inspect first?`
- `reveal a little more: suggest payload candidates`
- `show final exploit: write a requests-based exploit script`

### Pwn

Include `checksec`, binary protections, source code if available, crash offset, architecture, libc info, and GDB observations. Ask for attack path ranking before jumping to exploit code.

Useful prompts:

- `Analyze stack/heap attack points`
- `What should I verify in gdb next?`
- `Draft a pwntools script after the strategy is clear`

### Crypto

Include the algorithm, source code, parameters, ciphertext, public keys, and any oracle behavior. Ask the assistant to separate facts from guesses because crypto challenges often hinge on one weak assumption.

Useful prompts:

- `Identify the broken assumption`
- `Suggest a z3 or Sage approach`
- `Explain how to recognize this pattern later`

### Reversing

Include strings output, suspicious functions, decompiler snippets, file type, architecture, and anti-debug behavior. Ask for a hypothesis and verification checklist.

Useful prompts:

- `What function should I rename first?`
- `Infer the flag check logic`
- `Suggest an angr script design if symbolic execution fits`

### Forensic

Include file type, metadata, extracted strings, binwalk results, packet details, or filesystem artifacts. Ask for a tool-first workflow.

Useful prompts:

- `What should I inspect next?`
- `Prioritize stego/file carving/network analysis`
- `Give commands for binwalk, strings, and exiftool`

## Recommended Tools

- Burp Suite
- pwntools
- GDB / pwndbg
- IDA Free / Ghidra
- CyberChef
- z3
- angr
- binwalk
- strings
- exiftool

## Security Precautions

- Do not attack real services.
- Use this only for CTFs, wargames, local labs, or authorized testing.
- Do not upload your API key to GitHub.
- Keep `.env` private.
- If you are unsure whether a target is authorized, stop and verify permission first.

## Notes

The assistant follows this loop:

1. Hypothesis
2. Verification
3. Failure analysis
4. Strategy change

It also avoids repeating one failed attack endlessly. After three failed attempts, it should explain why the method may be failing and suggest a different vulnerability class or approach.
