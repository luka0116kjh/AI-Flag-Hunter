import html
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from openai import APITimeoutError

from ctf_assistant import CTFAssistant
from file_analyzer import (
    analyze_uploaded_files,
    format_analysis_for_prompt,
    group_flag_candidates,
    truncate_text,
)
from flag_extractor import select_best_final_flag


HOST = "127.0.0.1"
PORT = 8000
MAX_UPLOAD_BYTES = 32 * 1024 * 1024

# Client-disconnect exceptions the server must survive without crashing.
CLIENT_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError)

# If the rendered "Local Evidence" section grows past this, it is written to
# reports/result.html instead of being inlined, and the response only links to it.
MAX_INLINE_EVIDENCE_BYTES = 300_000

# How long to wait for the AI call before giving up and showing offline-mode advice.
AI_TIMEOUT_SECONDS = 90

# The "prompt evidence sent to AI" block mostly duplicates Local Evidence, so it is
# collapsed by default and capped separately from file_analyzer's own per-tool limits.
MAX_PROMPT_EVIDENCE_DISPLAY = 20_000

REPORTS_DIR = Path("reports")
REPORT_FILENAME = "result.html"

AI_TIMEOUT_MESSAGE = f"""AI 분석이 시간 초과({AI_TIMEOUT_SECONDS}초)되었습니다. 서버는 계속 동작 중입니다.

더 가벼운 방식으로 다시 시도해보세요:
python scan_folder.py .\\samples --only-flag --no-ai
python scan_folder.py .\\samples --only-flag --xor
"""


def parse_header_options(value):
    """Parse a simple multipart header with ; key=value options."""
    parts = [part.strip() for part in value.split(";")]
    main_value = parts[0].lower()
    options = {}

    for part in parts[1:]:
        if "=" not in part:
            continue
        key, raw_value = part.split("=", 1)
        options[key.strip().lower()] = raw_value.strip().strip('"')

    return main_value, options


def parse_multipart_form(headers, body):
    """Parse the small multipart forms used by this app without cgi.FieldStorage."""
    content_type = headers.get("Content-Type", "")
    media_type, options = parse_header_options(content_type)
    boundary = options.get("boundary")
    if media_type != "multipart/form-data" or not boundary:
        raise ValueError("Expected multipart/form-data request.")

    delimiter = b"--" + boundary.encode("utf-8")
    fields = {}
    files = {}

    for part in body.split(delimiter):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if part.endswith(b"--"):
            part = part[:-2].rstrip(b"\r\n")
        if b"\r\n\r\n" not in part:
            continue

        raw_headers, content = part.split(b"\r\n\r\n", 1)
        part_headers = {}
        for raw_line in raw_headers.split(b"\r\n"):
            if b":" not in raw_line:
                continue
            key, value = raw_line.split(b":", 1)
            part_headers[key.decode("utf-8", errors="replace").lower()] = (
                value.decode("utf-8", errors="replace").strip()
            )

        disposition = part_headers.get("content-disposition", "")
        _, disposition_options = parse_header_options(disposition)
        name = disposition_options.get("name")
        filename = disposition_options.get("filename")
        if not name:
            continue

        if filename is not None:
            files.setdefault(name, []).append({
                "filename": filename,
                "content": content,
                "content_type": part_headers.get("content-type", "application/octet-stream"),
            })
        else:
            fields[name] = content.decode("utf-8", errors="replace").strip()

    return fields, files


STYLE = """
body {
  margin: 0;
  font-family: Arial, sans-serif;
  background: #101114;
  color: #f1f3f5;
}
main {
  max-width: 1120px;
  margin: 0 auto;
  padding: 28px;
}
h1 {
  margin: 0 0 8px;
  font-size: 30px;
}
.subtitle {
  margin: 0 0 24px;
  color: #aab2bf;
}
.layout {
  display: grid;
  grid-template-columns: 360px 1fr;
  gap: 18px;
}
section {
  background: #181b20;
  border: 1px solid #2c313a;
  border-radius: 8px;
  padding: 18px;
}
label {
  display: block;
  margin: 14px 0 6px;
  color: #d8dde6;
  font-size: 14px;
}
input,
select,
textarea {
  width: 100%;
  box-sizing: border-box;
  border: 1px solid #3b4250;
  border-radius: 6px;
  background: #0f1115;
  color: #f1f3f5;
  padding: 10px;
  font-size: 14px;
}
textarea {
  min-height: 92px;
  resize: vertical;
}
button {
  width: 100%;
  margin-top: 18px;
  border: 0;
  border-radius: 6px;
  background: #2f80ed;
  color: white;
  padding: 12px 14px;
  font-weight: 700;
  cursor: pointer;
}
button:hover {
  background: #1f6fd1;
}
pre {
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
  line-height: 1.48;
}
.result-title {
  margin: 0 0 12px;
  font-size: 18px;
}
.notice {
  color: #aab2bf;
  line-height: 1.55;
}
.error {
  color: #ffb4b4;
}
.warning {
  margin: 0 0 16px;
  padding: 12px;
  border: 1px solid #8b6f2a;
  border-radius: 6px;
  background: #2a2415;
  color: #ffe2a3;
  line-height: 1.45;
}
.candidate-group {
  margin: 0 0 18px;
}
.candidate-group h3 {
  margin: 0 0 10px;
  font-size: 15px;
}
.candidate {
  margin: 0 0 10px;
  padding: 10px;
  border: 1px solid #343a46;
  border-radius: 6px;
  background: #101318;
}
.candidate strong {
  color: #ffffff;
}
.candidate-meta {
  margin-top: 6px;
  color: #b6bfcc;
  font-size: 13px;
  line-height: 1.45;
}
.usage-box {
  margin-top: 12px;
  padding: 10px;
  border: 1px solid #334155;
  border-radius: 6px;
  background: #111827;
  color: #cbd5e1;
  font-size: 13px;
  line-height: 1.5;
}
.usage-box strong {
  color: #f8fafc;
}
.evidence-file {
  margin: 0 0 18px;
  padding: 12px;
  border: 1px solid #2f3744;
  border-radius: 6px;
  background: #111318;
}
.evidence-file h3 {
  margin: 0 0 10px;
  font-size: 16px;
}
.evidence-grid {
  display: grid;
  grid-template-columns: 120px 1fr;
  gap: 6px 10px;
  margin-bottom: 12px;
  color: #cbd5e1;
  font-size: 13px;
}
.small-pre {
  max-height: 260px;
  overflow: auto;
  border: 1px solid #2c313a;
  border-radius: 6px;
  padding: 10px;
  background: #0b0d10;
}
.answer-box {
  margin: 0 0 18px;
  padding: 28px;
  border-radius: 8px;
  text-align: center;
  border: 1px solid #2c313a;
}
.answer-box.found {
  background: #10241a;
  border-color: #2f9e58;
}
.answer-box.not-found {
  background: #241414;
  border-color: #a34848;
}
.answer-value {
  font-family: "Consolas", "Menlo", monospace;
  font-size: 28px;
  font-weight: 700;
  word-break: break-word;
  color: #f1f3f5;
}
.answer-label {
  margin: 0 0 10px;
  color: #aab2bf;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
details.report-details {
  margin-top: 6px;
}
details.report-details summary {
  cursor: pointer;
  color: #7fb2ff;
  padding: 8px 0;
}
@media (max-width: 860px) {
  .layout {
    grid-template-columns: 1fr;
  }
}
"""


def page(content):
    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CTF Z.AI Flag Extractor</title>
  <style>{STYLE}</style>
</head>
<body>
  <main>
    <h1>CTF Z.AI Flag Extractor</h1>
    <p class="subtitle">CTF 유형을 고르고 문제 폴더를 업로드하면 전체 파일에서 flag 후보를 분석합니다.</p>
    {content}
  </main>
  <script>
    const form = document.querySelector("form");
    const filesInput = document.querySelector("input[name='challenge_files']");
    const usageBox = document.querySelector("#live-usage");
    const submitButton = document.querySelector("button[type='submit']");

    function estimateTokens(bytes) {{
      return Math.max(1, Math.ceil(bytes / 4));
    }}

    if (form && filesInput && usageBox) {{
      filesInput.addEventListener("change", () => {{
        let totalBytes = 0;
        for (const file of filesInput.files) {{
          totalBytes += file.size;
        }}
        usageBox.innerHTML =
          "<strong>선택된 파일:</strong> " + filesInput.files.length + "개<br>" +
          "<strong>업로드 크기:</strong> " + totalBytes.toLocaleString() + " bytes<br>" +
          "<strong>대략 토큰 위험도:</strong> 약 " + estimateTokens(totalBytes).toLocaleString() + " tokens 이하로 추정";
      }});

      const stuckAfterSeconds = {AI_TIMEOUT_SECONDS + 30};

      form.addEventListener("submit", (event) => {{
        if (submitButton && submitButton.disabled) {{
          // Already submitting; block accidental double-submits (double click, Enter twice).
          event.preventDefault();
          return;
        }}
        let startedAt = Date.now();
        if (submitButton) {{
          submitButton.disabled = true;
          submitButton.textContent = "분석 중...";
        }}
        usageBox.innerHTML = "<strong>분석 중:</strong> API 응답 대기 중<br><strong>경과 시간:</strong> 0초";
        const intervalId = setInterval(() => {{
          const elapsed = Math.floor((Date.now() - startedAt) / 1000);
          usageBox.innerHTML =
            "<strong>분석 중:</strong> API 응답 대기 중<br>" +
            "<strong>경과 시간:</strong> " + elapsed + "초<br>" +
            "<span>실제 사용 토큰은 응답 완료 후 결과에 표시됩니다.</span>";
          if (elapsed >= stuckAfterSeconds) {{
            clearInterval(intervalId);
            if (submitButton) {{
              submitButton.disabled = false;
              submitButton.textContent = "Flag 추출";
            }}
            usageBox.innerHTML =
              "<strong>응답이 오래 걸리고 있습니다.</strong><br>" +
              "서버가 멈추지 않았다면 페이지를 새로고침하거나 다시 시도해주세요.";
          }}
        }}, 1000);
      }});
    }}
  </script>
</body>
</html>"""


def form_page(result_html=""):
    return page(
        f"""
<div class="layout">
  <section>
    <p class="warning">
      API 분석은 토큰을 사용합니다. 폴더 안 파일이 많거나 문자열이 많으면 한 문제를 5번 정도 분석해도 무료/남은 토큰이 빠르게 줄 수 있습니다.
      먼저 로컬 후보를 확인하고, 필요한 경우에만 반복 실행하세요.
    </p>
    <form method="post" action="/analyze" enctype="multipart/form-data">
      <label>CTF 유형</label>
      <select name="category">
        <option value="reversing">reversing</option>
        <option value="pwn">pwn</option>
        <option value="crypto">crypto</option>
        <option value="web">web</option>
        <option value="forensic">forensic</option>
      </select>

      <label>문제 폴더</label>
      <input type="file" name="challenge_files" webkitdirectory directory multiple required>

      <label style="display: flex; align-items: center; gap: 8px; margin-top: 16px;">
        <input type="checkbox" name="only_flag" value="1" style="width: auto;">
        Answer only / Flag only
      </label>

      <button type="submit">Flag 추출</button>
      <div id="live-usage" class="usage-box">
        <strong>API 사용량:</strong> 폴더를 선택하면 예상 업로드 크기와 토큰 위험도를 표시합니다.
      </div>
    </form>
  </section>

  <section>
    {result_html or '<p class="notice">문제 폴더를 넣고 Flag 추출을 누르면 결과가 여기에 표시됩니다. 실제 바이너리 실행이나 디버깅은 하지 않고, 파일 바이트에서 안전하게 추출한 근거를 기반으로 분석합니다.</p>'}
  </section>
</div>
"""
    )


def build_ai_prompt(analysis_text, fields):
    return f"""
This is an authorized CTF challenge. Analyze the uploaded file evidence and try
to extract or infer the flag.

Upload target: {fields['filename']}
Category: {fields['category']}

Local file analysis:
{analysis_text}

Answer in Korean. Be concise and practical.
Do not ask the user to run cat, xxd, strings, file, readelf, or objdump for
uploaded files. The local evidence below already includes equivalent previews,
strings, ELF metadata, symbols, and tool outputs when available.
Rank local candidates by confidence and evidence. Explain which candidate is
most likely to be the real flag, but avoid claiming certainty when the evidence
is weak or when multiple candidates exist.
If a flag is directly visible or strongly inferable, put it at the top as:
Flag candidate: ...
Confidence: High/Medium/Low
Evidence: ...

If the flag is not recoverable from the uploaded evidence alone, say that clearly.
Then give a short non-duplicated checklist of next exact steps based on the
evidence. Do not repeat the same checklist item with different wording.
For reversing, name the likely function/symbol/string/section to inspect next.
For forensic, suggest the next extraction or decoding step based on previews.
For crypto, suggest decoding/math checks based on observed data. For web or pwn,
only give CTF-safe local or authorized-lab guidance.
""".strip()


def render_candidate(candidate):
    value = html.escape(candidate["value"])
    confidence = html.escape(candidate["confidence"])
    pattern = html.escape(candidate["pattern_name"])
    reason = html.escape(candidate["reason"])
    source = html.escape(candidate.get("source", "unknown source"))
    return f"""
<div class="candidate">
  <strong>{value}</strong>
  <div class="candidate-meta">
    confidence: {confidence}<br>
    matched pattern: {pattern}<br>
    source: {source}<br>
    reason: {reason}
  </div>
</div>
"""


def render_candidate_group(title, candidates):
    if not candidates:
        return f"""
<div class="candidate-group">
  <h3>{html.escape(title)}</h3>
  <p class="notice">No candidates in this group.</p>
</div>
"""

    rendered = "\n".join(render_candidate(candidate) for candidate in candidates)
    return f"""
<div class="candidate-group">
  <h3>{html.escape(title)}</h3>
  {rendered}
</div>
"""


def render_flag_candidates(analysis):
    grouped = group_flag_candidates(analysis["flag_candidates"])
    if not analysis["flag_candidates"]:
        return """
<h2 class="result-title">Local Flag Candidates</h2>
<p class="notice">No direct flag candidate found. The flag may be generated dynamically or hidden behind logic.</p>
"""

    return f"""
<h2 class="result-title">Local Flag Candidates</h2>
{render_candidate_group("High confidence", grouped["high"])}
{render_candidate_group("Medium confidence", grouped["medium"])}
{render_candidate_group("Low confidence / suspicious strings", grouped["low"][:30])}
"""


def render_list_items(items, empty_text="None"):
    if not items:
        return f'<p class="notice">{html.escape(empty_text)}</p>'
    return "<pre class=\"small-pre\">" + html.escape("\n".join(f"- {item}" for item in items)) + "</pre>"


def render_tool_outputs(tool_outputs):
    if not tool_outputs:
        return '<p class="notice">No external tool output. Tools may be unavailable on this system.</p>'

    blocks = []
    for name, result in tool_outputs.items():
        command = " ".join(result.get("command", []))
        text = [
            f"command: {command}",
            f"success: {result.get('success')}",
        ]
        if result.get("error"):
            text.append(f"error: {result['error']}")
        if result.get("stdout"):
            text.append("stdout:\n" + result["stdout"])
        if result.get("stderr"):
            text.append("stderr:\n" + result["stderr"])
        blocks.append(f"<h3>{html.escape(name)}</h3><pre class=\"small-pre\">{html.escape(chr(10).join(text))}</pre>")
    return "\n".join(blocks)


def render_elf_metadata(elf_info):
    if not elf_info:
        return '<p class="notice">No ELF metadata for this file.</p>'

    lines = []
    for key in ("architecture", "bits", "endianness", "elf_type", "entry_point", "stripped"):
        if key in elf_info:
            lines.append(f"{key}: {elf_info[key]}")
    if elf_info.get("security"):
        lines.append("security:")
        for key, value in elf_info["security"].items():
            lines.append(f"  {key}: {value}")
    for key in ("sections", "imports", "functions", "symbols"):
        if elf_info.get(key):
            values = elf_info[key][:100]
            lines.append(f"{key}: " + ", ".join(values))
    return f"<pre class=\"small-pre\">{html.escape(chr(10).join(lines))}</pre>"


def render_file_evidence(report):
    strings = report.get("ascii_strings", [])[:100]
    utf16_strings = report.get("utf16le_strings", [])[:100]
    suspicious = report.get("suspicious_strings", [])[:100]
    decoded = report.get("decoded_candidates", [])
    decoded_text = "\n\n".join(
        f"{item['type']} ({item['confidence']}): {item['reason']}\n{item['preview']}"
        for item in decoded[:10]
    )

    return f"""
<div class="evidence-file">
  <h3>{html.escape(report['filename'])}</h3>
  <div class="evidence-grid">
    <div>Size</div><div>{report['size']} bytes</div>
    <div>SHA-256</div><div>{html.escape(report['sha256'])}</div>
    <div>Type</div><div>{html.escape(report['file_type'])}</div>
    <div>Bytes</div><div>{html.escape(report['byte_summary'])}</div>
    <div>Permissions</div><div>{html.escape(report.get('executable_permissions', 'unknown'))}</div>
  </div>

  <h3>Text Preview</h3>
  <pre class="small-pre">{html.escape(report.get('text_preview') or 'No text preview.')}</pre>

  <h3>Hex Preview</h3>
  <pre class="small-pre">{html.escape(report.get('hex_preview') or 'No hex preview.')}</pre>

  <h3>Possible Decoded Forms</h3>
  <pre class="small-pre">{html.escape(decoded_text or 'No obvious hex/base64/url/rot13 decoded form.')}</pre>

  <h3>Extracted Strings</h3>
  {render_list_items(strings)}

  <h3>Suspicious Strings</h3>
  {render_list_items(suspicious, 'No suspicious strings.')}

  <h3>UTF-16LE Strings</h3>
  {render_list_items(utf16_strings, 'No UTF-16LE strings.')}

  <h3>ELF Metadata</h3>
  {render_elf_metadata(report.get('elf_info', {}))}

  <h3>Tool Outputs</h3>
  {render_tool_outputs(report.get('tool_outputs', {}))}
</div>
"""


def render_answer_only(analysis):
    """Render the answer-only result: just the flag, or NOT_FOUND.

    Only the local scanner's candidates are considered (no AI call), and no
    per-file evidence (strings/hex/tool output) is rendered so the response
    stays tiny even for large uploads. Only the short candidate list is
    available, collapsed, for context.
    """
    best = select_best_final_flag(analysis["flag_candidates"])

    if best:
        box = f"""
<div class="answer-box found">
  <p class="answer-label">Flag</p>
  <div class="answer-value">{html.escape(best["value"])}</div>
</div>
"""
    else:
        box = """
<div class="answer-box not-found">
  <p class="answer-label">Flag</p>
  <div class="answer-value">NOT_FOUND</div>
</div>
"""

    return f"""
{box}
<details class="report-details">
  <summary>Show local flag candidates (no full evidence in this mode)</summary>
  {render_flag_candidates(analysis)}
</details>
"""


def render_local_evidence(analysis):
    reports = analysis.get("file_reports") or [analysis]
    files = "\n".join(
        f"- {report['filename']} | {report['size']} bytes | {report['file_type']} | {report['sha256']}"
        for report in reports[:100]
    )
    if len(reports) > 100:
        files += f"\n...[{len(reports) - 100} more file(s)]"

    evidence = "\n".join(render_file_evidence(report) for report in reports[:12])
    if len(reports) > 12:
        evidence += f"<p class=\"notice\">File evidence truncated in UI: {len(reports) - 12} more file(s).</p>"

    return f"""
<h2 class="result-title">Local Evidence</h2>
<h3>Uploaded Files</h3>
<pre class="small-pre">{html.escape(files)}</pre>
{render_flag_candidates(analysis)}
{evidence}
"""


def save_full_report(evidence_html):
    """Persist the full Local Evidence HTML to reports/result.html.

    Returns a URL path the running server can serve back to the browser, so
    large results never have to be inlined into the response body.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    target = REPORTS_DIR / REPORT_FILENAME
    target.write_text(page(evidence_html), encoding="utf-8")
    return f"/reports/{REPORT_FILENAME}"


def render_local_evidence_section(analysis):
    """Render Local Evidence, saving to disk instead of inlining once it gets too big.

    A huge inline response is what triggers the browser-side connection drop
    this feature is meant to fix, so anything past MAX_INLINE_EVIDENCE_BYTES
    is written to reports/result.html and only linked from the page.
    """
    evidence_html = render_local_evidence(analysis)
    byte_size = len(evidence_html.encode("utf-8"))
    if byte_size <= MAX_INLINE_EVIDENCE_BYTES:
        return evidence_html

    link = save_full_report(evidence_html)
    print(f"[WEB] local evidence too large to inline ({byte_size} bytes) -> saved to {link}")
    return f"""
<h2 class="result-title">Local Evidence</h2>
<p class="warning">
  Local Evidence가 너무 커서({byte_size:,} bytes) 화면에 전체를 표시하지 않습니다.
  전체 리포트: <a href="{link}" target="_blank" rel="noopener">{html.escape(link)}</a>
</p>
{render_flag_candidates(analysis)}
"""


def get_usage_value(usage, name):
    if usage is None:
        return None
    if hasattr(usage, name):
        return getattr(usage, name)
    if isinstance(usage, dict):
        return usage.get(name)
    return None


def render_api_usage(usage, prompt_text):
    prompt_tokens = get_usage_value(usage, "prompt_tokens")
    completion_tokens = get_usage_value(usage, "completion_tokens")
    total_tokens = get_usage_value(usage, "total_tokens")
    estimated_prompt_tokens = max(1, len(prompt_text) // 4)

    if total_tokens is None:
        return f"""
<h2 class="result-title">API Usage</h2>
<div class="usage-box">
  <strong>실제 token usage:</strong> API 응답에 usage 정보가 포함되지 않았습니다.<br>
  <strong>프롬프트 추정:</strong> 약 {estimated_prompt_tokens:,} tokens<br>
  <span>정확한 사용량은 NVIDIA/Z.AI 대시보드의 usage 화면에서 확인하세요.</span>
</div>
"""

    return f"""
<h2 class="result-title">API Usage</h2>
<div class="usage-box">
  <strong>prompt tokens:</strong> {prompt_tokens}<br>
  <strong>completion tokens:</strong> {completion_tokens}<br>
  <strong>total tokens:</strong> {total_tokens}
</div>
"""


class CTFWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            self._handle_get()
        except CLIENT_DISCONNECT_ERRORS as error:
            print(f"[WARN] Client disconnected during GET {self.path}: {error}")
        except Exception:
            print(f"[ERROR] Unhandled exception while handling GET {self.path}:")
            traceback.print_exc()

    def _handle_get(self):
        if self.path in ("/", "/index.html"):
            self.respond_html(form_page())
            return
        if self.path.startswith("/reports/"):
            self._serve_report_file()
            return
        self.send_error(404)

    def _serve_report_file(self):
        """Serve files saved by save_full_report(), e.g. /reports/result.html."""
        rel_path = urllib.parse.unquote(self.path[len("/reports/"):])
        reports_root = REPORTS_DIR.resolve()
        target = (REPORTS_DIR / rel_path).resolve()
        try:
            target.relative_to(reports_root)
        except ValueError:
            self.send_error(404)
            return
        if not target.is_file():
            self.send_error(404)
            return

        data = target.read_bytes()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except CLIENT_DISCONNECT_ERRORS as error:
            print(f"[WARN] Client disconnected while serving {self.path}: {error}")

    def do_POST(self):
        try:
            self._handle_analyze()
        except CLIENT_DISCONNECT_ERRORS as error:
            print(f"[WARN] Client disconnected during POST {self.path}: {error}")
        except Exception:
            print("[ERROR] Unhandled exception while handling /analyze request:")
            traceback.print_exc()
            self.respond_html(
                form_page('<p class="error">서버 내부 오류가 발생했습니다. 터미널 로그를 확인해주세요. 서버는 계속 실행 중입니다.</p>'),
                status=500,
            )

    def _handle_analyze(self):
        if self.path != "/analyze":
            self.send_error(404)
            return

        print("[WEB] analyze request received")

        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD_BYTES:
            self.respond_html(
                form_page('<p class="error">업로드가 너무 큽니다. 폴더 전체 최대 32MB까지 지원합니다.</p>'),
                status=413,
            )
            return

        try:
            body = self.rfile.read(length)
            fields_raw, files = parse_multipart_form(self.headers, body)
        except ValueError as error:
            self.respond_html(form_page(f'<p class="error">{html.escape(str(error))}</p>'), status=400)
            return

        if "challenge_files" not in files:
            self.respond_html(form_page('<p class="error">문제 폴더를 선택해주세요.</p>'), status=400)
            return

        uploaded_files = [
            file_item
            for file_item in files["challenge_files"]
            if file_item["filename"] and len(file_item["content"]) > 0
        ]
        if not uploaded_files:
            self.respond_html(form_page('<p class="error">분석할 파일이 없습니다.</p>'), status=400)
            return

        print(f"[WEB] files uploaded: {len(uploaded_files)}")

        only_flag = bool(fields_raw.get("only_flag"))
        print(f"[WEB] only_flag mode: {only_flag}")

        print("[WEB] local analysis started")
        local_analysis = analyze_uploaded_files(uploaded_files)
        print("[WEB] local analysis finished")

        if only_flag:
            print("[WEB] ai analysis skipped")
            self._respond_result(render_answer_only(local_analysis))
            return

        analysis_text = format_analysis_for_prompt(local_analysis)

        fields = {
            "filename": f"{len(uploaded_files)} file(s) from uploaded folder",
            "category": fields_raw.get("category") or "reversing",
        }

        assistant = CTFAssistant()
        if not assistant.is_ready():
            self.respond_html(
                form_page('<p class="error">API 설정이 없습니다. .env 파일에 ZAI_API_KEY를 설정해주세요.</p>'),
                status=500,
            )
            return

        prompt = build_ai_prompt(analysis_text, fields)
        print("[WEB] ai analysis started")
        answer = assistant.ask(prompt, timeout=AI_TIMEOUT_SECONDS)
        if answer is None:
            if isinstance(assistant.last_error, APITimeoutError):
                print(f"[WEB] ai analysis timed out after {AI_TIMEOUT_SECONDS}s")
                answer = AI_TIMEOUT_MESSAGE
            else:
                print(f"[WEB] ai analysis failed: {assistant.last_error}")
                answer = "API 호출에 실패했습니다. 터미널의 오류 메시지를 확인해주세요."
        else:
            print("[WEB] ai analysis finished")

        escaped_local = html.escape(truncate_text(analysis_text, MAX_PROMPT_EVIDENCE_DISPLAY))
        escaped_answer = html.escape(answer)
        local_evidence_html = render_local_evidence_section(local_analysis)
        usage_html = render_api_usage(assistant.last_usage, prompt)
        result_html = f"""
{local_evidence_html}
<hr>
{usage_html}
<hr>
<h2 class="result-title">AI Analysis</h2>
<pre>{escaped_answer}</pre>
<hr>
<details class="report-details">
  <summary>Show prompt evidence sent to AI</summary>
  <pre>{escaped_local}</pre>
</details>
"""
        self._respond_result(result_html)

    def _respond_result(self, result_html):
        encoded_len = len(result_html.encode("utf-8"))
        print(f"[WEB] response size: {encoded_len} bytes")
        self.respond_html(form_page(result_html))

    def respond_html(self, body, status=200):
        encoded = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            print("[WEB] response sent")
        except CLIENT_DISCONNECT_ERRORS as error:
            print(f"[WARN] Client disconnected while sending response: {error}")
            return


def run_server():
    server = ThreadingHTTPServer((HOST, PORT), CTFWebHandler)
    print(f"CTF Z.AI Flag Extractor UI: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
