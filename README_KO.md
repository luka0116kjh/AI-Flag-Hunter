[English](README.md) | [한국어](README_KO.md)

---

# CTF Z.AI Assistant

CTF 문제 풀이를 위한 Python 보조 도구입니다. 터미널 CLI와 간단한 웹 UI를 포함하고 있습니다. OpenAI SDK 호환 인터페이스를 통해 Z.AI API를 활용하며, 취약점 분석, 공격 포인트 탐색, 풀이 전략 수립, 페이로드 아이디어 제안, 스크립트 초안 작성, 리버싱 중심의 파일 분석 등을 지원합니다.

본 도구는 단계적 정보 공개(Progressive Disclosure) 방식을 지원하므로 다음과 같이 요청할 수 있습니다:

- `hint only` (힌트만 요청)
- `reveal a little more` (조금 더 자세한 정보 요청)
- `show final exploit` (최종 익스플로잇 공개)

> **주의:** 본 도구는 CTF, 워게임, 로컬 랩 환경 및 승인된 보안 테스트 목적으로만 사용해야 합니다.

## 설치 방법

```bash
cd ctf-zai-assistant
python -m venv .venv

.\.venv\Scripts\Activate.ps1

source .venv/bin/activate
