import json
import os
import tempfile
from pathlib import Path

from file_analyzer import run_command


SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"
SCRIPT_NAME = "extract_functions.py"


def analyze_with_ghidra(uploaded_files, timeout=60):
    headless = os.getenv("GHIDRA_HEADLESS_PATH", "").strip()
    if not headless:
        return {
            "enabled": False,
            "error": "GHIDRA_HEADLESS_PATH is not set.",
            "files": [],
        }

    script_path = SCRIPT_DIR / SCRIPT_NAME
    if not script_path.exists():
        return {
            "enabled": False,
            "error": f"Ghidra script not found: {script_path}",
            "files": [],
        }

    results = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        project_dir = temp_root / "project"
        input_dir = temp_root / "input"
        output_dir = temp_root / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        for index, uploaded_file in enumerate(uploaded_files):
            input_path = input_dir / f"sample_{index}_{Path(uploaded_file['filename']).name}"
            input_path.write_bytes(uploaded_file["content"])
            output_path = output_dir / f"result_{index}.json"
            command = [
                headless,
                str(project_dir),
                "ctf_scan",
                "-import",
                str(input_path),
                "-scriptPath",
                str(SCRIPT_DIR),
                "-postScript",
                SCRIPT_NAME,
                str(output_path),
                "-deleteProject",
            ]
            command_result = run_command(command, timeout=timeout, max_output=12000)
            parsed = {}
            if output_path.exists():
                try:
                    parsed = json.loads(output_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    parsed = {"error": str(error)}
            results.append({
                "filename": uploaded_file["filename"],
                "command_result": command_result,
                "analysis": parsed,
            })

    return {
        "enabled": True,
        "files": results,
    }
