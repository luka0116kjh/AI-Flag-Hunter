import os
import sys

from dotenv import load_dotenv


# OpenAI-compatible API defaults for direct Z.AI access.
DEFAULT_BASE_URL = "https://api.z.ai/api/paas/v4/"
DEFAULT_MODEL = "glm-5.2"


def load_config():
    """Load API configuration from a local .env file."""
    load_dotenv()

    api_key = os.getenv("ZAI_API_KEY")
    base_url = os.getenv("ZAI_BASE_URL", DEFAULT_BASE_URL)
    model = os.getenv("ZAI_MODEL", DEFAULT_MODEL)

    if not api_key:
        print(
            "\n[Configuration error]\n"
            "ZAI_API_KEY is missing.\n\n"
            "Beginner-friendly setup:\n"
            "1. Copy .env.example to .env\n"
            "2. Open .env\n"
            "3. Replace your_zai_api_key_here with your real Z.AI API key\n\n"
            "Example:\n"
            "ZAI_API_KEY=sk-your-real-key\n\n"
            "If you are using an OpenAI-compatible gateway such as NVIDIA,\n"
            "also set ZAI_BASE_URL and ZAI_MODEL in .env.\n",
            file=sys.stderr,
        )
        return None

    return {
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
    }
