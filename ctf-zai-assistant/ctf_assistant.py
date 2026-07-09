from openai import OpenAI

from config import load_config
from prompts import SYSTEM_PROMPT


class CTFAssistant:
    """Small wrapper around a Z.AI OpenAI-compatible chat API."""

    def __init__(self):
        config = load_config()
        if config is None:
            self.client = None
            self.model = None
        else:
            self.client = OpenAI(
                api_key=config["api_key"],
                base_url=config["base_url"],
            )
            self.model = config["model"]

        # Keep the conversation history so follow-up questions have context.
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
        ]
        self.last_usage = None
        self.last_error = None

    def is_ready(self):
        """Return True when the API client is configured."""
        return self.client is not None

    def ask(self, user_message, timeout=None):
        """Send one message and return the assistant response as text.

        `timeout` (seconds) is forwarded to the underlying API call so a slow
        or hanging endpoint does not block the caller forever. On any failure
        (including timeouts) this returns None and stashes the exception in
        `self.last_error` so callers can tell a timeout apart from other
        errors without this method raising.
        """
        if not self.is_ready():
            return None

        self.last_error = None
        self.messages.append({"role": "user", "content": user_message})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                timeout=timeout,
            )
            self.last_usage = getattr(response, "usage", None)
            answer = response.choices[0].message.content
            self.messages.append({"role": "assistant", "content": answer})
            return answer
        except Exception as error:
            self.messages.pop()
            self.last_usage = None
            self.last_error = error
            print(f"\n[API error] Could not get a response: {error}\n")
            return None

    def stream_ask(self, user_message):
        """Send one message and print the assistant response in real time."""
        if not self.is_ready():
            return None

        self.messages.append({"role": "user", "content": user_message})
        answer_parts = []

        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                stream=True,
            )

            for chunk in stream:
                if not getattr(chunk, "choices", None):
                    continue
                if len(chunk.choices) == 0:
                    continue

                delta = chunk.choices[0].delta
                if delta is None:
                    continue

                content = getattr(delta, "content", None)
                if content:
                    print(content, end="", flush=True)
                    answer_parts.append(content)

            print()
            answer = "".join(answer_parts)
            self.messages.append({"role": "assistant", "content": answer})
            return answer
        except Exception as error:
            self.messages.pop()
            print(f"\n[API error] Could not get a streaming response: {error}\n")
            return None
