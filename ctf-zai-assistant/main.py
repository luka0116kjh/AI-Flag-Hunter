from ctf_assistant import CTFAssistant


EXIT_COMMANDS = {"exit", "quit", "종료"}


def ask_input(label):
    """Read one field from the terminal."""
    return input(f"{label}: ").strip()


def build_initial_prompt(challenge_info):
    """Turn the user's form-style input into one clear prompt for the model."""
    return f"""
Please analyze this authorized CTF challenge.
If the category or request is related to reversing, reverse engineering, rev,
crackme, binary analysis, or mobile reversing, prioritize a reversing-focused
workflow.

Challenge name: {challenge_info["name"]}
Category: {challenge_info["category"]}
Environment: {challenge_info["environment"]}
Provided files/materials: {challenge_info["materials"]}
My current progress: {challenge_info["progress"]}
Request: {challenge_info["request"]}

Use progressive disclosure by default. Start with analysis, attack points,
verification steps, and practical next actions. Do not reveal a full final
exploit unless I explicitly ask for "show final exploit".
""".strip()


def collect_challenge_info():
    """Collect the first challenge description from the user."""
    print("Enter challenge information.\n")
    return {
        "name": ask_input("Challenge name"),
        "category": ask_input("Category"),
        "environment": ask_input("Environment"),
        "materials": ask_input("Provided files/materials"),
        "progress": ask_input("My current progress"),
        "request": ask_input("Request"),
    }


def run_cli():
    """Run the interactive terminal assistant."""
    print("=== CTF Z.AI Assistant ===\n")

    assistant = CTFAssistant()
    if not assistant.is_ready():
        return

    challenge_info = collect_challenge_info()
    initial_prompt = build_initial_prompt(challenge_info)

    print("\n--- AI Analysis ---\n")
    assistant.stream_ask(initial_prompt)

    print("\nYou can now ask follow-up questions.")
    print('Progressive commands: "hint only", "reveal a little more", "show final exploit"')
    print('Type "exit", "quit", or "종료" to stop.\n')

    while True:
        user_message = input("You: ").strip()
        if user_message.lower() in EXIT_COMMANDS:
            print("Good luck with the challenge.")
            break

        if not user_message:
            continue

        print("\nAssistant:\n")
        assistant.stream_ask(user_message)
        print()


if __name__ == "__main__":
    run_cli()
