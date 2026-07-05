import subprocess


def run(args: list[str], input_text: str | None = None) -> str:
    result = subprocess.run(
        args, input=input_text, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()
