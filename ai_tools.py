#!/usr/bin/env python3

import re
import argparse
import os
from pathlib import Path
from openai import OpenAI

# =========================
# DEFAULT CONFIG
# =========================

DEFAULT_LOG_FILE = Path("./logs/nginx_error.log")
DEFAULT_MAX_LINES = 300
MODEL_NAME = "gpt-4o-mini"  # lightweight, fast, cost-effective

# =========================
# LOG READING
# =========================

def read_log_file(log_path: Path, max_lines: int) -> str:
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    return "".join(lines[-max_lines:])

# =========================
# MASKING FUNCTIONS
# =========================

def mask_ip_addresses(text: str) -> str:
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    return re.sub(ip_pattern, "x.x.x.x", text)

def mask_credentials(text: str) -> str:
    patterns = [
        r"(password\s*=\s*)(\S+)",
        r"(passwd\s*=\s*)(\S+)",
        r"(token\s*=\s*)(\S+)",
        r"(api_key\s*=\s*)(\S+)"
    ]
    for pattern in patterns:
        text = re.sub(pattern, r"\1****", text, flags=re.IGNORECASE)
    return text

def sanitize_logs(text: str) -> str:
    text = mask_ip_addresses(text)
    text = mask_credentials(text)
    return text

# =========================
# PROMPT BUILDER
# =========================

def build_prompt(log_data: str) -> str:
    return f"""
You are a senior Linux infrastructure engineer.

Context:
These are Nginx error logs from a production Ubuntu 22.04 server.

Tasks:
1. Identify the main error types.
2. Highlight recurring or critical errors.
3. Explain likely root causes.
4. Suggest clear remediation steps.

Output format:
- Error summary
- Root causes
- Recommended actions

Logs:
{log_data}
""".strip()

# =========================
# AI CALL
# =========================

def analyze_with_ai(prompt: str) -> str:
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        raise EnvironmentError("AI_API_KEY environment variable not set")

    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a helpful infrastructure assistant."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )

    return response.choices[0].message.content.strip()

# =========================
# ARGUMENT PARSER
# =========================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="AI-assisted Nginx error log analyzer"
    )

    parser.add_argument(
        "--logfile",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to Nginx error log file"
    )

    parser.add_argument(
        "--lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        help="Number of log lines to analyze"
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis and only show prompt"
    )

    return parser.parse_args()

# =========================
# MAIN
# =========================

def main():
    args = parse_arguments()

    try:
        raw_logs = read_log_file(args.logfile, args.lines)
        safe_logs = sanitize_logs(raw_logs)
        prompt = build_prompt(safe_logs)

        if args.no_ai:
            print("\n====== AI PROMPT PREVIEW ======\n")
            print(prompt)
        else:
            print("\n====== AI ANALYSIS ======\n")
            analysis = analyze_with_ai(prompt)
            print(analysis)

        print("\n====== END ======\n")

    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
