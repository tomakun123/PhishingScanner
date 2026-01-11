import argparse
from pathlib import Path
import sys

def scan_command(eml_path: str):
    path = Path(eml_path).expanduser()

    if path.suffix.lower() != ".eml":
        raise ValueError("File must have .eml extension")

    if not path.exists():
        raise FileNotFoundError("File not found")

    print("Scan target:", path.resolve())
    # Placeholder: actual scan will go here

def main():
    parser = argparse.ArgumentParser(
        description="PhishLab - Email phishing detection tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a .eml email file"
    )
    scan_parser.add_argument(
        "eml_path",
        help="Path to .eml file"
    )

    args = parser.parse_args()

    try:
        if args.command == "scan":
            scan_command(args.eml_path)

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
