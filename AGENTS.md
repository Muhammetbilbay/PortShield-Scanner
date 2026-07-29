# PortShield Scanner — AI Agent Guidance

## What this project is

PortShield Scanner is a Python-based TCP/UDP port scanner and banner grabber with multi-threaded and asynchronous scanning support. It is written in Turkish and designed as a CLI tool for recon/security scanning.

## Key files

- `scanner.py` — main application logic and CLI entrypoint
- `README.md` — usage examples and project overview
- `requirements.txt` — dependency list (`colorama==0.4.6`)
- `rapor.html` / `test_output.json` / `test_phase4.json` — example output files, not source code

## How to run

- Install dependencies: `pip install -r requirements.txt`
- Run the scanner: `python scanner.py -t <target> [-p <ports>] [--output <file>]`
- Example: `python scanner.py -t scanme.nmap.org -p 22,80,443 --output sonuc.json`

## Important behavior and conventions

- The CLI is Turkish-first: help text, status messages, and warnings are in Turkish.
- Output is UTF-8-safe; file writes use `encoding='utf-8'` and the HTML report includes `<meta charset="UTF-8">`.
- Threading and async scanning are combined: `asyncio.run(async_scan_manager(...))` drives the scan, while socket operations may run in thread executor for UDP or sync fallback behavior.
- `--udp` enables UDP scanning; otherwise TCP is used.
- `--top-ports` selects a pre-defined list of popular ports.
- `save_results()` supports `.json`, `.html`, and default text output.

## What agents should preserve

- Preserve Turkish strings and user-facing messages unless asked to internationalize.
- Keep existing Unicode/UTF-8 handling intact, especially in output generation.
- Respect the current CLI argument names and behavior.
- Avoid introducing external dependencies beyond `requirements.txt` unless the user explicitly approves it.

## When to use this guidance

Use this file when modifying or extending the scanner, improving reports, fixing CLI behavior, or adding new scanning modes. It helps keep changes aligned with the repository’s current structure, language, and output conventions.
