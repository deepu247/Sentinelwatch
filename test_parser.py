"""
Test script for Module 2 — Parser.
Run: python3 test_parser.py
"""

from modules.parser import parse_line

test_lines = [
    # Should detect: invalid_user
    "Jun 22 08:07:04 security-lab sshd[24566]: Invalid user fakeuser from 103.147.0.182 port 64503",
    # Should detect: failed_login
    "Jun 22 08:07:04 security-lab sshd[1234]: Failed password for root from 185.220.101.45 port 52341 ssh2",
    # Should be ignored
    "Jun 22 08:07:10 security-lab sudo: ubuntu : TTY=pts/4 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/grep"
]

print("Running parser tests...\n")
for line in test_lines:
    result = parse_line(line)
    if result:
        print(f"[DETECTED] {result}")
    else:
        print(f"[IGNORED]  (not relevant)")

print("\nAll tests done!")
