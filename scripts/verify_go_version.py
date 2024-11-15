import subprocess
import sys
import os
import re

def error(message, code = 1):
    # print(message, file=sys.stderr)
    sys.exit(code)

def usage():
    return f"Usage: {sys.argv[0]} [target min go version]"

def get_system_go_version():
    which = subprocess.run(
        ["which", "go"],
        capture_output=True,
    )

    if which.returncode:
        error("go: command not found")

    output = subprocess.run(
        ["go", "version"],
        capture_output=True,
        text=True
    )

    pattern = r"\bgo(\d+)\.(\d+)\.(\d+)\b"
    match = re.search(pattern, output.stdout)
    if match:
        major, minor, patch = map(int, match.groups())
        return (major, minor, patch)
    error("System go version doesn't match the go versionning system (goXX.YY.ZZ) !")

def parse_go_semver(entry):
    pattern = r"^go(\d+)\.(\d+)\.(\d+)$"
    match = re.match(pattern, entry)
    if match:
        major, minor, patch = map(int, match.groups())
        return (major, minor, patch)
    error(f"\"{entry}\" doesn't match the go versionning system (goXX.YY.ZZ) !")

def main():
    if len(sys.argv) != 2:
        error(usage(), 1)

    min_version = parse_go_semver(sys.argv[1])
    cur_version = get_system_go_version()

    for i in range(3):
        if cur_version[i] < min_version[i]:
            error(f"Installed go version go{'.'.join((str(i) for i in cur_version))} is older than minimum required version go{'.'.join((str(i) for i in min_version))}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
