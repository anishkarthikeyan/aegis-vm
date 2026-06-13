from __future__ import annotations

import argparse
import sys

from aegis_vm import __version__
from aegis_vm.exceptions import SyntaxInspectionError
from aegis_vm.inspector import inspect_code, inspect_file
from aegis_vm.policy import SafetyPolicy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis-vm",
        description="Inspect Python source for structural safety violations.",
    )
    parser.add_argument("path", nargs="?", help="Python file to inspect")
    parser.add_argument(
        "-c",
        "--code",
        help="Inspect a Python source string instead of a file",
    )
    parser.add_argument(
        "--lenient",
        action="store_true",
        help="Use the lenient safety policy",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    policy = SafetyPolicy.lenient() if args.lenient else SafetyPolicy.strict()

    if args.code is not None:
        source = args.code
        filename = "<string>"
        inspect = lambda: inspect_code(source, policy=policy, filename=filename)
    elif args.path is not None:
        inspect = lambda: inspect_file(args.path, policy=policy)
    else:
        parser.error("Provide a file path or --code string to inspect.")

    try:
        result = inspect()
    except SyntaxInspectionError as exc:
        print(f"syntax error: {exc}", file=sys.stderr)
        return 2

    for finding in result.findings:
        print(finding)

    if result.safe:
        print("SAFE")
        return 0

    print("UNSAFE", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
