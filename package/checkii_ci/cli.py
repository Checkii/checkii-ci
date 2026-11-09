"""``checkii-ci``: assess, findings, version."""

from __future__ import annotations

import argparse
import re
import sys

from checkii_ci import __version__, assess, findings
from checkii_ci.assess import EXIT_ERROR


SECRET_NAMES = re.compile(r"token|secret|passw(or)?d|(^|[^a-z])key($|[^a-z])")
# Flags that legitimately carry "key" in their name and never a secret value.
SECRET_NAME_EXCEPTIONS = {"idempotency-key", "idempotency_key"}
QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'")


def _option_name(argument: str) -> str | None:
    """The option name of ``-x``, ``--x`` or ``--x=value`` forms, else None."""
    if len(argument) < 2 or not argument.startswith("-") or argument == "--":
        return None
    name = argument.lstrip("-").split("=", 1)[0].lower()
    return name or None


def _looks_secret(name: str) -> bool:
    return name not in SECRET_NAME_EXCEPTIONS and bool(SECRET_NAMES.search(name))


class Parser(argparse.ArgumentParser):
    """An argparse parser whose errors never repeat raw argument values.

    argparse's own messages quote the offending input ("unrecognized
    arguments: -token=...", "invalid choice: '...'"), which would copy a
    misplaced secret into a CI log. Only option names survive here.
    """

    def error(self, message: str):
        if message.startswith("unrecognized arguments:"):
            names = []
            for argument in message.split(":", 1)[1].split():
                name = _option_name(argument)
                if name:
                    names.append(("--" if argument.startswith("--") else "-") + name)
            message = "unrecognized arguments (values withheld): " + (
                " ".join(names) or "<positional values>"
            )
        else:
            message = QUOTED.sub("<value>", message)
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="checkii-ci",
        description=(
            "Fail-closed pull-request assessment through the Checkii control plane. "
            "The API token is read from CHECKII_API_TOKEN and is never a flag."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    assessment = commands.add_parser(
        "assess",
        help="run an immutable base-to-head repository assessment",
        description=(
            "Exit codes: 0 passed, 1 threshold reached, 2 error (including network "
            "failure), 3 policy denied, 4 cancelled or expired."
        ),
    )
    assess.add_assess_arguments(assessment)
    listing = commands.add_parser(
        "findings", help="fetch and print the findings bound to a job"
    )
    findings.add_findings_arguments(listing)
    commands.add_parser("version", help="print the client version")
    return parser


def _refuses_secret_flags(argv: list[str]) -> bool:
    """No flag may carry a secret; refuse before argparse can echo it.

    Both hyphen forms and the ``=value`` form are checked, so ``-token=x``
    never reaches argparse's "unrecognized arguments" message.
    """
    return any(
        _looks_secret(name) for argument in argv if (name := _option_name(argument))
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _refuses_secret_flags(arguments):
        print(
            "checkii-ci: the API token is read from CHECKII_API_TOKEN; "
            "it is never accepted as a command-line flag",
            file=sys.stderr,
        )
        return EXIT_ERROR
    args = build_parser().parse_args(arguments)
    if args.command == "version":
        print(f"checkii-ci {__version__}")
        return 0
    if args.command == "findings":
        return findings.run(args)
    return assess.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
