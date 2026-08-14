#!/usr/bin/env python3
"""The version in Cargo.toml must have a DATED section in CHANGELOG.md.

This gate exists because 0.9.1 published to crates.io on 2026-08-13 while CHANGELOG.md still
said `## [0.9.1] - unreleased`. Nothing caught it: CHANGELOG.md is not in the crate tarball, so
`cargo publish --dry-run` never looks at it, and no other job read the file at all. The result
was a repository whose own changelog said the currently-published version had not been released.

The file's convention is the one Keep a Changelog specifies and that 0.9.0 already followed: a
DATE means released, the literal word `unreleased` means not yet. So the property worth holding
is not "the version is mentioned somewhere" -- a heading exists either way, which is exactly why
reading for the heading would have passed on the broken file. It is that the section for the
version being built carries a real ISO date.

Checked on dev, qa AND publish rather than only at the publish gate: a release note is written
long before it is published, and a gate that only fires at the end tells you on the worst day.
"""

import datetime
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"

# `## [0.9.2] - 2026-08-14` or `## [0.9.2] - unreleased`. The trailer is captured loosely on
# purpose: anything that is not a date must be REPORTED, not silently treated as absent. A
# stricter pattern would simply fail to match a malformed line and fall through to "no section
# for this version", which names the wrong defect.
HEADING = re.compile(r"^##\s*\[(?P<version>[^\]]+)\]\s*-\s*(?P<trailer>.+?)\s*$", re.MULTILINE)

# A date MAY carry a parenthetical, and two real headings do: `0.9.0-rc.1` is marked a superseded
# development snapshot and `0.1.0` is marked built-but-not-published. Both are dated and both are
# honest, so anchoring on `^\d{4}-\d{2}-\d{2}$` rejected them -- the first version of this gate
# did exactly that and called two correct lines defects. The date must still come FIRST, so
# `unreleased (soon)` is not quietly accepted by loosening.
ISO_DATE = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})(?:\s*\(.*\))?$")


def manifest_version() -> str:
    """Ask cargo, not a regex over Cargo.toml -- the manifest is what actually publishes."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    import json

    packages = json.loads(out)["packages"]
    return next(p["version"] for p in packages if p["name"] == "oauth-as")


def main() -> int:
    version = manifest_version()
    text = CHANGELOG.read_text(encoding="utf-8")

    sections = {m.group("version"): m.group("trailer") for m in HEADING.finditer(text)}
    if not sections:
        print("::error::CHANGELOG.md has no `## [version] - date` headings at all", file=sys.stderr)
        return 1

    if version not in sections:
        print(
            f"::error::crates/oauth-as/Cargo.toml says {version}, but CHANGELOG.md has no "
            f"`## [{version}]` section. Found: {', '.join(sorted(sections))}",
            file=sys.stderr,
        )
        return 1

    trailer = sections[version]
    if not ISO_DATE.match(trailer):
        print(
            f"::error::CHANGELOG.md says `## [{version}] - {trailer}`. The version that is about "
            f"to be built and published must carry an ISO date (YYYY-MM-DD), not '{trailer}'. "
            f"This is the exact defect 0.9.1 shipped with: published to crates.io while its own "
            f"changelog section still said unreleased.",
            file=sys.stderr,
        )
        return 1

    try:
        datetime.date.fromisoformat(trailer)
    except ValueError:
        print(f"::error::`## [{version}] - {trailer}` is not a real calendar date", file=sys.stderr)
        return 1

    # Every version BELOW the current one is already out. A released version left on
    # `unreleased` is the 0.9.1 bug sitting in history, so it fails here too rather than
    # being tidied up only for whichever version happens to be current.
    stale = sorted(v for v, t in sections.items() if v != version and not ISO_DATE.match(t))
    if stale:
        print(
            f"::error::these CHANGELOG.md sections are not the version being built and are still "
            f"undated, so they claim a shipped version was never released: {', '.join(stale)}",
            file=sys.stderr,
        )
        return 1

    print(f"CHANGELOG.md: {version} is dated {trailer}, and no other section is left undated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
