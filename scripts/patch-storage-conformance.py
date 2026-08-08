#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
"""
Wire the exported `Storage` conformance harness into the two files it does NOT own.

The harness itself (crates/oauth-as/src/storage_conformance.rs, its unit tests in
src/tests/storage_conformance.rs, and the broken-store self-test in
tests/storage_conformance_selftest.rs) is written directly. Everything it needs from a file owned
by another change lives here, so the two halves can be reviewed and applied independently.

Rules this script holds itself to:
  * every edit is anchored on surrounding TEXT, never on a line number;
  * an anchor that is not found EXACTLY ONCE in its file is a hard failure and NOTHING is written;
  * it refuses to run twice (each edit carries a marker whose presence means "already applied");
  * phase 1 checks every edit in every file, phase 2 writes, so a half-applied tree is not a state
    this script can produce.

Run from anywhere:  python3 scripts/patch-storage-conformance.py [--repo /path/to/oauth-as]

WHAT IT CHANGES AND WHY, file by file:

crates/oauth-as/Cargo.toml
  One new cargo feature, `test-util`, OFF by default and pulling NO dependency. It exists so a
  HOST can run the storage contract against its OWN implementation from its OWN test suite; a
  default build gets none of it.

crates/oauth-as/src/lib.rs
  Declares the module behind that feature. Deliberately NOT re-exported at the crate root, unlike
  every other module here: `Violation`, `CHECKS` and `Task` are generic words that mean something
  only next to the thing they describe, and this surface is one a host names once in a test rather
  than reaches for constantly. `oauth_as::storage_conformance::StorageConformance` says what it is.
"""

import argparse
import os
import sys

REPO_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (relative path, marker meaning "already applied", [(anchor, replacement), ...])
EDITS = [
    (
        "crates/oauth-as/Cargo.toml",
        "test-util = []",
        [
            (
                "token-exchange = []\n",
                "token-exchange = []\n"
                "# A RUNNABLE conformance harness for the `Storage` contract, for a HOST to call from its\n"
                "# own test suite against its own implementation (crates/oauth-as/src/storage_conformance.rs).\n"
                "#\n"
                "# It is a cargo feature rather than a separate crate because it tests a trait whose\n"
                "# semantics live here, and because a host already depends on this crate. OFF by default and\n"
                "# it adds NO dependency: the concurrency primitives it needs are hand-written over std, so a\n"
                "# default build pays nothing for it, in code or in tree.\n"
                "#\n"
                "# WHY IT EXISTS AT ALL: `Storage::take_*` is documented as an ATOMIC remove-and-return, and\n"
                "# that clause is the only thing making single-use artifacts single use. A host that\n"
                "# implements it as read-then-delete compiles, type-checks, and passes a single-node test\n"
                "# suite, while a multi-node deployment silently double-spends refresh tokens and stops\n"
                "# detecting authorization code replay. Nothing inside this crate can see that, so the check\n"
                "# has to be runnable where the host's store is.\n"
                "test-util = []\n",
            )
        ],
    ),
    (
        "crates/oauth-as/src/lib.rs",
        "pub mod storage_conformance;",
        [
            (
                "pub mod server;\npub mod store;\n",
                "pub mod server;\n"
                "/// A runnable conformance harness for the [`store::Storage`] contract, behind the\n"
                "/// `test-util` cargo feature (off by default), for a HOST to run against its OWN store.\n"
                "///\n"
                "/// The contract this crate depends on most is that `take_*` is an ATOMIC\n"
                "/// remove-and-return; a read-then-delete implementation of it passes every single-node\n"
                "/// test a host is likely to write and double-spends refresh tokens on two nodes. Nothing\n"
                "/// in this crate can detect that, which is why the check ships as something the host runs.\n"
                "///\n"
                "/// Not re-exported at the crate root on purpose: `Violation` and `CHECKS` are generic\n"
                "/// words that only mean something next to the thing they describe, and a host names this\n"
                "/// surface once, in a test.\n"
                '#[cfg(feature = "test-util")]\n'
                "pub mod storage_conformance;\n"
                "pub mod store;\n",
            )
        ],
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=REPO_DEFAULT, help="repository root")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    # PHASE 1: read and check everything. Nothing is written until every edit in every file has
    # been proven applicable.
    planned = []
    for rel, marker, edits in EDITS:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            print(f"FAIL: {rel} does not exist under {repo}", file=sys.stderr)
            return 1
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if marker in text:
            print(
                f"FAIL: {rel} already contains the marker {marker!r}: this patch has already "
                f"been applied, and applying it twice is not something it will do.",
                file=sys.stderr,
            )
            return 1
        for anchor, replacement in edits:
            count = text.count(anchor)
            if count != 1:
                print(
                    f"FAIL: in {rel}, the anchor\n---\n{anchor}---\nwas found {count} times, "
                    f"expected exactly 1. The file has moved underneath this patch; fix the "
                    f"anchor by hand rather than guessing.",
                    file=sys.stderr,
                )
                return 1
            text = text.replace(anchor, replacement, 1)
        planned.append((path, rel, text))

    # The harness's own files are written directly rather than by this script, so a tree with the
    # wiring and without the module would not compile. Checked here so the failure names the
    # missing file instead of arriving as a rustc error.
    for rel in (
        "crates/oauth-as/src/storage_conformance.rs",
        "crates/oauth-as/src/tests/storage_conformance.rs",
        "crates/oauth-as/tests/storage_conformance_selftest.rs",
    ):
        if not os.path.isfile(os.path.join(repo, rel)):
            print(
                f"FAIL: {rel} is missing. This patch only wires the harness in; the harness "
                f"itself belongs to the same change and must be present first.",
                file=sys.stderr,
            )
            return 1

    # PHASE 2: write.
    for path, rel, text in planned:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"patched {rel}")
    print("ok: storage conformance harness host-file edits applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
