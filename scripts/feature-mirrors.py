#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (C) 2026 Matthew Jackson
#
# THE CARGO FEATURE LIST HAS FOUR HAND-MAINTAINED MIRRORS, AND THIS IS WHAT CHECKS THEM.
#
# `[features]` in crates/oauth-as/Cargo.toml is the source of truth. Four other places restate
# it, none of them derived from it, and a feature added to the crate and not to them escapes a
# gate silently:
#
#   1. .github/workflows/dev.yml, the `tests (every feature EXCEPT the ES256 backend)` step. The
#      ONLY configuration in which "no ES256 backend installed" is ever executed. A feature missing
#      here is a feature whose no-backend behaviour nobody runs.
#   2. .github/workflows/qa.yml, the same step again, on the promotion branch.
#   3. .github/workflows/publish.yml, the same step a THIRD time, and the one that matters most:
#      it is the last gate before an irreversible crates.io publish. This header said "three" and
#      listed two workflows until 2026-08-12, while publish.yml carried the list inside a step
#      called `Full gate before publish (...)` -- a name this script does not grep for, in a file
#      this script did not read. So the count was wrong, the coverage was wrong, and the one place
#      a stale matrix cannot be fixed after the fact was the place nothing checked. The step there
#      has been split out and renamed to match; keep all three named identically.
#   4. scripts/size-probe/Cargo.toml, the `f-<feature>` mirrors, plus the ALL_FEATURES line in
#      scripts/size-report.sh that measures them. A feature missing there is a feature whose
#      linked size nothing budgets.
#
# This repository has already been bitten by exactly this class, twice. The no-backend list once
# omitted `http`, which compiled tests/wire_reachability.rs (`#![cfg(feature = "http")]`) out of
# the one configuration where the metadata document's advertisement can be false, and
# `client_secret_jwt` shipped broken in precisely that configuration. Separately, an example's
# `required-features` drifted from a CI feature list and broke the MCP scanner. The rule was
# written down in a comment both times. A comment is not a check.
#
# THE EXCLUSION IS A RULE, NOT A LIST. The no-backend step deliberately leaves out the ES256
# backend, and the way that is expressed here is: any feature whose transitive closure contains
# `jwt-p256` is a backend feature and is excluded; everything else is required. `jwt` is therefore
# REQUIRED (it is the trait surface and pulls no backend) and `jwt-pkcs8` is excluded without
# anybody naming it, because it enables `jwt-p256`. Writing the exclusions out by hand would have
# added a FOURTH mirror to a script whose whole purpose is to have fewer of them.
#
# Nothing here is skippable. If a mirror cannot be parsed, that is a failure: a drift check that
# quietly compares two empty lists is the same bug one level up.

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRATE_MANIFEST = os.path.join(ROOT, "crates", "oauth-as", "Cargo.toml")
PROBE_MANIFEST = os.path.join(ROOT, "scripts", "size-probe", "Cargo.toml")
SIZE_REPORT = os.path.join(ROOT, "scripts", "size-report.sh")
# The two halves of "this probe row actually measures something": the gated exerciser, and the
# call site that keeps fat LTO from deleting it. See `check_size_probe`.
PROBE_SRC = os.path.join(ROOT, "scripts", "size-probe", "src")
WORKFLOWS = [
    os.path.join(ROOT, ".github", "workflows", "dev.yml"),
    os.path.join(ROOT, ".github", "workflows", "qa.yml"),
    os.path.join(ROOT, ".github", "workflows", "publish.yml"),
]

# The step whose `run:` carries the no-backend feature list, in all three workflows. Named rather
# than pattern-matched so that renaming the step is a loud failure here rather than a check that
# silently stops finding anything to compare.
NO_BACKEND_STEP = "tests (every feature EXCEPT the ES256 backend)"

# The feature that IS the built-in ES256 backend. Anything that reaches it is excluded from the
# no-backend list; see the header.
BACKEND = "jwt-p256"

# The SECOND hand-maintained feature list, unchecked until 0.9.2. See `check_no_rar_step`.
NO_RAR_STEP = "tests (every feature EXCEPT rar, so the RFC 9396 s5 refusals actually run)"

# The feature that step exists to leave OFF, so the `not(feature = "rar")` refusal proofs compile.
EXCLUDED_FROM_NO_RAR = "rar"

problems = []


def fail(message):
    problems.append(message)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def features_of(path):
    """The `[features]` table of a manifest, as {name: [entries]}.

    tomllib when the runner has it (3.11+), and a deliberately strict hand parser when it does
    not: this file's shape is one `name = [...]` per line, and anything else is reported rather
    than skipped, because a feature this parser silently dropped is a feature this check would
    then certify as mirrored everywhere.
    """
    try:
        import tomllib

        with open(path, "rb") as handle:
            table = tomllib.load(handle).get("features", {})
        if not table:
            fail("%s has no [features] table, so there is nothing to check against" % path)
        return table
    except ImportError:
        pass

    table = {}
    in_features = False
    for number, line in enumerate(read(path).splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("["):
            in_features = stripped == "[features]"
            continue
        if not in_features:
            continue
        match = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*\[(.*)\]\s*(#.*)?$', stripped)
        if not match:
            fail(
                "%s:%d: the feature parser does not understand %r. Rather than skip it (and then "
                "certify a feature nobody checked), this check fails: teach the parser or put the "
                "feature on one line." % (path, number, stripped)
            )
            continue
        table[match.group(1)] = re.findall(r'"([^"]+)"', match.group(2))
    if not table:
        fail("%s has no [features] table, so there is nothing to check against" % path)
    return table


def closure(table, seeds):
    """Every feature of THIS manifest that enabling `seeds` turns on.

    `dep:x` and `x/y` entries are not features of this crate and are stepped over; `x/y` may still
    enable the optional dependency `x`, which is not a feature name either.
    """
    seen = set()
    stack = list(seeds)
    while stack:
        name = stack.pop()
        if name in seen or name not in table:
            continue
        seen.add(name)
        for entry in table[name]:
            if entry.startswith("dep:") or "/" in entry:
                continue
            stack.append(entry)
    return seen


def workflow_feature_list(path, step=NO_BACKEND_STEP):
    """The comma-separated feature list of a named step's `cargo test --features`.

    Parsed out of the raw text rather than with a YAML loader on purpose: the sibling step-name
    drift check in qa.yml owns the YAML view of these files, and this one needs the shell command
    inside a block scalar, which is text either way.
    """
    text = read(path)
    if step not in text:
        fail(
            "%s has no step named %r. If it was renamed, rename it in ALL THREE workflows and "
            "update the step constant in scripts/feature-mirrors.py; a drift check that cannot "
            "find what it compares proves nothing." % (path, step)
        )
        return None
    after = text.split(step, 1)[1]
    # The step's own body only: stop at the next step, so a `--features` further down the file
    # (there are several) cannot be mistaken for this one's.
    body = re.split(r'\n\s*- name:', after, maxsplit=1)[0]
    joined = body.replace("\\\n", " ")
    match = re.search(r'--features\s+([A-Za-z0-9_,.\-]+)', joined)
    if not match:
        fail(
            "%s: the %r step has no `--features <list>` to read. The check cannot pass vacuously, "
            "so this is a failure." % (path, step)
        )
        return None
    return [f for f in match.group(1).split(",") if f]


def check_workflows(crate_features):
    backend_features = {
        name
        for name in crate_features
        if name == BACKEND or BACKEND in closure(crate_features, [name])
    }
    required = set(crate_features) - {"default"} - backend_features

    for path in WORKFLOWS:
        listed = workflow_feature_list(path)
        if listed is None:
            continue
        unknown = [f for f in listed if f not in crate_features]
        for name in sorted(unknown):
            fail(
                "%s: the %r step asks for a feature %r that crates/oauth-as/Cargo.toml does not "
                "declare." % (path, NO_BACKEND_STEP, name)
            )
        reached = closure(crate_features, listed)
        for name in sorted(required - reached):
            fail(
                "%s: feature %r is declared in crates/oauth-as/Cargo.toml and the %r step does not "
                "reach it. That step is the ONLY place the no-ES256-backend build is executed, so "
                "%r has no no-backend coverage at all. Add it to that step's --features list."
                % (path, name, NO_BACKEND_STEP, name)
            )
        for name in sorted(reached & backend_features):
            fail(
                "%s: the %r step reaches %r, which enables the ES256 backend %r. The whole point "
                "of that step is that no backend is installed, so this makes it a duplicate of "
                "the --all-features run." % (path, NO_BACKEND_STEP, name, BACKEND)
            )


def check_no_rar_step(crate_features):
    """The SECOND hand-maintained feature list, which nothing checked until 0.9.2.

    WHY THIS EXISTS. Round 12 found that the RFC 9396 section 5 refusals -- the proofs that a
    request carrying `authorization_details` is REFUSED rather than silently ignored when the
    crate cannot represent one -- had never run in any workflow. Two files were gated
    `not(feature = "rar")`, no feature set named anywhere excluded `rar`, and one of them had
    never even been compiled. The fix was this step, whose rule is "--all-features minus rar".

    That made it the second-most load-bearing feature list in the repository, and it was
    hand-maintained with nothing watching it -- the exact defect this script's header describes
    having found once already in publish.yml. Deleting a feature from it left this script printing
    "all mirrored" and exiting 0, which was proven by experiment before this function was written.

    The rule is the mirror image of the no-backend one: every declared feature must be reached
    EXCEPT `rar`, and `rar` must NOT be reached, or the gated refusals do not compile and the step
    is a second copy of the --all-features run.
    """
    required = set(crate_features) - {"default", EXCLUDED_FROM_NO_RAR}

    for path in WORKFLOWS:
        listed = workflow_feature_list(path, NO_RAR_STEP)
        if listed is None:
            continue
        unknown = [f for f in listed if f not in crate_features]
        for name in sorted(unknown):
            fail(
                "%s: the %r step asks for a feature %r that crates/oauth-as/Cargo.toml does not "
                "declare." % (path, NO_RAR_STEP, name)
            )
        reached = closure(crate_features, listed)
        if EXCLUDED_FROM_NO_RAR in reached:
            fail(
                "%s: the %r step reaches %r. The entire purpose of that step is that %r is OFF, "
                "so that the two test files gated `not(feature = \"%s\")` compile and run. With "
                "it on they vanish and the step is a duplicate of the --all-features run, which "
                "is the state that let the RFC 9396 section 5 refusals go unproven until 0.9.1."
                % (
                    path,
                    NO_RAR_STEP,
                    EXCLUDED_FROM_NO_RAR,
                    EXCLUDED_FROM_NO_RAR,
                    EXCLUDED_FROM_NO_RAR,
                )
            )
        for name in sorted(required - reached):
            fail(
                "%s: feature %r is declared in crates/oauth-as/Cargo.toml and the %r step does "
                "not reach it. That step is the ONLY place the RFC 9396 section 5 refusals are "
                "executed, so a build with %r and without %r is never tested. Add it to that "
                "step's --features list."
                % (path, name, NO_RAR_STEP, name, EXCLUDED_FROM_NO_RAR)
            )


def check_size_probe(crate_features):
    probe = features_of(PROBE_MANIFEST)
    for name in sorted(set(crate_features) - {"default"}):
        mirror = "f-" + name
        if mirror not in probe:
            fail(
                "scripts/size-probe/Cargo.toml: feature %r is declared in "
                "crates/oauth-as/Cargo.toml and has no %r mirror, so nothing measures what it "
                "adds to a linked binary and no size budget covers it." % (name, mirror)
            )
            continue
        if ("oauth-as/" + name) not in probe[mirror]:
            fail(
                "scripts/size-probe/Cargo.toml: %r exists but does not enable %r, so the row it "
                "measures is not the feature it is named after."
                % (mirror, "oauth-as/" + name)
            )

    # A MIRROR THAT EXISTS BUT IS NEVER EXERCISED MEASURES A LIE, which is the one failure the
    # probe was built to prevent. `size-probe/src/main.rs`'s own header says it: "a probe that only
    # names a type... measures the feature at close to zero and reports a lie". Under
    # `lto = "fat"`, code no call site reaches is deleted outright, so a row whose exerciser is
    # missing measures the feature at roughly nothing and budgets nothing -- and the size gate goes
    # GREEN, because a row that measures nothing is comfortably inside any budget.
    #
    # Until 0.9.2 this check verified only that `f-<name>` EXISTED and enabled `oauth-as/<name>`.
    # Deleting the dispatch block for a feature left the whole script printing "all mirrored" and
    # exiting 0, proven by experiment. The two halves below are what make a probe row mean
    # something: a gated `pub fn <name>()` in exercise_features.rs, and a call to it from
    # exercise.rs. Neither alone is enough -- a function nothing calls is exactly the dead code fat
    # LTO removes.
    # THERE ARE TWO CONVENTIONS and both are legitimate, so this checks the property rather than
    # one spelling of it. `http`, `axum` and the `jwt*` family are exercised by dedicated modules
    # (exercise_http.rs, exercise_jwt.rs); everything else gets a gated `pub fn` in
    # exercise_features.rs that exercise.rs calls. A first draft of this check knew only the second
    # convention and reported five false failures against a probe that was entirely correct.
    probe_src = {
        os.path.basename(p): read(p) for p in glob.glob(os.path.join(PROBE_SRC, "*.rs"))
    }
    all_probe_src = "\n".join(probe_src.values())
    dispatch = probe_src.get("exercise.rs", "")
    exercisers = probe_src.get("exercise_features.rs", "")

    for name in sorted(set(crate_features) - {"default"}):
        gate = '#[cfg(feature = "f-%s")]' % name
        if gate not in all_probe_src and ('feature = "f-%s"' % name) not in all_probe_src:
            fail(
                "scripts/size-probe/src/: feature %r is mirrored as `f-%s` in the probe manifest "
                "but no source file gates anything on it, so the row measures a build that does "
                "not touch the feature. Under `lto = \"fat\"` that is close to zero, and the size "
                "gate PASSES on a row that budgets nothing -- the exact lie the probe exists to "
                "prevent." % (name, name)
            )
            continue
        # Second convention only: a gated exerciser that nothing calls is dead code fat LTO
        # removes, which is the same lie with an extra step. Deleting the dispatch line was
        # invisible to this script before 0.9.2, proven by experiment.
        fn = name.replace("-", "_")
        defined = re.search(
            r'#\[cfg\(feature\s*=\s*"f-%s"\)\]\s*\npub fn %s\s*\('
            % (re.escape(name), re.escape(fn)),
            exercisers,
        )
        if defined and ("exercise_features::%s(" % fn) not in dispatch:
            fail(
                "scripts/size-probe/src/exercise.rs: `exercise_features::%s()` is defined and "
                "nothing calls it. Under `lto = \"fat\"` an uncalled function is deleted, so the "
                "%r row measures the feature at close to zero and reports it as a PASS, because "
                "nothing is smaller than a budget." % (fn, name)
            )
    for name, entries in sorted(probe.items()):
        for entry in entries:
            if entry.startswith("oauth-as/"):
                wanted = entry.split("/", 1)[1]
                if wanted not in crate_features:
                    fail(
                        "scripts/size-probe/Cargo.toml: %r enables %r, which crates/oauth-as/"
                        "Cargo.toml does not declare." % (name, entry)
                    )

    # scripts/size-report.sh's ALL_FEATURES is the list the `all-features` row is measured with.
    # A mirror that exists in the probe but is missing here is a feature the biggest row does not
    # include, so the total it budgets is not the total.
    text = read(SIZE_REPORT)
    match = re.search(r'^ALL_FEATURES="([^"]*)"', text, re.MULTILINE)
    if not match:
        fail(
            "scripts/size-report.sh has no ALL_FEATURES= line for this check to read; it cannot "
            "pass vacuously, so this is a failure."
        )
        return
    measured = set(match.group(1).split(","))
    for name in sorted(set(crate_features) - {"default"}):
        if ("f-" + name) not in measured:
            fail(
                "scripts/size-report.sh: ALL_FEATURES does not include %r, so the all-features "
                "size row is measured without feature %r and its budget understates the crate."
                % ("f-" + name, name)
            )


def main():
    crate_features = features_of(CRATE_MANIFEST)
    if len(crate_features) < 2:
        fail(
            "read %d features out of crates/oauth-as/Cargo.toml, which cannot be right; the check "
            "itself is broken and must be fixed before its result means anything"
            % len(crate_features)
        )
    check_workflows(crate_features)
    check_no_rar_step(crate_features)
    check_size_probe(crate_features)

    if problems:
        for problem in problems:
            print("::error::%s" % problem)
        print(
            "\nfeature-mirrors: %d problem(s). [features] in crates/oauth-as/Cargo.toml is the "
            "source of truth; the lists above restate it and have drifted." % len(problems)
        )
        return 1
    print(
        "feature-mirrors: %d crate features, all mirrored in the no-backend AND no-rar lists of "
        "all %d workflows, in the size probe and in the size report"
        % (len(crate_features) - 1, len(WORKFLOWS))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
