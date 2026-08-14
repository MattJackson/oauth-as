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

# THE VERSION IN Cargo.toml HAS THREE LOCKFILE MIRRORS, AND ONE OF THEM HAS NOW BEEN MISSED TWICE.
#
# Every gate runs `--locked`, deliberately: a budget or a proof measured against one dependency
# resolve is worthless if checked against another. The cost is that a satellite lockfile naming a
# STALE version of this crate makes cargo refuse to do anything at all --
#
#     error: cannot update the lock file .../fuzz/Cargo.lock because --locked was passed
#
# -- so the job does not fail on its merits, it fails to start. At 0.9.1 that was `fuzz/Cargo.lock`
# still saying 0.9.0, fixed in 551a8de. At 0.9.2 it was `fuzz/Cargo.lock` still saying 0.9.1: the
# root and the probe were remembered by hand, the third was not, and qa's fuzz job could not build
# on the release commit. Nothing checked it either time.
#
# It is worse than an ordinary red build because of WHERE it lands. `dev.yml` and `publish.yml`
# have no fuzz job, so both were fully green; the only signal was a red job on a branch the publish
# path does not consult, and reaching `main` publishes.
LOCKFILES = [
    os.path.join(ROOT, "Cargo.lock"),
    os.path.join(ROOT, "fuzz", "Cargo.lock"),
    os.path.join(ROOT, "scripts", "size-probe", "Cargo.lock"),
]
# The two halves of "this probe row actually measures something": the gated exerciser, and the
# call site that keeps fat LTO from deleting it. See `check_size_probe`.
PROBE_SRC = os.path.join(ROOT, "scripts", "size-probe", "src")

# EVERY FEATURE, THE FILE THAT EXERCISES IT, AND THE SYMBOL THAT MUST BE REACHED.
#
# Written out rather than inferred, because inferring it is what let two holes open (see
# `check_size_probe`). A feature missing from this table FAILS: "this check has no opinion about
# that feature" is exactly the state that let an unexercised row measure zero and pass its budget.
#
# Two conventions, both legitimate. `http`, `axum` and the `jwt` family are exercised by dedicated
# modules whose single entry point `exercise.rs` calls; everything else gets a gated `pub fn` in
# `exercise_features.rs` that `exercise.rs` calls by name.
PROBE_EXERCISERS = {
    "http": ("exercise_http.rs", "exercise_http::plane()"),
    "axum": ("exercise_http.rs", "exercise_http::plane()"),
    "jwt": ("exercise_jwt.rs", "exercise_jwt::plane()"),
    "jwt-p256": ("exercise_jwt.rs", "exercise_jwt::plane()"),
    "jwt-pkcs8": ("exercise_jwt.rs", "exercise_jwt::plane()"),
    "mtls": ("exercise_features.rs", "exercise_features::mtls()"),
    "par": ("exercise_features.rs", "exercise_features::par()"),
    "jar": ("exercise_features.rs", "exercise_features::jar()"),
    "rar": ("exercise_features.rs", "exercise_features::rar()"),
    "dpop": ("exercise_features.rs", "exercise_features::dpop()"),
    "client-assertion": ("exercise_features.rs", "exercise_features::client_assertion()"),
    "consent": ("exercise_features.rs", "exercise_features::consent()"),
    "token-exchange": ("exercise_features.rs", "exercise_features::token_exchange()"),
    "resource-metadata": ("exercise_features.rs", "exercise_features::resource_metadata()"),
    "cimd": ("exercise_features.rs", "exercise_features::cimd()"),
    "test-util": ("exercise_features.rs", "exercise_features::test_util()"),
}
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

    # EVERY FEATURE MUST NAME ITS EXERCISER, AND THE EXERCISER MUST BE CALLED. No feature is
    # exempt, and there is no arm of this check that ends in "then skip it".
    #
    # The first version of this check had two holes, both proven by experiment, and both are the
    # SAME DEFECT IT WAS WRITTEN TO CATCH one level up: a gate that quietly stops applying.
    #
    #   HOLE A: it read `if defined and dispatch_missing`. When the regex missed, the check was
    #   SKIPPED rather than FAILED. The regex required the `#[cfg]` attribute to be immediately
    #   followed by `pub fn`, so putting an ordinary doc comment between them disabled it. Proven:
    #   the cimd dispatch was deleted (script went red, correctly), then one `///` line was added
    #   above `pub fn cimd()` and the script printed "all mirrored" and exited 0 with the exerciser
    #   dead-code-eliminated.
    #
    #   HOLE B: the module convention -- http, axum and the jwt family, exercised from
    #   exercise_http.rs and exercise_jwt.rs -- had NO dispatch check at all, because no
    #   `pub fn <name>()` exists in exercise_features.rs for them, so `defined` was always None.
    #   The only surviving test was "does the string `feature = "f-axum"` appear anywhere in
    #   src/*.rs", which a COMMENT satisfies. Proven: the entire `#[cfg(feature = "f-axum")]` block
    #   -- the tokio runtime, the bound listener, the axum::serve future, everything the axum row
    #   exists to link -- was replaced with `acc = acc.wrapping_add(1);` and the script still said
    #   "all mirrored".
    #
    # Neither hole could be caught by the size gate either, WHEN THIS WAS WRITTEN: `size-report.sh`
    # compared a delta against an upper bound and had no FLOOR, so a row whose exerciser vanished
    # measured close to zero and was comfortably inside any budget.
    #
    # THAT HALF IS NOW FIXED, and the division of labour is worth stating exactly, because each of
    # these two checks is the other's blind spot and neither is a substitute:
    #
    #   * size-report.sh grew a floor_for() beside its budget_for(): every gated row now has a
    #     minimum as well as a maximum, so a row that COLLAPSES is red. PROVEN 2026-08-13 by
    #     replacing the body of `exercise_http::plane()` with a `return 0` -- leaving the `#[cfg]`,
    #     the `pub fn` and the call site all in place, so THIS script still printed "all mirrored"
    #     -- whereupon the `http` row fell from 423,715 bytes to 220,946 and the gate reported
    #     "UNDER its floor of 407.0 KiB (195,822 bytes short)". The pre-floor script, run against
    #     the identical tree, printed "every gated feature set is within its recorded budget" and
    #     exited 0.
    #
    #   * The floor does NOT rescue a single feature going quiet inside a row that carries fifteen
    #     others. MEASURED in the same session: gutting `exercise_features::rar()` moved the
    #     `all-features` row by 1,868 bytes, 0.13%, because the features around it already
    #     instantiate the JSON machinery RAR shares. No floor can see that. Only the check BELOW
    #     can, which is why it is a string check and why it stays.
    #
    # So: this check catches a per-feature exerciser that is missing or unreachable; the floor
    # catches a whole row that stopped measuring. A feature whose exerciser is present, called,
    # and hollow is caught by NEITHER, and the honest place to close that is a gated row per
    # feature in size-report.sh -- a decision about CI minutes, recorded there, not taken here.
    #
    # So the rule is now explicit rather than inferred. `PROBE_EXERCISERS` names, for every
    # feature, the file that exercises it and the symbol that must be reachable, and a feature
    # absent from that table is a FAILURE rather than a feature this check has nothing to say
    # about. Adding a feature therefore means adding a line here, which is the point: the table is
    # small, it is checked, and it cannot silently stop applying.
    for name in sorted(set(crate_features) - {"default"}):
        entry = PROBE_EXERCISERS.get(name)
        if entry is None:
            fail(
                "scripts/feature-mirrors.py: feature %r has no entry in PROBE_EXERCISERS, so "
                "nothing here checks that its size row measures anything. Add one naming the file "
                "that exercises it and the symbol that must be reached. A feature this check has "
                "no opinion about is a row that can quietly measure zero." % name
            )
            continue
        source_file, symbol = entry
        source = probe_src.get(source_file)
        if source is None:
            fail(
                "scripts/size-probe/src/%s: named as %r's exerciser and does not exist."
                % (source_file, name)
            )
            continue
        gate = 'feature = "f-%s"' % name
        # The gate may sit INSIDE the exerciser file, or on the `mod` declaration in main.rs --
        # `exercise_http` and `exercise_jwt` are whole modules compiled only under their feature,
        # so the gate that governs them is `#[cfg(feature = "f-http")] mod exercise_http;`. Both
        # spellings mean the same thing: nothing in that file is linked without the feature.
        declaration = probe_src.get("main.rs", "")
        if gate not in source and gate not in declaration:
            fail(
                "scripts/size-probe/src/%s: nothing is gated on `%s`, there or on its `mod` "
                "declaration in main.rs, so the %r row builds a binary that never touches the "
                "feature. Under `lto = \"fat\"` that measures close to zero and PASSES any budget "
                "-- the exact lie the probe exists to prevent." % (source_file, gate, name)
            )
        # The symbol must be REACHED, from the dispatcher, by name. For the exercise_features.rs
        # convention that is the call in exercise.rs; for the module convention it is the module's
        # own entry point, which exercise.rs calls unconditionally.
        if symbol not in all_probe_src.replace(source, "", 1) and symbol not in dispatch:
            fail(
                "scripts/size-probe/src/: %r's exerciser %r is defined and nothing calls it. "
                "Under `lto = \"fat\"` an uncalled function is deleted, so the row measures the "
                "feature at close to zero and reports it as a PASS, because nothing is smaller "
                "than a budget." % (name, symbol)
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


def check_lockfiles():
    """Every satellite lockfile must name the version `crates/oauth-as/Cargo.toml` declares.

    See `LOCKFILES` for why this exists. Short version: `--locked` makes a stale one fail the job
    before it starts rather than on its merits, and it has now been missed twice in two releases.
    """
    text = read(CRATE_MANIFEST)
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        fail(
            "crates/oauth-as/Cargo.toml has no top-level version= for this check to read; it "
            "cannot pass vacuously, so this is a failure."
        )
        return
    declared = match.group(1)
    for path in LOCKFILES:
        if not os.path.exists(path):
            fail("%s does not exist, and this check is named for it." % path)
            continue
        found = re.search(
            r'\[\[package\]\]\nname = "oauth-as"\nversion = "([^"]+)"', read(path)
        )
        if not found:
            fail(
                "%s has no `oauth-as` package entry, so nothing here can tell whether it is "
                "stale. A lockfile this check cannot read is one it cannot vouch for." % path
            )
            continue
        if found.group(1) != declared:
            fail(
                "%s pins oauth-as %s while crates/oauth-as/Cargo.toml declares %s. Every gate "
                "runs --locked, so cargo will REFUSE TO BUILD rather than fail on the merits: "
                "`cannot update the lock file ... because --locked was passed`. Run "
                "`cargo update --manifest-path <that manifest> -p oauth-as`."
                % (path, found.group(1), declared)
            )


def main():
    crate_features = features_of(CRATE_MANIFEST)
    if len(crate_features) < 2:
        fail(
            "read %d features out of crates/oauth-as/Cargo.toml, which cannot be right; the check "
            "itself is broken and must be fixed before its result means anything"
            % len(crate_features)
        )
    check_lockfiles()
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
