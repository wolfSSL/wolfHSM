#!/usr/bin/env python3

# Compare legacy vs refactor gcovr tracefiles per config and report the
# src/ coverage that only the legacy suite provides. A line or branch
# covered by legacy but not by refactor (in the same build config) is
# coverage that would be lost if the legacy suite were trimmed, so it
# blocks trimming until the refactor tree catches up. Output groups by
# source file; mapping a file back to the legacy suite that exercises
# it is the reviewer's step.
#
# Usage: compare_tracefiles.py <cov-json-dir> <out-dir>
#   Pairs <dir>/legacy-<config>.json with <dir>/refactor-<config>.json.

import glob
import json
import os
import sys
from collections import defaultdict


def load_tracefile(path):
    # Return {file: {"lines": {n: covered}, "branches": {n: {key: cov}}}}.
    # A line/branch is covered if any of its entries has count > 0.
    with open(path) as fh:
        data = json.load(fh)
    files = {}
    for entry in data.get("files", []):
        name = entry["file"].lstrip("./")
        lines = defaultdict(bool)
        branches = defaultdict(lambda: defaultdict(bool))
        for ln in entry.get("lines", []):
            n = ln["line_number"]
            lines[n] = lines[n] or ln.get("count", 0) > 0
            for br in ln.get("branches", []):
                key = (br.get("source_block_id"),
                       br.get("destination_block_id"))
                covered = br.get("count", 0) > 0
                branches[n][key] = branches[n][key] or covered
        files[name] = {"lines": dict(lines), "branches": branches}
    return files


def legacy_only(legacy, refactor):
    # Per file, find lines/branches covered in legacy but not refactor.
    result = {}
    for name, lf in legacy.items():
        rf = refactor.get(name)
        only_lines = []
        for n, covered in lf["lines"].items():
            if not covered:
                continue
            if rf is None or not rf["lines"].get(n, False):
                only_lines.append(n)
        only_branches = []
        for n, keys in lf["branches"].items():
            for key, covered in keys.items():
                if not covered:
                    continue
                rcov = rf and rf["branches"].get(n, {}).get(key, False)
                if not rcov:
                    only_branches.append(n)
        if only_lines or only_branches:
            result[name] = {
                "file_absent_in_refactor": rf is None,
                "lines": sorted(only_lines),
                "branch_count": len(only_branches),
            }
    return result


def discover_configs(cov_dir):
    configs = []
    for p in sorted(glob.glob(os.path.join(cov_dir, "legacy-*.json"))):
        name = os.path.basename(p)[len("legacy-"):-len(".json")]
        if os.path.exists(os.path.join(cov_dir, "refactor-%s.json" % name)):
            configs.append(name)
    return configs


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: %s <cov-json-dir> <out-dir>\n" % argv[0])
        return 2
    cov_dir, out_dir = argv[1], argv[2]
    os.makedirs(out_dir, exist_ok=True)

    configs = discover_configs(cov_dir)
    if not configs:
        sys.stderr.write("no legacy/refactor tracefile pairs found\n")
        return 1

    per_config = {}
    # union[file] -> set of configs where the file has legacy-only lines
    union = defaultdict(set)
    for cfg in configs:
        legacy = load_tracefile(os.path.join(cov_dir, "legacy-%s.json" % cfg))
        refactor = load_tracefile(
            os.path.join(cov_dir, "refactor-%s.json" % cfg))
        diff = legacy_only(legacy, refactor)
        per_config[cfg] = diff
        for name, info in diff.items():
            if info["lines"]:
                union[name].add(cfg)

    with open(os.path.join(out_dir, "legacy-only-coverage.json"), "w") as fh:
        json.dump({"configs": per_config}, fh, indent=2, sort_keys=True)
        fh.write("\n")

    write_summary(os.path.join(out_dir, "summary.md"), configs, per_config,
                  union)
    return 0


def write_summary(path, configs, per_config, union):
    lines = ["## Legacy-only coverage (trim blockers)", ""]
    lines.append("Lines and branches covered by the legacy suite but not "
                 "the refactor suite, per build config. A file listed here "
                 "still has coverage the refactor tree does not reproduce.")
    lines.append("")
    for cfg in configs:
        diff = per_config[cfg]
        total_lines = sum(len(i["lines"]) for i in diff.values())
        total_branches = sum(i["branch_count"] for i in diff.values())
        header = "### %s: %d legacy-only lines, %d branches" % (
            cfg, total_lines, total_branches)
        lines.append(header)
        if not diff:
            lines.append("")
            lines.append("Refactor covers everything legacy does.")
            lines.append("")
            continue
        lines.append("")
        lines.append("| file | lines | branches | file absent |")
        lines.append("|------|------:|---------:|:-----------:|")
        for name in sorted(diff):
            info = diff[name]
            absent = "yes" if info["file_absent_in_refactor"] else ""
            lines.append("| %s | %d | %d | %s |" % (
                name, len(info["lines"]), info["branch_count"], absent))
        lines.append("")

    lines.append("### Trim-blocker files (legacy-only lines in any config)")
    lines.append("")
    if union:
        lines.append("| file | configs |")
        lines.append("|------|---------|")
        for name in sorted(union):
            lines.append("| %s | %s |" % (name,
                                          ", ".join(sorted(union[name]))))
    else:
        lines.append("None. Every file's legacy line coverage is reproduced "
                     "by the refactor suite.")
    lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines))
        fh.write("\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
