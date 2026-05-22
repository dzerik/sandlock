# SPDX-License-Identifier: Apache-2.0
"""Jailed entry point: import a tool module and call one function.

Invoked by McpSandbox inside a Landlock + seccomp sandbox::

    python -m sandlock.mcp._worker --syspath DIR MODULE QUALNAME ARGS_JSON

DIR is prepended to sys.path (clean_env strips PYTHONPATH) so that
locally-defined tool modules resolve.  MODULE is imported, the top-level
function QUALNAME is called with the JSON-decoded keyword arguments, and
its result is printed (str as-is, otherwise JSON).  A non-zero exit and a
traceback on stderr signal failure to the parent.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sandlock.mcp._worker")
    parser.add_argument("--syspath", default=None)
    parser.add_argument("module")
    parser.add_argument("qualname")
    parser.add_argument("args_json")
    ns = parser.parse_args(argv)

    if ns.syspath:
        sys.path.insert(0, ns.syspath)

    module = importlib.import_module(ns.module)
    func = getattr(module, ns.qualname)
    result = func(**json.loads(ns.args_json))

    if result is not None:
        print(result if isinstance(result, str) else json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
