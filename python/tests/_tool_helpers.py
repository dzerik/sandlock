# SPDX-License-Identifier: Apache-2.0
"""Stdlib-only tool functions for McpSandbox tests.

Tools live in their own importable module (no sandlock/pytest imports) so
the jailed worker can import them by name, mirroring how a real MCP server
should structure its tools.
"""


def _read_file_tool(path: str) -> str:
    import os
    workspace = os.environ["SANDLOCK_WORKSPACE"]
    with open(os.path.join(workspace, path)) as f:
        return f.read()


def _write_file_tool(path: str, content: str) -> str:
    import os
    workspace = os.environ["SANDLOCK_WORKSPACE"]
    with open(os.path.join(workspace, path), "w") as f:
        f.write(content)
    return f"wrote {len(content)} bytes"


def _run_python_tool(code: str) -> str:
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(code)
    return buf.getvalue()


def _list_files_tool() -> str:
    import os, json
    workspace = os.environ["SANDLOCK_WORKSPACE"]
    return json.dumps(sorted(os.listdir(workspace)))
