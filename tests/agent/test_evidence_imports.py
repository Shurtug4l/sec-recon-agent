"""The agent reads TOOL_EFFECTS without building the MCP server."""

import subprocess
import sys


def test_evidence_does_not_import_the_mcp_server() -> None:
    # A fresh interpreter: in-process sys.modules is shared with every other
    # test, so it would already hold the server.
    probe = (
        "import sys, sec_recon_agent.agent.evidence; "
        "heavy = ('sec_recon_agent.mcp_server.server', 'uvicorn'); "
        "loaded = [m for m in heavy if m in sys.modules]; "
        "sys.exit(f'imported {loaded}' if loaded else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr or result.stdout
