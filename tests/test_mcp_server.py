import sys
import unittest
from datetime import timedelta
from importlib.util import find_spec
from pathlib import Path


@unittest.skipUnless(find_spec("mcp"), "Installer requirements-mcp.txt pour tester le plugin")
class MCPServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_packaged_server_reports_signals_and_redacts_inputs(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        root = Path(__file__).resolve().parents[1]
        params = StdioServerParameters(
            command=sys.executable,
            args=["-B", "-m", "cyber.mcp_server"],
            cwd=str(root),
        )
        token = "ghp_" + "Ab9cD7eF2hJ6kL8mN3pQ5rS1tU4vW0xYz9aB"
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=10)) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                self.assertEqual([tool.name for tool in tools], ["verifier_code"])
                self.assertTrue(tools[0].annotations.readOnlyHint)
                self.assertFalse(tools[0].annotations.openWorldHint)

                result = await session.call_tool("verifier_code", {"fichiers": [
                    {"chemin": "package.json", "contenu": '{"scripts":{"postinstall":"echo ok"}}'},
                    {"chemin": "synthetic-name.py", "contenu": f'key = "{token}"\n'},
                    {"chemin": ".github/workflows/ci.yml", "contenu": "permissions: write-all\n"},
                ]})
                self.assertFalse(result.isError)
                report = result.structuredContent
                self.assertEqual(
                    {(item["rule_id"], item["fichier"]) for item in report["signaux"]},
                    {("PKG-001", 1), ("SECRET-002", 2), ("WF-002", 3)},
                )
                self.assertNotIn(token, result.model_dump_json())
                self.assertNotIn("synthetic-name.py", result.model_dump_json())
                self.assertNotIn("echo ok", result.model_dump_json())

                cases = [
                    [{"chemin": f"../{token}", "contenu": ""}],
                    [{"chemin": "/etc/hosts", "contenu": ""}],
                    [{"chemin": "script.py", "contenu": [token]}],
                    [{"chemin": "script.py", "contenu": "é" * 16385}],
                    [{"chemin": f"{i}.py", "contenu": "x" * 32768} for i in range(4)],
                    [{"chemin": "same.py", "contenu": ""}] * 2,
                ]
                for files in cases:
                    rejected = await session.call_tool("verifier_code", {"fichiers": files})
                    self.assertTrue(rejected.isError)
                    self.assertNotIn(token, rejected.model_dump_json())

                partial = await session.call_tool("verifier_code", {"fichiers": [
                    {"chemin": "package.json", "contenu": "{"},
                ]})
                self.assertTrue(partial.structuredContent["analyse_partielle"])
