# Examples

All of these run offline from a source checkout (`pip install -e '.[mcp,langchain]'` or use `PYTHONPATH=.`).

| file | what it shows |
|---|---|
| `guard_basics.py` | `guard.sanitize`, `guard.scan_text`, and `guard.fetch` with its SSRF guard |
| `wrap_any_tool.py` | `@wrap_tool` around a plain Python tool function (sync and async) |
| `langchain_rag.py` | `InjectionWatchTransformer` before indexing, `guard_tool`, and the `fetch_url_safely` tool |
| `mcp_client.py` | start the MCP server over stdio and call `fetch_url_safely` like an agent would |
| `claude_desktop_config.json` | the MCP server entry for Claude Desktop / Claude Code / other MCP clients |
| `github-action.yml` | a workflow that scans your built site and uploads SARIF to code scanning |
