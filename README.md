# scoped-drive-mcp

A Python MCP server (official `mcp` SDK, Streamable HTTP transport) deployed on Vercel. It sits between Grok and Google Drive, restricts access to a single configured folder or Shared Drive, and exposes role-based tools (viewer, editor, admin) tied to bearer tokens. **Work in progress** — see [docs/PLAN.md](docs/PLAN.md) for the full plan.
