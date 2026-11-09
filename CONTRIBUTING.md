# Contributing

scoped-drive-mcp is an MCP server that sits between Grok Bot and Google Drive. The owner signs in and ticks the files and folders the bot may use. Everything else stays out of reach.

## Set up locally

```bash
uv sync
cp .env.example .env
uv run --env-file .env uvicorn api.index:app --reload
```

Fill in `.env` on your own machine. It is git-ignored. Do not commit secrets, tokens, client JSON, or `.env`.

## Tests

```bash
uv run pytest
uv run ruff check .
```

The suite uses an in-memory fake Drive. No network is required.

After you change dependencies, regenerate the Vercel requirements file:

```bash
uv export --no-dev --no-hashes --no-emit-project -o requirements.txt
```

Commit that updated `requirements.txt` with the dependency change.

## Pull requests

Branch from `main`. In the pull request, describe what changed and why.

Keep the existing scope checks, roles, and security behavior intact unless the pull request is explicitly about that.

## Security

Do not open a public issue for a vulnerability that would expose Drive contents or tokens. Contact the repo owner through GitHub.

## License

This project is licensed under the [MIT License](LICENSE).
