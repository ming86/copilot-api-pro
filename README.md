# Copilot API Pro

Fork of [ericc-ch/copilot-api](https://github.com/ericc-ch/copilot-api) that adds OpenAI `/v1/responses`, persistent Claude Code model selection, daemon-friendly start/stop, and tighter error handling. CLI name: `copilot-api-pro`.

> This is a reverse-engineered proxy of GitHub Copilot. It is unofficial and may break at any time.

## Highlights
- OpenAI-compatible endpoints (including `/v1/responses` for GPT-4.1 / gpt-5.1-codex) and Anthropic-compatible `/v1/messages`.
- One-shot Claude Code setup: select models once, persist them, and reuse with `--daemon`.
- Codex CLI helper: generates `wire_api=responses` command for Codex.
- Manual approval and rate-limit guard rails to reduce Copilot abuse flags.
- Background daemon with `start --daemon` and `stop`.

## Requirements
- Bun 1.0+ recommended.
- A GitHub Copilot account (individual, business, or enterprise).
- Files are stored under `~/.local/share/copilot-api` (tokens, Claude Code config, daemon pid).

## Quick start
```sh
# Foreground / background
npx copilot-api-pro@latest start
npx copilot-api-pro@latest start --daemon
npx copilot-api-pro@latest stop

# Claude Code (select & persist models, copy command)
npx copilot-api-pro@latest start --claude-code

# Reset Claude Code selection
npx copilot-api-pro@latest start --claude-code --reset

# Codex (generate wire_api=responses command)
npx copilot-api-pro@latest start --codex

# Show usage
npx copilot-api-pro@latest check-usage
```

## Help
`npx copilot-api-pro@latest --help` shows the command list (command name is `copilot-api-pro`):
```
USAGE copilot-api-pro auth|start|stop|check-usage|debug

COMMANDS
        auth         Run GitHub auth flow without running the server
        start        Start the Copilot API server
        stop         Stop the background Copilot API server started with --daemon
        check-usage  Show current GitHub Copilot usage/quota information
        debug        Print debug information about the application
```

## CLI
- `start` – start the server. Common flags: `-p/--port` (default 4141), `-a/--account-type` (`individual|business|enterprise`), `--manual`, `-r/--rate-limit <sec>`, `--wait`, `-g/--github-token <token>`, `--proxy-env`, `--claude-code`, `--reset`, `--codex`, `--daemon`, `--show-token`, `-v/--verbose`.
- `auth` – run GitHub auth flow only (writes token).
- `stop` – stop the `--daemon` background process.
- `check-usage` – print Copilot usage/quotas.
- `debug` – print version/runtime/path info (`--json` available).

## API surface
- OpenAI: `/v1/chat/completions`, `/v1/embeddings`, `/v1/models`, `/v1/responses`.
- Anthropic: `/v1/messages`, `/v1/messages/count_tokens`.
- Usage: `/usage`, token debug: `/token`.
