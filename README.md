# Copilot API Pro

> [!NOTE]
> This is a fork of [ericc-ch/copilot-api](https://github.com/ericc-ch/copilot-api). The package/CLI name is **copilot-api-pro** (`npx copilot-api-pro@latest start`).  
> Highlights of this fork:  
> - Native OpenAI `/v1/responses` support (latest GPT models such as gpt-5.1-codex).  
> - Persisted Claude Code model selection, daemon start/stop commands, non-interactive startup.  
> - Improved error handling for Copilot responses and daemon management.
> - bug fixes

> [!WARNING]
> This is a reverse-engineered proxy of GitHub Copilot API. It is not supported by GitHub, and may break unexpectedly. Use at your own risk.

> [!WARNING]
> **GitHub Security Notice:**  
> Excessive automated or scripted use of Copilot (including rapid or bulk requests, such as via automated tools) may trigger GitHub's abuse-detection systems.  
> You may receive a warning from GitHub Security, and further anomalous activity could result in temporary suspension of your Copilot access.
>
> GitHub prohibits use of their servers for excessive automated bulk activity or any activity that places undue burden on their infrastructure.
>
> Please review:
>
> - [GitHub Acceptable Use Policies](https://docs.github.com/site-policy/acceptable-use-policies/github-acceptable-use-policies#4-spam-and-inauthentic-activity-on-github)
> - [GitHub Copilot Terms](https://docs.github.com/site-policy/github-terms/github-terms-for-additional-products-and-features#github-copilot)
>
> Use this proxy responsibly to avoid account restrictions.

CLI: `npx copilot-api-pro@latest start`

Quick start
```sh
npx copilot-api-pro@latest start             # 前台
npx copilot-api-pro@latest start --daemon    # 后台
npx copilot-api-pro@latest stop              # 停止后台
npx copilot-api-pro@latest start --claude-code  # 生成 Claude Code 命令并保存模型
npx copilot-api-pro@latest start --codex        # 生成 Codex 命令 (responses)
npx copilot-api-pro@latest check-usage          # 查看用量
```

Quick start
```sh
# 前台 / 后台
npx copilot-api-pro@latest start
npx copilot-api-pro@latest start --daemon
npx copilot-api-pro@latest stop

# Claude Code（选择并保存模型，复制命令）
npx copilot-api-pro@latest start --claude-code

# Codex（生成 wire_api=responses 命令）
npx copilot-api-pro@latest start --codex

# 查看用量
npx copilot-api-pro@latest check-usage
```