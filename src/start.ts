#!/usr/bin/env node

import { defineCommand } from "citty"
import clipboard from "clipboardy"
import consola from "consola"
import { spawn } from "node:child_process"
import fs from "node:fs/promises"
import process from "node:process"
import { serve, type ServerHandler } from "srvx"
import invariant from "tiny-invariant"

import { ensurePaths } from "./lib/paths"
import { PATHS } from "./lib/paths"
import { initProxyFromEnv } from "./lib/proxy"
import { generateEnvScript } from "./lib/shell"
import { state } from "./lib/state"
import { setupCopilotToken, setupGitHubToken } from "./lib/token"
import { cacheModels, cacheVSCodeVersion } from "./lib/utils"
import { server } from "./server"

interface RunServerOptions {
  port: number
  verbose: boolean
  accountType: string
  manual: boolean
  rateLimit?: number
  rateLimitWait: boolean
  githubToken?: string
  claudeCode: boolean
  claudeCodeReset: boolean
  codex: boolean
  showToken: boolean
  proxyEnv: boolean
  daemon: boolean
}

export async function runServer(options: RunServerOptions): Promise<void> {
  if (options.proxyEnv) {
    initProxyFromEnv()
  }

  if (options.verbose) {
    consola.level = 5
    consola.info("Verbose logging enabled")
  }

  state.accountType = options.accountType
  if (options.accountType !== "individual") {
    consola.info(`Using ${options.accountType} plan GitHub account`)
  }

  state.manualApprove = options.manual
  state.rateLimitSeconds = options.rateLimit
  state.rateLimitWait = options.rateLimitWait
  state.showToken = options.showToken

  await ensurePaths()
  await cacheVSCodeVersion()

  if (options.githubToken) {
    state.githubToken = options.githubToken
    consola.info("Using provided GitHub token")
  } else {
    await setupGitHubToken()
  }

  await setupCopilotToken()
  await cacheModels()

  consola.info(
    `Available models: \n${state.models?.data.map((model) => `- ${model.id}`).join("\n")}`,
  )

  const serverUrl = `http://localhost:${options.port}`

  if (options.claudeCode) {
    invariant(state.models, "Models should be loaded by now")

    const storedConfig = await loadClaudeCodeConfig()
    if (storedConfig) {
      consola.info(
        `Claude Code config: model="${storedConfig.model}", small="${storedConfig.smallModel}", path=${PATHS.CLAUDE_CODE_CONFIG_PATH}`,
      )
    }

    if (options.claudeCodeReset && storedConfig) {
      consola.info(
        "Resetting stored Claude Code config; re-prompting selection.",
      )
      await clearClaudeCodeConfig()
    }

    const effectiveStored = options.claudeCodeReset ? null : storedConfig
    const validConfig =
      effectiveStored
      && state.models.data.some((model) => model.id === effectiveStored.model)
      && state.models.data.some(
        (model) => model.id === effectiveStored.smallModel,
      )
    const configToUse = validConfig ? effectiveStored : null

    if (!configToUse && options.daemon) {
      throw new Error(
        "Claude Code config not found. Run `copilot-api start --claude-code` once without --daemon to set it.",
      )
    }

    const selectedModel =
      configToUse?.model
      ?? (await consola.prompt("Select a model to use with Claude Code", {
        type: "select",
        options: state.models.data.map((model) => model.id),
      }))

    const selectedSmallModel =
      configToUse?.smallModel
      ?? (await consola.prompt("Select a small model to use with Claude Code", {
        type: "select",
        options: state.models.data.map((model) => model.id),
      }))

    if (!configToUse || options.claudeCodeReset) {
      const config = { model: selectedModel, smallModel: selectedSmallModel }
      await saveClaudeCodeConfig(config)
      consola.info(
        `Saved Claude Code config to ${PATHS.CLAUDE_CODE_CONFIG_PATH}: model="${config.model}", small="${config.smallModel}"`,
      )
    }

    const command = generateEnvScript(
      {
        ANTHROPIC_BASE_URL: serverUrl,
        ANTHROPIC_AUTH_TOKEN: "dummy",
        ANTHROPIC_MODEL: selectedModel,
        ANTHROPIC_DEFAULT_SONNET_MODEL: selectedModel,
        ANTHROPIC_SMALL_FAST_MODEL: selectedSmallModel,
        ANTHROPIC_DEFAULT_HAIKU_MODEL: selectedSmallModel,
        DISABLE_NON_ESSENTIAL_MODEL_CALLS: "1",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      },
      "claude",
    )

    try {
      clipboard.writeSync(command)
      consola.success("Copied Claude Code command to clipboard!")
    } catch {
      consola.warn(
        "Failed to copy to clipboard. Here is the Claude Code command:",
      )
      consola.log(command)
    }
  }

  if (options.codex) {
    invariant(state.models, "Models should be loaded by now")
    const selectedModel = await consola.prompt(
      "Select a model to use with Codex",
      {
        type: "select",
        options: state.models.data.map((model) => model.id),
      },
    )

    const codexCommand = [
      "codex",
      `-c model_providers.copilot-api.name=copilot-api`,
      `-c model_providers.copilot-api.base_url=${serverUrl}/v1`,
      `-c model_providers.copilot-api.wire_api=responses`,
      `-c model_provider=copilot-api`,
      `-c model_reasoning_effort=high`,
      `-m ${selectedModel}`,
    ].join(" ")

    try {
      clipboard.writeSync(codexCommand)
      consola.success("Copied Codex command to clipboard!")
    } catch {
      consola.warn("Failed to copy Codex command. Here it is:")
      consola.log(codexCommand)
    }
  }

  consola.box(
    `🌐 Usage Viewer: https://ericc-ch.github.io/copilot-api?endpoint=${serverUrl}/usage`,
  )

  serve({
    fetch: server.fetch as ServerHandler,
    port: options.port,
  })
}

export const start = defineCommand({
  meta: {
    name: "start",
    description: "Start the Copilot API server",
  },
  args: {
    port: {
      alias: "p",
      type: "string",
      default: "4141",
      description: "Port to listen on",
    },
    verbose: {
      alias: "v",
      type: "boolean",
      default: false,
      description: "Enable verbose logging",
    },
    "account-type": {
      alias: "a",
      type: "string",
      default: "individual",
      description: "Account type to use (individual, business, enterprise)",
    },
    manual: {
      type: "boolean",
      default: false,
      description: "Enable manual request approval",
    },
    "rate-limit": {
      alias: "r",
      type: "string",
      description: "Rate limit in seconds between requests",
    },
    wait: {
      alias: "w",
      type: "boolean",
      default: false,
      description:
        "Wait instead of error when rate limit is hit. Has no effect if rate limit is not set",
    },
    "github-token": {
      alias: "g",
      type: "string",
      description:
        "Provide GitHub token directly (must be generated using the `auth` subcommand)",
    },
    "claude-code": {
      alias: "c",
      type: "boolean",
      default: false,
      description:
        "Generate a command to launch Claude Code with Copilot API config",
    },
    "claude-code-reset": {
      type: "boolean",
      default: false,
      description:
        "Force re-select Claude Code models and overwrite stored config",
    },
    codex: {
      type: "boolean",
      default: false,
      description:
        "Generate a command to use Codex CLI with Copilot API (responses wire)",
    },
    "show-token": {
      type: "boolean",
      default: false,
      description: "Show GitHub and Copilot tokens on fetch and refresh",
    },
    "proxy-env": {
      type: "boolean",
      default: false,
      description: "Initialize proxy from environment variables",
    },
    daemon: {
      type: "boolean",
      default: false,
      description: "Run the server in the background",
    },
  },
  async run({ args }) {
    const rateLimitRaw = args["rate-limit"]
    const rateLimit =
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      rateLimitRaw === undefined ? undefined : Number.parseInt(rateLimitRaw, 10)

    const options = {
      port: Number.parseInt(args.port, 10),
      verbose: args.verbose,
      accountType: args["account-type"],
      manual: args.manual,
      rateLimit,
      rateLimitWait: args.wait,
      githubToken: args["github-token"],
      claudeCode: args["claude-code"],
      claudeCodeReset: args["claude-code-reset"],
      codex: args.codex,
      showToken: args["show-token"],
      proxyEnv: args["proxy-env"],
      daemon: args.daemon || process.env.COPILOT_API_IS_DAEMON === "1",
    }

    if (args.daemon && process.env.COPILOT_API_IS_DAEMON !== "1") {
      await ensurePaths()
      const child = spawn(process.argv[0], process.argv.slice(1), {
        detached: true,
        stdio: "ignore",
        env: { ...process.env, COPILOT_API_IS_DAEMON: "1" },
      })

      await fs.writeFile(PATHS.PID_PATH, String(child.pid))
      consola.info(
        `Copilot API server is starting in the background (pid ${child.pid}).`,
      )
      child.unref()
      return
    }

    return runServer(options)
  },
})

interface ClaudeCodeConfig {
  model: string
  smallModel: string
}

const loadClaudeCodeConfig = async (): Promise<ClaudeCodeConfig | null> => {
  try {
    const content = await fs.readFile(PATHS.CLAUDE_CODE_CONFIG_PATH, "utf8")
    if (!content) return null
    return JSON.parse(content) as ClaudeCodeConfig
  } catch {
    return null
  }
}

const saveClaudeCodeConfig = async (config: ClaudeCodeConfig) => {
  await fs.writeFile(
    PATHS.CLAUDE_CODE_CONFIG_PATH,
    JSON.stringify(config, null, 2),
  )
}

const clearClaudeCodeConfig = async () => {
  try {
    await fs.unlink(PATHS.CLAUDE_CODE_CONFIG_PATH)
  } catch {
    // ignore
  }
}
