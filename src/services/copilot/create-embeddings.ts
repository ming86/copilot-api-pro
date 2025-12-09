import consola from "consola"

import { copilotHeaders, copilotBaseUrl } from "~/lib/api-config"
import { HTTPError } from "~/lib/error"
import { state } from "~/lib/state"

export const createEmbeddings = async (payload: EmbeddingRequest) => {
  if (!state.copilotToken) throw new Error("Copilot token not found")

  if (payload.input === undefined || payload.input === null) {
    throw new Error("Embedding input is required")
  }

  const model = resolveEmbeddingModel(payload.model)
  const normalizedInput = normalizeInput(payload.input)
  const normalizedPayload: EmbeddingRequest = {
    ...payload,
    model,
    input: normalizedInput,
  }

  const response = await fetch(`${copilotBaseUrl(state)}/embeddings`, {
    method: "POST",
    headers: {
      ...copilotHeaders(state),
      "openai-intent": "embeddings",
    },
    body: JSON.stringify(normalizedPayload),
  })

  if (!response.ok) {
    const body = await response.text()
    consola.error("Embeddings request failed", {
      status: response.status,
      statusText: response.statusText,
      body,
    })
    throw new HTTPError(body || "Failed to create embeddings", response)
  }

  return (await response.json()) as EmbeddingResponse
}

export interface EmbeddingRequest {
  input: string | Array<string>
  model?: string
  encoding_format?: "float" | "base64"
  dimensions?: number
}

export interface Embedding {
  object: string
  embedding: Array<number>
  index: number
}

export interface EmbeddingResponse {
  object: string
  data: Array<Embedding>
  model: string
  usage: {
    prompt_tokens: number
    total_tokens: number
  }
}

const resolveEmbeddingModel = (model?: string) => {
  const embeddingCandidates =
    state.models?.data.filter((candidate) => {
      const idMatch = candidate.id.toLowerCase().includes("embedding")
      const typeMatch = candidate.capabilities.type
        ?.toLowerCase()
        .includes("embedding")

      return idMatch || Boolean(typeMatch)
    }) ?? []

  if (model) {
    const supported = state.models?.data.some((m) => m.id === model)
    if (supported) return model

    if (embeddingCandidates.length > 0) {
      const fallback = embeddingCandidates[0]
      consola.warn(
        `Embedding model "${model}" not available. Falling back to "${fallback.id}".`,
      )
      return fallback.id
    }

    consola.error(
      `Embedding model "${model}" not available and no embedding-capable models found.`,
    )
    throw new Error("Embedding model not available")
  }

  if (embeddingCandidates.length > 0) {
    return embeddingCandidates[0].id
  }

  throw new Error("Embedding model not specified and no default found")
}

const normalizeInput = (input: string | Array<string>) => {
  if (Array.isArray(input)) return input
  return [input]
}
