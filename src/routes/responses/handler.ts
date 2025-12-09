import type { Context } from "hono"

import { streamSSE } from "hono/streaming"

import { awaitApproval } from "~/lib/approval"
import { forwardError } from "~/lib/error"
import { checkRateLimit } from "~/lib/rate-limit"
import { state } from "~/lib/state"
import {
  createResponses,
  type ResponsesPayload,
  type ResponsesResponse,
} from "~/services/copilot/create-responses"

export async function handleResponseEndpoint(c: Context) {
  try {
    await checkRateLimit(state)

    const payload = await c.req.json<ResponsesPayload>()

    if (state.manualApprove) {
      await awaitApproval()
    }

    const response = await createResponses(payload)

    if (isNonStreaming(response)) {
      return c.json(response)
    }

    return streamSSE(c, async (stream) => {
      for await (const rawEvent of response) {
        if (rawEvent.data === "[DONE]") break
        if (!rawEvent.data) continue

        await stream.writeSSE(rawEvent)
      }
    })
  } catch (error) {
    return await forwardError(c, error)
  }
}

const isNonStreaming = (
  response: Awaited<ReturnType<typeof createResponses>>,
): response is ResponsesResponse =>
  typeof (response as AsyncIterable<unknown>)[Symbol.asyncIterator]
  !== "function"
