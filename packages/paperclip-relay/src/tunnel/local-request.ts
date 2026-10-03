/**
 * Serving one relayed HTTP stream against the local app.
 *
 * The dialer holds the browser's request head (from `open_stream`) and the request
 * body (raw bytes on the tunnel socket). This module turns that into a real
 * request to the local app, reports the response head back over the control
 * channel, and pipes the response body out over the tunnel socket.
 *
 * Note what is *not* here: no framing logic, no multiplexing, no state machine.
 * One tunnel socket is one request, which is why this can be a straight pipe.
 */
import { request as httpRequest, type ClientRequest, type IncomingMessage, type OutgoingHttpHeaders } from "node:http";
import type { Readable, Writable } from "node:stream";

import type { RelayErrorCode } from "../protocol/error-codes.js";
import type { RelayStreamRequest } from "../dialer/control-client.js";
import { normalizeRelayedRequestHeaders } from "./normalize.js";

/**
 * Response headers that must not cross back to the browser.
 *
 * `transfer-encoding` is the important one. Node has already de-chunked the
 * upstream response by the time these headers are read, so forwarding
 * `transfer-encoding: chunked` would tell the browser to wait for chunk framing
 * that no longer exists — the response would hang until it timed out rather than
 * fail loudly. `connection` and the rest are hop-by-hop for the same reason they
 * are on the request side.
 */
const STRIPPED_RESPONSE_HEADERS: ReadonlySet<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export interface RelayStreamByteCounts {
  /** Bytes read from the relayed client, i.e. the request body. */
  readonly bytesFromClient: number;
  /** Bytes written back toward the relayed client, i.e. the response body. */
  readonly bytesToClient: number;
}

export interface ServeRelayHttpStreamInput {
  readonly request: RelayStreamRequest;
  /** Request body bytes arriving on the tunnel socket. */
  readonly body: Readable;
  /** Where the response body is written. Usually the tunnel socket. */
  readonly responseSink: Writable;
  /** Report the response head before any body byte flows. */
  readonly onHead: (status: number, headers: Record<string, string>) => void;
  /** The response finished cleanly. */
  readonly onEnd: (counts: RelayStreamByteCounts) => void;
  /** The stream failed. The caller tears the tunnel socket down. */
  readonly onError: (code: RelayErrorCode, message: string) => void;
  /** Local origin the app listens on, e.g. `http://127.0.0.1:3100`. */
  readonly localBaseUrl: string;
  /** Authority matching it, e.g. `127.0.0.1:3100`. */
  readonly localAuthority: string;
  /** Deadline for the local app to produce response headers. */
  readonly localResponseTimeoutMs?: number;
  /** Injectable request implementation, for tests. */
  readonly createRequest?: typeof httpRequest;
}

const DEFAULT_LOCAL_RESPONSE_TIMEOUT_MS = 30_000;

export function serveRelayHttpStream(input: ServeRelayHttpStreamInput): void {
  const createRequest = input.createRequest ?? httpRequest;
  const timeoutMs = input.localResponseTimeoutMs ?? DEFAULT_LOCAL_RESPONSE_TIMEOUT_MS;

  let settled = false;
  let bytesFromClient = 0;
  let bytesToClient = 0;

  const finish = (): void => {
    if (settled) return;
    settled = true;
    input.onEnd({ bytesFromClient, bytesToClient });
  };

  const failWith = (code: RelayErrorCode, message: string): void => {
    if (settled) return;
    settled = true;
    input.onError(code, message);
  };

  let url: URL;
  let headers: Record<string, string>;
  try {
    // `path` was validated as origin-form by the decoder: it starts with a single
    // slash and cannot begin with `//`, so it cannot escape the base origin.
    url = new URL(input.request.path, input.localBaseUrl);
    headers = normalizeRelayedRequestHeaders(input.request.headers, {
      localAuthority: input.localAuthority,
      localOrigin: input.localBaseUrl,
      clientIp: input.request.clientIp,
    }).headers;
  } catch (error) {
    failWith("internal_error", error instanceof Error ? error.message : "could not build the local request");
    return;
  }

  const outgoing: OutgoingHttpHeaders = { ...headers, host: input.localAuthority };

  let localRequest: ClientRequest;
  try {
    localRequest = createRequest(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port === "" ? undefined : Number(url.port),
        method: input.request.method,
        path: `${url.pathname}${url.search}`,
        headers: outgoing,
      },
      (response: IncomingMessage) => onLocalResponse(response),
    );
  } catch (error) {
    failWith("internal_error", error instanceof Error ? error.message : "could not reach the local app");
    return;
  }

  localRequest.setTimeout(timeoutMs, () => {
    localRequest.destroy(new Error(`the local app did not respond within ${timeoutMs}ms`));
  });
  localRequest.on("error", (error: Error) => {
    failWith("internal_error", `local request failed: ${error.message}`);
  });

  function onLocalResponse(response: IncomingMessage): void {
    if (settled) {
      response.destroy();
      return;
    }

    const responseHeaders: Record<string, string> = {};
    for (const [name, value] of Object.entries(response.headers)) {
      if (value === undefined) continue;
      const lower = name.toLowerCase();
      if (STRIPPED_RESPONSE_HEADERS.has(lower)) continue;
      // Node exposes repeated headers as an array. Joining with ", " matches how
      // a single-valued header of the same name would have been folded.
      responseHeaders[lower] = Array.isArray(value) ? value.join(", ") : value;
    }

    try {
      input.onHead(response.statusCode ?? 502, responseHeaders);
    } catch (error) {
      response.destroy();
      failWith("internal_error", error instanceof Error ? error.message : "could not report the response head");
      return;
    }

    response.on("data", (chunk: Buffer) => {
      bytesToClient += chunk.byteLength;
    });
    response.on("error", (error: Error) => {
      failWith("internal_error", `local response failed: ${error.message}`);
    });
    response.on("end", () => {
      finish();
    });

    response.pipe(input.responseSink);
    input.responseSink.on("error", () => {
      // The browser or the relay went away mid-response. Stop reading rather than
      // buffering into a sink nobody is draining.
      response.destroy();
      failWith("internal_error", "the relayed response could not be written back");
    });
  }

  input.body.on("data", (chunk: Buffer) => {
    bytesFromClient += chunk.byteLength;
  });
  input.body.on("error", (error: Error) => {
    failWith("internal_error", `relayed request body failed: ${error.message}`);
  });
  input.body.pipe(localRequest);
  input.body.on("end", () => {
    localRequest.end();
  });
}