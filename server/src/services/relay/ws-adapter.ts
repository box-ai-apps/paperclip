/**
 * Adapters from the relay client's structural socket interfaces to `ws`.
 *
 * The package defines its own narrow interfaces rather than depending on `ws`, for
 * the reasons in `protocol/index.ts`: text frames only on the control channel, and
 * no ambiguity about Buffer-versus-string. This file is the one place that knows
 * about `ws`, so the rest of the client half stays testable without a network and
 * free of a runtime dependency.
 */
import { WebSocket, type ClientOptions, type RawData } from "ws";

import type {
  RelayControlSocket,
  RelayControlSocketFactory,
  RelayTunnelSocket,
} from "@paperclipai/paperclip-relay";

import { logger } from "../../middleware/logger.js";

/** RFC 6455 policy violation: the peer is refusing this connection on purpose. */
const CLOSE_POLICY_VIOLATION = 1008;

/**
 * A `RelayControlSocket` over a `ws` client.
 *
 * A class rather than an object literal because `on` is an overloaded member; four
 * `on` properties in one literal is a duplicate identifier, not an overload set.
 */
class WsControlSocket implements RelayControlSocket {
  constructor(private readonly socket: WebSocket) {}

  on(event: "open", listener: () => void): void;
  on(event: "message", listener: (data: string) => void): void;
  on(event: "close", listener: (code: number, reason: string) => void): void;
  on(event: "error", listener: (error: Error) => void): void;
  on(event: string, listener: (...args: never[]) => void): void {
    if (event === "message") {
      this.socket.on("message", (data: RawData, isBinary: boolean) => {
        // The control channel is JSON text. A binary frame means the peer changed
        // protocol, so drop the connection loudly rather than letting the decoder
        // reject a stream of garbage frames one at a time.
        if (isBinary) {
          this.socket.close(CLOSE_POLICY_VIOLATION, "binary frame on the control channel");
          return;
        }
        (listener as (value: string) => void)(toText(data));
      });
      return;
    }
    if (event === "close") {
      this.socket.on("close", (code: number, reason: Buffer) => {
        (listener as (code: number, reason: string) => void)(code, reason.toString("utf8"));
      });
      return;
    }
    if (event === "error") {
      this.socket.on("error", listener as (error: Error) => void);
      return;
    }
    this.socket.on("open", listener as () => void);
  }

  send(data: string): void {
    this.socket.send(data);
  }

  close(code?: number, reason?: string): void {
    this.socket.close(code, reason);
  }
}

/**
 * Drain a WebSocket's messages as one ordered byte stream.
 *
 * `ws` preserves message boundaries, but the tunnel protocol is a byte pipe with
 * no framing — the relay owns HTTP framing on the browser side and this side owns
 * it toward the local app. Concatenating payloads in arrival order is therefore
 * correct. What must not happen is reordering or dropping on a boundary, which is
 * why this is a queue with a single waiter rather than an event-emitter `for await`.
 */
function byteStreamFromWebSocket(socket: WebSocket): AsyncIterable<Buffer> {
  return {
    [Symbol.asyncIterator]: () => {
      const queue: Buffer[] = [];
      let done = false;
      let failure: Error | null = null;
      let waiter: (() => void) | null = null;
      let attached = false;

      const wake = (): void => {
        const resolve = waiter;
        waiter = null;
        resolve?.();
      };

      const detach = (): void => {
        if (!attached) return;
        attached = false;
        socket.off("message", onMessage);
        socket.off("close", onClose);
        socket.off("error", onError);
      };

      function onMessage(data: RawData): void {
        queue.push(toBuffer(data));
        wake();
      }

      function onClose(): void {
        done = true;
        detach();
        wake();
      }

      function onError(error: Error): void {
        failure = error;
        done = true;
        detach();
        wake();
      }

      return {
        next: async (): Promise<IteratorResult<Buffer>> => {
          if (!attached) {
            attached = true;
            socket.on("message", onMessage);
            socket.on("close", onClose);
            socket.on("error", onError);
          }
          for (;;) {
            const chunk = queue.shift();
            if (chunk !== undefined) return { value: chunk, done: false };
            if (failure !== null) {
              const error = failure;
              failure = null;
              throw error;
            }
            if (done) return { value: undefined, done: true };
            await new Promise<void>((resolve) => {
              waiter = resolve;
            });
          }
        },
        return: async (): Promise<IteratorResult<Buffer>> => {
          detach();
          done = true;
          return { value: undefined, done: true };
        },
      };
    },
  };
}

function toBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data as ArrayBuffer);
}

function toText(data: RawData): string {
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (Array.isArray(data)) return Buffer.concat(data).toString("utf8");
  return Buffer.from(data as ArrayBuffer).toString("utf8");
}

/**
 * Build the control-socket factory.
 *
 * The relay credential is sent as an `Authorization` header on the upgrade
 * request. This is why the client half does not use the global `WebSocket`: that
 * follows the browser spec, which has no headers option, so the only ways to carry
 * a bearer token would be a query parameter or a subprotocol. Both put a secret
 * somewhere it ends up logged.
 */
export function createControlSocketFactory(
  options: {
    readonly openTimeoutMs?: number;
    readonly headers?: Record<string, string>;
  } = {},
): RelayControlSocketFactory {
  const openTimeoutMs = options.openTimeoutMs ?? 15_000;

  return (url: string, bearerToken: string): RelayControlSocket => {
    const clientOptions: ClientOptions = {
      headers: {
        ...options.headers,
        authorization: `Bearer ${bearerToken}`,
      },
      handshakeTimeout: openTimeoutMs,
    };
    const socket = new WebSocket(url, clientOptions);
    // `binaryType` is an instance property rather than a client option, and
    // "nodebuffer" is what the control channel expects text frames to arrive as.
    socket.binaryType = "nodebuffer";

    return new WsControlSocket(socket);
  };
}

/**
 * Build the tunnel-socket factory.
 *
 * `perMessageDeflate` is disabled deliberately. The tunnel already carries
 * compressed application bytes inside its own framing; adding permessage-deflate
 * underneath means each frame is separately compressed, so a byte stream split
 * across two messages stops being a byte stream. It also costs CPU per frame for
 * no benefit on an already-encrypted hop.
 */
export function createTunnelSocketFactory(
  options: { readonly openTimeoutMs?: number } = {},
): (url: string) => RelayTunnelSocket {
  const openTimeoutMs = options.openTimeoutMs ?? 15_000;

  return (url: string): RelayTunnelSocket => {
    const clientOptions: ClientOptions = {
      handshakeTimeout: openTimeoutMs,
      perMessageDeflate: false,
      // A stream must not be buffered waiting for the peer; the relay pairs this
      // socket with a browser that is already waiting on the other end.
      maxPayload: 64 * 1024 * 1024,
    };
    const socket = new WebSocket(url, clientOptions);
    socket.binaryType = "nodebuffer";

    const closed = new Promise<{ code: number | null; reason: string | null }>((resolve) => {
      let settled = false;
      const settle = (value: { code: number | null; reason: string | null }): void => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      socket.on("close", (code: number, reason: Buffer) => {
        settle({ code, reason: reason.toString("utf8") });
      });
      socket.on("error", (error: Error) => {
        logger.warn({ err: error }, "relay tunnel socket failed");
        settle({ code: null, reason: error.message });
      });
    });

    return {
      inbound: byteStreamFromWebSocket(socket),
      write(chunk: Buffer): void {
        if (socket.readyState !== WebSocket.OPEN) {
          throw new Error("the relay tunnel socket is not open");
        }
        socket.send(chunk, { binary: true });
      },
      end(): void {
        socket.close(1000, "response complete");
      },
      destroy(reason?: string): void {
        try {
          socket.close(CLOSE_POLICY_VIOLATION, (reason ?? "torn down").slice(0, 120));
        } catch {
          socket.terminate();
        }
      },
      closed,
    };
  };
}