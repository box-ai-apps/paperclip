/**
 * Serving a stream end to end: relay asks, tunnel socket opens, local app answers.
 *
 * This is the join between the three halves. It owns the concurrency ceiling, the
 * per-stream lifecycle, and the guarantee that every path releases exactly what
 * it took — a leaked slot would eventually wedge the instance with no way to serve
 * anything, and a leaked socket would keep streaming bytes for a stream the relay
 * believes is finished.
 *
 * Cleanup is therefore written once, in {@link retire}, and every exit path calls
 * it. The alternative — a `finally` in each branch — is where the one path that
 * forgets lives.
 */
import { connect as netConnect, type Socket } from "node:net";
import { Readable, Writable } from "node:stream";
import { URL } from "node:url";

import type { RelayDialerEvent, RelayStreamRequest } from "../dialer/control-client.js";
import type { RelayErrorCode } from "../protocol/error-codes.js";
import type { RelayMessage } from "../protocol/messages.js";
import { PROTOCOL_VERSION } from "../protocol/version.js";
import { normalizeRelayedRequestHeaders } from "./normalize.js";
import { readRawResponseHead, serveRelayHttpStream } from "./local-request.js";
import { openTunnelSocket, type RelayTunnelSocket } from "./tunnel-socket.js";

/** Connection to the local app, for streams that need raw byte access. */
export type LocalConnector = (url: string) => Promise<Socket>;

export interface RelayStreamHandlerOptions {
  /** Send a message on the control channel. */
  readonly send: (message: RelayMessage) => void;
  /** Open a tunnel socket for a stream. */
  readonly openTunnel: (input: { streamNonce: string }) => RelayTunnelSocket;
  /** Local origin the app listens on. */
  readonly localBaseUrl: string;
  /** Authority matching it. */
  readonly localAuthority: string;
  /** Ceiling on concurrently served streams. */
  readonly maxConcurrentStreams: number;
  /** Injectable TCP connector. */
  readonly connectLocal?: LocalConnector;
  /** Deadline for the local app to produce a response head. */
  readonly localResponseTimeoutMs?: number;
}

interface ActiveStream {
  readonly streamId: string;
  readonly tunnel: RelayTunnelSocket | null;
  /** Set only on the WebSocket path; the HTTP path talks over `http.request`. */
  local: Socket | null;
  retired: boolean;
}

interface SessionInfo {
  readonly controlUrl: string;
  readonly tunnelUrl: string;
}

export class RelayStreamHandler {
  private readonly options: RelayStreamHandlerOptions;
  private readonly connectLocal: LocalConnector;
  private readonly active = new Map<string, ActiveStream>();
  private session: SessionInfo | null = null;

  constructor(options: RelayStreamHandlerOptions) {
    this.options = options;
    this.connectLocal = options.connectLocal ?? defaultLocalConnector;
    if (!Number.isSafeInteger(options.maxConcurrentStreams) || options.maxConcurrentStreams <= 0) {
      throw new Error("maxConcurrentStreams must be a positive safe integer");
    }
  }

  /** Streams currently being served. */
  get activeCount(): number {
    return this.active.size;
  }

  /** Send a message on the control channel. */
  private send(message: RelayMessage): void {
    this.options.send(message);
  }

  /**
   * Record where tunnel sockets should go, from the dialer's `ready` event.
   *
   * Until this is set, no stream can be served. That is deliberate: opening a
   * tunnel socket without a validated session would mean opening one to an
   * unnegotiated peer.
   */
  setSession(session: SessionInfo | null): void {
    this.session = session;
    if (session === null) this.closeAll("the relay session ended");
  }

  /**
   * React to a dialer event.
   *
   * Only the stream events are handled here; connection lifecycle stays the
   * dialer's business.
   */
  handleDialerEvent(event: RelayDialerEvent): void {
    switch (event.type) {
      case "open_stream":
        void this.serve(event.request);
        return;
      case "close_stream":
        this.retire(event.streamId, `the relay closed this stream (${event.code ?? "no code"})`);
        return;
      default:
        return;
    }
  }

  /**
   * Serve one stream.
   *
   * Never throws: every failure becomes a `stream_error` on the control channel,
   * because the alternative is an unhandled rejection inside a socket callback
   * taking down the process.
   */
  async serve(request: RelayStreamRequest): Promise<void> {
    if (this.active.has(request.streamId)) {
      // Two streams claiming one id means the relay is confused or hostile. The
      // existing stream keeps running; the newcomer is refused rather than being
      // allowed to interleave with it.
      this.reject(request.streamId, "internal_error", "a stream with this id is already open");
      return;
    }

    if (this.session === null) {
      this.reject(request.streamId, "internal_error", "no established relay session");
      return;
    }

    if (this.active.size >= this.options.maxConcurrentStreams) {
      this.reject(request.streamId, "stream_limit_reached", "this instance is at its stream ceiling");
      return;
    }

    let tunnel: RelayTunnelSocket;
    try {
      tunnel = this.options.openTunnel({
        streamNonce: request.streamNonce,
      });
    } catch (error) {
      this.reject(
        request.streamId,
        "internal_error",
        error instanceof Error ? error.message : "could not open the tunnel socket",
      );
      return;
    }

    const entry: ActiveStream = {
      streamId: request.streamId,
      tunnel,
      local: null,
      retired: false,
    };
    this.active.set(request.streamId, entry);

    try {
      if (request.kind === "websocket") {
        await this.serveWebSocket(entry, request);
        return;
      }
      this.serveHttp(entry, request);
    } catch (error) {
      this.fail(
        entry,
        "internal_error",
        error instanceof Error ? error.message : "the stream could not be served",
      );
    }
  }

  private serveHttp(entry: ActiveStream, request: RelayStreamRequest): void {
    const tunnel = entry.tunnel;
    if (!tunnel) throw new Error("the stream has no tunnel socket");

    serveRelayHttpStream({
      request,
      body: readableFrom(tunnel.inbound),
      responseSink: sinkFrom(tunnel),
      localBaseUrl: this.options.localBaseUrl,
      localAuthority: this.options.localAuthority,
      ...(this.options.localResponseTimeoutMs === undefined
        ? {}
        : { localResponseTimeoutMs: this.options.localResponseTimeoutMs }),
      onHead: (status, headers) => {
        this.send({
          v: PROTOCOL_VERSION,
          type: "response_head",
          streamId: entry.streamId,
          status,
          headers,
        });
      },
      onEnd: (counts) => {
        this.complete(entry, counts.bytesFromClient, counts.bytesToClient);
      },
      onError: (code, message) => {
        this.fail(entry, code, message);
      },
    });
  }

  /**
   * Serve a WebSocket stream.
   *
   * This does not open a local WebSocket. It writes the browser's upgrade request
   * to a raw TCP socket and relays the app's own `101` back verbatim, because
   * `Sec-WebSocket-Accept` is derived from the key in the *browser's* request — a
   * locally negotiated handshake would produce an accept value the browser
   * rejects.
   */
  private async serveWebSocket(entry: ActiveStream, request: RelayStreamRequest): Promise<void> {
    const tunnel = entry.tunnel;
    if (!tunnel) throw new Error("the stream has no tunnel socket");

    const socket = await this.connectLocal(this.options.localBaseUrl);
    entry.local = socket;

    const upgradeHeaders = normalizeRelayedRequestHeaders(request.headers, {
      localAuthority: this.options.localAuthority,
      localOrigin: this.options.localBaseUrl,
      clientIp: request.clientIp,
      // `Connection: Upgrade` and `Upgrade: websocket` are the negotiation, not a
      // hop description. Without them the app sees a plain GET and answers 200.
      preserveHandshakeHeaders: true,
    }).headers;

    const lines = [`${request.method} ${request.path} HTTP/1.1`];
    for (const [name, value] of Object.entries(upgradeHeaders)) {
      if (name === "host") continue;
      lines.push(`${name}: ${value}`);
    }
    lines.push(`host: ${this.options.localAuthority}`);
    socket.write(`${lines.join("\r\n")}\r\n\r\n`);

    socket.setTimeout(this.options.localResponseTimeoutMs ?? 30_000, () => {
      socket.destroy(new Error("the local app did not complete the WebSocket handshake in time"));
    });

    const head = await readRawResponseHead(socket, {
      preserveHandshakeHeaders: true,
      ...(this.options.localResponseTimeoutMs === undefined
        ? {}
        : { deadlineMs: this.options.localResponseTimeoutMs }),
    });

    if (entry.retired) {
      socket.destroy();
      return;
    }

    if (head.status !== 101) {
      // The app declined the upgrade. Forwarding the status lets the browser see
      // why — 401 from the session check is the common and useful case.
      this.send({
        v: PROTOCOL_VERSION,
        type: "response_head",
        streamId: entry.streamId,
        status: head.status,
        headers: head.headers,
      });
      socket.destroy();
      this.complete(entry, 0, 0);
      return;
    }

    this.send({
      v: PROTOCOL_VERSION,
      type: "response_head",
      streamId: entry.streamId,
      status: 101,
      headers: head.headers,
    });

    socket.setTimeout(0);

    let bytesFromClient = 0;
    let bytesToClient = 0;

    socket.on("data", (chunk: Buffer) => {
      bytesToClient += chunk.byteLength;
      try {
        tunnel.write(chunk);
      } catch {
        // The browser or the relay went away mid-stream. Stop reading rather than
        // buffering into a socket nobody is draining.
        socket.destroy();
      }
    });
    socket.on("error", () => {
      this.fail(entry, "internal_error", "the local WebSocket connection failed");
    });
    // One close handler, doing both jobs: report the stream finished and tell the
    // relay no more bytes are coming. Registering two would double-count and
    // double-send on every close.
    socket.on("close", () => {
      this.complete(entry, bytesFromClient, bytesToClient);
      tunnel.end();
    });
    socket.on("end", () => {
      socket.end();
    });

    void consume(tunnel.inbound, (chunk) => {
      bytesFromClient += chunk.byteLength;
      if (!socket.destroyed) socket.write(chunk);
    }).catch(() => {
      socket.destroy();
    });
  }

  /** Tear every stream down. Used when the session ends. */
  closeAll(reason: string): void {
    for (const entry of [...this.active.values()]) {
      this.retire(entry.streamId, reason);
    }
  }

  private complete(entry: ActiveStream, bytesFromClient: number, bytesToClient: number): void {
    if (entry.retired) return;
    this.retireStreamOnly(entry);
    this.send({
      v: PROTOCOL_VERSION,
      type: "stream_end",
      streamId: entry.streamId,
      bytesFromClient,
      bytesToClient,
    });
  }

  private fail(entry: ActiveStream, code: RelayErrorCode, message: string): void {
    if (entry.retired) return;
    this.retireStreamOnly(entry);
    this.send({ v: PROTOCOL_VERSION, type: "stream_error", streamId: entry.streamId, code, message });
  }

  /**
   * Release everything a stream took.
   *
   * Sets `retired` first so a re-entrant close from a socket callback cannot run
   * this twice, which would send a second `stream_end` for one stream.
   */
  private retire(streamId: string, reason: string): void {
    const entry = this.active.get(streamId);
    if (!entry) return;
    if (entry.retired) return;
    entry.retired = true;
    this.active.delete(streamId);
    try {
      entry.local?.destroy();
    } catch {
      /* already gone */
    }
    try {
      entry.tunnel?.destroy(reason);
    } catch {
      /* already gone */
    }
  }

  /** Release resources and mark retired, without emitting a terminal message. */
  private retireStreamOnly(entry: ActiveStream): void {
    if (entry.retired) return;
    entry.retired = true;
    this.active.delete(entry.streamId);
    try {
      entry.tunnel?.end();
    } catch {
      /* already ended */
    }
  }

  private reject(streamId: string, code: RelayErrorCode, message: string): void {
    this.send({ v: PROTOCOL_VERSION, type: "stream_reject", streamId, code, message });
  }
}

/** Build a `Readable` over a tunnel socket's inbound byte stream. */
function readableFrom(inbound: AsyncIterable<Buffer>): Readable {
  return Readable.from(inbound);
}

/** Adapt a tunnel socket's `write` to the `Writable` the HTTP path expects. */
function sinkFrom(tunnel: RelayTunnelSocket): Writable {
  return new Writable({
    write(chunk: Buffer, _encoding, callback) {
      try {
        tunnel.write(chunk);
        callback();
      } catch (error) {
        callback(error instanceof Error ? error : new Error("the tunnel socket rejected a write"));
      }
    },
    final(callback) {
      try {
        tunnel.end();
        callback();
      } catch (error) {
        callback(error instanceof Error ? error : new Error("the tunnel socket rejected end"));
      }
    },
  });
}

async function consume(inbound: AsyncIterable<Buffer>, onChunk: (chunk: Buffer) => void): Promise<void> {
  for await (const chunk of inbound) {
    onChunk(chunk);
  }
}

async function defaultLocalConnector(url: string): Promise<Socket> {
  const parsed = new URL(url);
  const port = parsed.port === "" ? 80 : Number(parsed.port);
  return await new Promise<Socket>((resolve, reject) => {
    const socket = netConnect({ host: parsed.hostname, port }, () => {
      socket.setNoDelay(true);
      resolve(socket);
    });
    socket.once("error", reject);
  });
}