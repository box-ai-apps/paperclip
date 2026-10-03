/**
 * The outbound control socket: registration, version negotiation, liveness, and
 * stream dispatch.
 *
 * This module owns one long-lived WebSocket to the relay and the state machine
 * around it. It deliberately does **not** know how to serve a stream: when the
 * relay asks for one, the state machine hands the request to a callback and
 * waits for the answer. Keeping stream serving outside means the handshake,
 * heartbeat, and reconnect behaviour can be tested exhaustively without a single
 * byte of stream traffic, and a stream-serving bug cannot corrupt the control
 * channel's own invariants.
 *
 * Every value arriving from the relay is untrusted and is decoded through the
 * strict decoder. A frame that fails to decode ends the connection rather than
 * being skipped: a peer sending bytes we cannot interpret means we can no longer
 * reason about what it is asking for.
 */
import { redactRelayCredential } from "../credential.js";
import { createControlFrameReader, encodeRelayMessage, type ControlFrameReader } from "../protocol/codec.js";
import { decodeRelayMessage } from "../protocol/decode.js";
import { RelayProtocolError } from "../protocol/errors.js";
import type { RelayErrorCode } from "../protocol/error-codes.js";
import {
  RELAY_CAPABILITIES,
  type RelayHeartbeatMessage,
  type RelayHelloOkMessage,
  type RelayHelloRejectMessage,
  type RelayMessage,
  type RelayOpenStreamMessage,
  type RelayStreamKind,
} from "../protocol/messages.js";
import {
  PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  negotiateProtocolVersion,
} from "../protocol/version.js";
import {
  createBackoffSequence,
  isPermanentRelayError,
  type BackoffOptions,
  type BackoffSequence,
} from "./backoff.js";

/**
 * The subset of a WebSocket client this module uses.
 *
 * Narrower than either `ws` or the browser `WebSocket`, on purpose: only text
 * frames are accepted, so the Buffer-versus-string ambiguity in `ws` never has to
 * be resolved here, and this package stays dependency-free with the `ws` adapter
 * living in `server/src/services/relay`.
 *
 * `on` rather than `addEventListener` because the production adapter is `ws`,
 * which is an EventEmitter.
 */
export interface RelayControlSocket {
  on(event: "open", listener: () => void): void;
  /** Text frames only. A binary frame is the relay's error. */
  on(event: "message", listener: (data: string) => void): void;
  on(event: "close", listener: (code: number, reason: string) => void): void;
  on(event: "error", listener: (error: Error) => void): void;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type RelayControlSocketFactory = (url: string, bearerToken: string) => RelayControlSocket;

/** What the relay wants served. */
export interface RelayStreamRequest {
  readonly streamId: string;
  readonly streamNonce: string;
  readonly kind: RelayStreamKind;
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  /** Address the relay observed for the client, or null when it could not tell. */
  readonly clientIp: string | null;
}

export type RelayStreamDecision =
  | { readonly accept: true }
  | { readonly accept: false; readonly code: RelayErrorCode; readonly message: string };

/**
 * What the dialer reports outward.
 *
 * Exactly one terminal event ends a session: `refused` when an operator must fix
 * something, `disconnected` when the network or the relay hiccuped. Two events
 * for one failure would leave a dashboard showing two errors for one cause and
 * make the reconnect counter meaningless.
 */
export type RelayDialerEvent =
  | { readonly type: "connecting"; readonly attempt: number }
  | {
      readonly type: "ready";
      readonly sessionId: string;
      readonly protocolVersion: number;
      readonly maxConcurrentStreams: number;
    }
  | {
      readonly type: "refused";
      readonly code: string;
      readonly message: string;
      readonly permanent: true;
    }
  | {
      readonly type: "disconnected";
      readonly code: string;
      readonly message: string;
      readonly permanent: false;
    }
  | { readonly type: "open_stream"; readonly request: RelayStreamRequest }
  | { readonly type: "close_stream"; readonly streamId: string; readonly code: string | null };

export type RelayDialerListener = (event: RelayDialerEvent) => void;

export interface RelayDialerOptions {
  /** Relay control endpoint. Already validated by `loadRelayConfig`. */
  readonly url: string;
  /** Slug this instance publishes as. */
  readonly instanceSlug: string;
  /** Resolves the credential presented on the upgrade request. */
  readonly resolveCredential: () => Promise<string | null>;
  readonly createSocket: RelayControlSocketFactory;
  /** Version reported in `hello`; null when it could not be resolved. */
  readonly paperclipVersion?: string | null;
  /**
   * Local floor on concurrent streams, independent of whatever the relay
   * advertises. The effective ceiling is the smaller of the two, so a relay
   * cannot talk this dialer into serving more than it is willing to.
   */
  readonly maxConcurrentStreams?: number;
  /** How long to wait for `hello_ok` or `hello_reject` after the socket opens. */
  readonly handshakeTimeoutMs?: number;
  /** Liveness timeout, as a multiple of the relay's heartbeat interval. */
  readonly heartbeatTimeoutMultiplier?: number;
  /** Reconnect backoff. Injected for deterministic tests. */
  readonly backoff?: BackoffOptions;
  /** Injected clock, for tests. */
  readonly now?: () => number;
  /** Injected randomness, for tests. */
  readonly random?: () => number;
}

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 15_000;
const DEFAULT_HEARTBEAT_TIMEOUT_MULTIPLIER = 2.5;
const DEFAULT_MAX_CONCURRENT_STREAMS = 8;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 15_000;

const CLOSE_CODE_NORMAL = 1000;
/** RFC 6455 policy violation: the relay is refusing this client on purpose. */
const CLOSE_CODE_POLICY_VIOLATION = 1008;

export type RelayDialerState = "idle" | "connecting" | "handshaking" | "ready" | "stopped";

/**
 * Liveness state machine over the control socket.
 *
 * Construct, then {@link start}. It reconnects on its own until it hits a
 * permanent refusal, at which point it stops and waits for
 * {@link retryAfterRefusal}.
 */
export class RelayDialer {
  private readonly resolveCredential: () => Promise<string | null>;
  private readonly createSocket: RelayControlSocketFactory;
  private readonly instanceSlug: string;
  private readonly url: string;
  private readonly paperclipVersion: string | null;
  private readonly localStreamCeiling: number;
  private readonly handshakeTimeoutMs: number;
  private readonly heartbeatTimeoutMultiplier: number;
  private readonly backoff: BackoffSequence;
  private readonly now: () => number;
  private readonly listeners = new Set<RelayDialerListener>();

  private socket: RelayControlSocket | null = null;
  private reader: ControlFrameReader | null = null;
  private state: RelayDialerState = "idle";
  private negotiatedVersion: number | null = null;
  private heartbeatIntervalMs = DEFAULT_HEARTBEAT_INTERVAL_MS;
  private lastInboundAt = 0;
  private heartbeatSeq = 0;
  private stopped = false;

  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: RelayDialerOptions) {
    this.url = options.url;
    this.instanceSlug = options.instanceSlug;
    this.resolveCredential = options.resolveCredential;
    this.createSocket = options.createSocket;
    this.paperclipVersion = options.paperclipVersion ?? null;
    this.localStreamCeiling = options.maxConcurrentStreams ?? DEFAULT_MAX_CONCURRENT_STREAMS;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
    this.heartbeatTimeoutMultiplier =
      options.heartbeatTimeoutMultiplier ?? DEFAULT_HEARTBEAT_TIMEOUT_MULTIPLIER;
    this.backoff = createBackoffSequence({
      ...options.backoff,
      random: options.random ?? options.backoff?.random,
    });
    this.now = options.now ?? Date.now;

    if (!Number.isSafeInteger(this.localStreamCeiling) || this.localStreamCeiling <= 0) {
      throw new Error("maxConcurrentStreams must be a positive safe integer");
    }
    if (!Number.isFinite(this.handshakeTimeoutMs) || this.handshakeTimeoutMs <= 0) {
      throw new Error("handshakeTimeoutMs must be a positive number");
    }
    if (this.heartbeatTimeoutMultiplier <= 1) {
      // At or below 1 the timeout is shorter than the interval, so a healthy
      // quiet relay is torn down before its first heartbeat is due.
      throw new Error("heartbeatTimeoutMultiplier must be greater than 1");
    }
  }

  get currentState(): RelayDialerState {
    return this.state;
  }

  /** The version agreed with the relay, or null before `hello_ok`. */
  get protocolVersion(): number | null {
    return this.negotiatedVersion;
  }

  /** The heartbeat interval currently in force, in milliseconds. */
  get heartbeatInterval(): number {
    return this.heartbeatIntervalMs;
  }

  on(listener: RelayDialerListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Begin connecting, and keep reconnecting until stopped or permanently
   * refused. A second call while already running is a no-op.
   */
  start(): void {
    if (this.state !== "idle") return;
    this.stopped = false;
    this.connect();
  }

  /**
   * Stop connecting and close the socket.
   *
   * Leaves the dialer in `stopped` rather than `idle`, so a stray late event
   * cannot revive a session an operator deliberately tore down.
   */
  stop(): void {
    this.stopped = true;
    const socket = this.teardown();
    this.state = "stopped";
    this.closeSocket(socket, CLOSE_CODE_NORMAL, "dialer stopped");
  }

  /**
   * Try again after a permanent refusal.
   *
   * Separate from {@link start} so "the relay said no" and "an operator fixed it
   * and asked us to retry" stay distinguishable at the call site.
   */
  retryAfterRefusal(): void {
    const socket = this.teardown();
    this.closeSocket(socket, CLOSE_CODE_NORMAL, "retry requested");
    this.stopped = false;
    this.state = "idle";
    this.backoff.reset();
    this.connect();
  }

  /**
   * Emit a stream decision back to the relay.
   *
   * Called by the stream handler in response to an `open_stream` event. Returns
   * false when the session is no longer live, so a handler that finishes after
   * the socket died does not throw.
   */
  respondToStream(streamId: string, decision: RelayStreamDecision): boolean {
    if (this.state !== "ready") return false;
    const v = this.negotiatedVersion ?? PROTOCOL_VERSION;
    if (decision.accept) {
      // Nothing to send: the tunnel socket is the acknowledgement.
      return true;
    }
    try {
      this.send({
        v,
        type: "stream_reject",
        streamId,
        code: decision.code,
        message: decision.message,
      });
    } catch {
      return false;
    }
    return true;
  }

  private connect(): void {
    if (this.stopped) return;
    this.state = "connecting";
    this.emit({ type: "connecting", attempt: this.backoff.attempts });
    void this.openSocket();
  }

  private async openSocket(): Promise<void> {
    let token: string | null;
    try {
      token = await this.resolveCredential();
    } catch (error) {
      // A store that throws is a database problem, not a credential problem.
      // Retry; if it is permanent the same failure recurs with backoff rather
      // than as a refusal the operator has to clear by hand.
      this.endSession("internal_error", describe("could not read the relay credential", error), false);
      return;
    }
    if (this.stopped) return;
    if (token === null) {
      this.endSession(
        "unauthorized_control",
        "this instance has no relay credential to publish with",
        true,
      );
      return;
    }

    let socket: RelayControlSocket;
    try {
      socket = this.createSocket(this.url, token);
    } catch (error) {
      this.endSession("internal_error", describe("could not open the relay control socket", error), false);
      return;
    }

    this.socket = socket;
    this.reader = createControlFrameReader();
    this.state = "handshaking";
    this.lastInboundAt = this.now();

    socket.on("open", () => this.onOpen());
    socket.on("message", (data: string) => this.onMessage(data));
    socket.on("error", (error: Error) => {
      // Node emits `error` before `close`. Record the cause but let `close`
      // drive the transition, so the socket is torn down exactly once.
      this.lastSocketError = error.message;
    });
    socket.on("close", (code: number, reason: string) => {
      this.onClose(code, String(reason ?? ""));
    });
  }

  private lastSocketError: string | null = null;

  private onOpen(): void {
    if (this.state !== "handshaking") return;

    this.handshakeTimer = setTimeout(() => {
      this.endSession("internal_error", "the relay did not complete the handshake in time", false);
    }, this.handshakeTimeoutMs);
    this.handshakeTimer.unref?.();

    try {
      this.send({
        v: PROTOCOL_VERSION,
        type: "hello",
        supportedProtocolVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
        instanceSlug: this.instanceSlug,
        paperclipVersion: this.paperclipVersion,
        capabilities: [...RELAY_CAPABILITIES],
      });
    } catch (error) {
      this.endSession("internal_error", describe("could not send the relay handshake", error), false);
    }
  }

  private onMessage(data: string): void {
    this.lastInboundAt = this.now();
    const reader = this.reader;
    if (!reader) return;

    let frames: string[];
    try {
      frames = reader.push(Buffer.from(data, "utf8"));
    } catch (error) {
      this.endSession(
        RelayProtocolError.is(error) ? error.code : "internal_error",
        describe("the relay sent an oversized control frame", error),
        false,
      );
      return;
    }

    for (const frame of frames) {
      let message: RelayMessage;
      try {
        message = decodeRelayMessage(frame, {
          expectedVersion: this.negotiatedVersion ?? PROTOCOL_VERSION,
        });
      } catch (error) {
        // A frame we cannot parse means we can no longer reason about what the
        // relay is asking. Drop the session instead of skipping it.
        this.endSession(
          RelayProtocolError.is(error) ? error.code : "internal_error",
          describe("the relay sent a control frame this build could not accept", error),
          false,
        );
        return;
      }
      if (!this.handleMessage(message)) return;
    }
  }

  /** @returns false when the message ended the session. */
  private handleMessage(message: RelayMessage): boolean {
    switch (message.type) {
      case "hello_ok":
        return this.onHelloOk(message);
      case "hello_reject":
        this.onHelloReject(message);
        return false;
      case "heartbeat":
        return true;
      case "open_stream":
        if (this.state !== "ready") {
          // A stream request before `hello_ok` means the relay skipped the
          // handshake. Refuse rather than serve on an unnegotiated session.
          this.endSession(
            "internal_error",
            "the relay asked for a stream before completing the handshake",
            false,
          );
          return false;
        }
        this.emit({ type: "open_stream", request: toStreamRequest(message) });
        return true;
      case "close_stream":
        this.emit({
          type: "close_stream",
          streamId: message.streamId,
          code: message.code,
        });
        return true;
      default: {
        // Negotiation agreed a version both sides speak, so the only messages
        // left are ones the *client* is allowed to send. Hearing one back means
        // the relay is confused about who is who, and acting on it would mean
        // treating a client-side instruction as if it came from the server.
        const arrived = message as { type: string };
        this.endSession(
          "internal_error",
          `the relay sent a client-only ${arrived.type} message on the control socket`,
          false,
        );
        return false;
      }
    }
  }

  /** @returns false when the handshake was refused. */
  private onHelloOk(message: RelayHelloOkMessage): boolean {
    // The relay chose a version. Confirm we actually speak it before treating
    // the session as live, so later frames are never decoded under a version
    // this build did not implement.
    const negotiated = negotiateProtocolVersion([message.protocolVersion]);
    if (!negotiated.ok) {
      this.endSession(
        "no_common_protocol_version",
        `the relay selected protocol version ${message.protocolVersion}, which this build does not speak`,
        true,
      );
      return false;
    }

    this.clearHandshakeTimer();
    this.negotiatedVersion = negotiated.version;
    this.heartbeatIntervalMs = message.heartbeatIntervalMs;
    this.state = "ready";
    this.lastInboundAt = this.now();
    this.backoff.reset();
    this.startHeartbeatLoop();

    this.emit({
      type: "ready",
      sessionId: message.sessionId,
      protocolVersion: negotiated.version,
      // The local ceiling is a floor on our own caution: a relay cannot talk
      // this dialer into serving more streams than it is willing to.
      maxConcurrentStreams: Math.min(message.maxConcurrentStreams, this.localStreamCeiling),
    });
    return true;
  }

  private onHelloReject(message: RelayHelloRejectMessage): void {
    this.endSession(message.code, message.message, isPermanentRelayError(message.code));
  }

  /**
   * Drive liveness off a repeating timer.
   *
   * Checking on a timer rather than re-arming on each inbound frame keeps the
   * send rate predictable: one heartbeat per interval regardless of how chatty
   * the relay is, and one timeout check per interval regardless of traffic.
   */
  private startHeartbeatLoop(): void {
    this.stopHeartbeatLoop();
    const intervalMs = this.heartbeatIntervalMs;
    const timeoutMs = Math.round(intervalMs * this.heartbeatTimeoutMultiplier);
    this.heartbeatTimer = setInterval(() => {
      if (this.state !== "ready") {
        this.stopHeartbeatLoop();
        return;
      }
      if (this.now() - this.lastInboundAt > timeoutMs) {
        this.endSession(
          "internal_error",
          `the relay sent nothing for ${timeoutMs}ms, past the agreed heartbeat`,
          false,
        );
        return;
      }
      this.heartbeatSeq += 1;
      const message: RelayHeartbeatMessage = {
        v: this.negotiatedVersion ?? PROTOCOL_VERSION,
        type: "heartbeat",
        seq: this.heartbeatSeq,
      };
      try {
        this.send(message);
      } catch {
        // The timeout above is the real liveness check; a send failure here does
        // not prove the connection is dead, so it is not treated as one.
      }
    }, intervalMs);
    this.heartbeatTimer.unref?.();
  }

  private onClose(code: number, reason: string): void {
    const wasReady = this.state === "ready";
    const socketError = this.lastSocketError;
    // The peer already closed, so there is nothing to close here — but the state
    // must still move off `ready`, or this dialer would go on reporting a live
    // session and would accept stream decisions against a dead socket.
    this.teardown();

    if (this.stopped) return;

    if (code === CLOSE_CODE_POLICY_VIOLATION) {
      this.state = "stopped";
      this.emitRefused(
        "unauthorized_control",
        reason === "" ? "the relay refused this client" : reason,
      );
      return;
    }

    // A session that had been working is not a backoff candidate: hammering the
    // relay after a network blip is the opposite of the right response.
    if (wasReady) this.backoff.reset();
    this.state = "connecting";
    const detail =
      reason !== ""
        ? reason
        : socketError !== null
          ? `socket error: ${socketError}`
          : `close code ${code}`;
    this.emitDisconnected("internal_error", `the relay control socket closed: ${detail}`);
    this.scheduleReconnect();
  }

  /**
   * End the session and either stop or schedule a reconnect.
   *
   * The socket is closed rather than abandoned so the relay sees a clean end
   * instead of holding a half-open registration until its own timeout.
   */
  private endSession(code: string, message: string, permanent: boolean): void {
    if (this.stopped) return;
    const socket = this.teardown();

    if (permanent || isPermanentRelayError(code)) {
      this.stopped = true;
      this.state = "stopped";
      this.closeSocket(socket, CLOSE_CODE_POLICY_VIOLATION, code);
      this.emitRefused(code, message);
      return;
    }

    this.state = "connecting";
    this.closeSocket(socket, CLOSE_CODE_NORMAL, code);
    this.emitDisconnected(code, message);
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    const delay = this.backoff.next();
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
    this.reconnectTimer.unref?.();
  }

  private emitRefused(code: string, message: string): void {
    this.emit({ type: "refused", code, message, permanent: true });
  }

  private emitDisconnected(code: string, message: string): void {
    this.emit({ type: "disconnected", code, message, permanent: false });
  }

  private send(message: RelayMessage): void {
    const socket = this.socket;
    if (!socket) throw new Error("the relay control socket is not open");
    socket.send(encodeRelayMessage(message));
  }

  /**
   * Clear every timer and forget the current socket.
   *
   * Returns the socket rather than closing it, because the right close code
   * differs by caller — a clean end, a policy violation, or nothing at all when
   * the peer closed first. Leaving that choice to the caller keeps a deliberate
   * `stop()` from being reported to the relay as a fault.
   */
  private teardown(): RelayControlSocket | null {
    this.clearHandshakeTimer();
    this.stopHeartbeatLoop();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    const socket = this.socket;
    this.socket = null;
    this.reader = null;
    this.negotiatedVersion = null;
    this.lastSocketError = null;
    return socket;
  }

  private closeSocket(
    socket: RelayControlSocket | null,
    code: number,
    reason: string,
  ): void {
    if (!socket) return;
    try {
      socket.close(code, reason);
    } catch {
      try {
        socket.close();
      } catch {
        /* already gone */
      }
    }
  }

  private clearHandshakeTimer(): void {
    if (!this.handshakeTimer) return;
    clearTimeout(this.handshakeTimer);
    this.handshakeTimer = null;
  }

  private stopHeartbeatLoop(): void {
    if (!this.heartbeatTimer) return;
    clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  private emit(event: RelayDialerEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // A listener must not be able to break the state machine. Its own bug is
        // its problem; tearing down a live session because a status callback
        // threw would be a far worse outcome.
      }
    }
  }
}

function toStreamRequest(message: RelayOpenStreamMessage): RelayStreamRequest {
  return {
    streamId: message.streamId,
    streamNonce: message.streamNonce,
    kind: message.kind,
    method: message.method,
    path: message.path,
    headers: message.headers,
    clientIp: message.clientIp,
  };
}

function describe(message: string, cause: unknown): string {
  return cause instanceof Error ? `${message}: ${cause.message}` : message;
}

export { redactRelayCredential };