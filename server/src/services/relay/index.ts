/**
 * Relay publishing lifecycle for this instance.
 *
 * Everything the relay needs in one place: load configuration, refuse to publish
 * an instance that must not be published, resolve a credential, keep the dialer
 * and stream handler joined, and shut all of it down cleanly.
 *
 * The refusal is the important part. `local_trusted` grants an implicit
 * instance-admin board actor to anything that can reach the socket, with no
 * credential at all. That is a reasonable default for a server bound to loopback
 * on a laptop, and a catastrophic one for a server whose entire purpose is to be
 * reachable from the internet. So the dialer refuses to start rather than
 * publishing, and the refusal names the way out.
 */
import {
  assertRelayPublishable,
  isRelayEnabled,
  loadRelayConfig,
  openTunnelSocket,
  type RelayClientConfig,
  type RelayCredentialStore,
  RelayDialer,
  type RelayDialerEvent,
  RelayGateError,
  type RelayStreamHandlerOptions,
  RelayStreamHandler,
} from "@paperclipai/paperclip-relay";

import { logger } from "../../middleware/logger.js";
import { createRelayCredentialStore, type RelayDb } from "./credential-store.js";
import { readRelayToken, relayTokenStorePath } from "./token-store.js";
import { createControlSocketFactory, createTunnelSocketFactory } from "./ws-adapter.js";

/** Deployment modes the server can run in; kept in step with `server/src/config.ts`. */
export type RelayDeploymentMode = "local_trusted" | "authenticated";

/** Observable state, mirrored into `relay_instance_settings` by the board routes. */
export type RelayRuntimeState =
  | "disabled"
  | "connecting"
  | "connected"
  | "disconnected"
  | "refused";

export interface RelayRuntimeOptions {
  readonly db: RelayDb;
  readonly deploymentMode: RelayDeploymentMode;
  /** Local origin the app listens on; the rewrite target for relayed requests. */
  readonly localBaseUrl: string;
  /** Authority matching it. */
  readonly localAuthority: string;
  readonly paperclipVersion?: string | null;
  readonly env?: NodeJS.ProcessEnv;
  /** Override in tests. */
  readonly createControlSocket?: ReturnType<typeof createControlSocketFactory>;
  readonly createTunnelSocket?: ReturnType<typeof createTunnelSocketFactory>;
  readonly credentialStore?: RelayCredentialStore;
  readonly now?: () => number;
}

export interface RelayRuntimeStatus {
  readonly enabled: boolean;
  readonly published: boolean;
  readonly instanceSlug: string | null;
  readonly sessionId: string | null;
  readonly protocolVersion: number | null;
  readonly maxConcurrentStreams: number | null;
  readonly activeStreams: number;
  readonly state: RelayRuntimeState;
  readonly lastErrorCode: string | null;
  readonly lastErrorMessage: string | null;
}

const DISABLED_STATUS: RelayRuntimeStatus = {
  enabled: false,
  published: false,
  instanceSlug: null,
  sessionId: null,
  protocolVersion: null,
  maxConcurrentStreams: null,
  activeStreams: 0,
  state: "disabled",
  lastErrorCode: null,
  lastErrorMessage: null,
};

/**
 * Owns the relay client half for one instance.
 *
 * Inert until {@link start}, and safe to stop more than once.
 */
export class RelayRuntime {
  private readonly options: RelayRuntimeOptions;
  private readonly env: NodeJS.ProcessEnv;
  /**
   * Resolved once from the same env the rest of the runtime uses.
   *
   * Reading it lazily from `process.env` would be a bug: a runtime configured
   * with one env could present a token read from another, which is exactly the
   * kind of split that only shows up in production.
   */
  private readonly tokenStorePath: string;
  private config: RelayClientConfig | null = null;
  private dialer: RelayDialer | null = null;
  private handler: RelayStreamHandler | null = null;
  private status: RelayRuntimeStatus = { ...DISABLED_STATUS };
  private readonly listeners = new Set<(status: RelayRuntimeStatus) => void>();

  /**
   * Where tunnel sockets go, learned from `hello_ok` and held for the session.
   *
   * Held here rather than re-derived per stream so there is exactly one
   * same-origin-validated value for the whole session.
   */
  private tunnelUrl: string | null = null;

  constructor(options: RelayRuntimeOptions) {
    this.options = options;
    this.env = options.env ?? process.env;
    this.tokenStorePath = relayTokenStorePath(this.env);
  }

  get currentStatus(): RelayRuntimeStatus {
    return { ...this.status, activeStreams: this.handler?.activeCount ?? 0 };
  }

  /**
   * Explain why this instance cannot publish, or null when it can.
   *
   * Separated from {@link start} so a board UI can show the problem beside the
   * toggle instead of failing a request with prose.
   */
  blockedReason(): string | null {
    if (!isRelayEnabled(this.env)) return null;
    try {
      assertRelayPublishable({ deploymentMode: this.options.deploymentMode });
      return null;
    } catch (error) {
      if (RelayGateError.is(error)) return error.message;
      return "relay publishing is unavailable";
    }
  }

  /**
   * Start publishing.
   *
   * @throws RelayGateError when the deployment mode must not be published.
   * @throws RelayConfigError when the configuration cannot be used. Both are
   *   startup failures on purpose: an instance that was told to publish and
   *   silently did not is worse than one that refuses to boot.
   */
  start(): RelayRuntime {
    if (!isRelayEnabled(this.env)) return this;

    // The gate runs before any socket is opened. There is no path in which a
    // local_trusted instance ends up with a live tunnel.
    assertRelayPublishable({ deploymentMode: this.options.deploymentMode });

    this.config = loadRelayConfig(this.env, {
      paperclipVersion: this.options.paperclipVersion ?? null,
    });
    if (!this.config) return this;

    const store = this.options.credentialStore ?? createRelayCredentialStore(this.options.db);
    const createControlSocket = this.options.createControlSocket ?? createControlSocketFactory();
    const createTunnelSocket = this.options.createTunnelSocket ?? createTunnelSocketFactory();

    this.handler = new RelayStreamHandler({
      send: (message) => {
        // The dialer owns encoding, versioning, and whether a session is live.
        if (this.dialer?.sendProtocolMessage(message) === false) {
          logger.debug({ messageType: message.type }, "dropped a stream message with no live session");
        }
      },
      openTunnel: ({ streamNonce }) => {
        if (this.tunnelUrl === null || this.config === null) {
          throw new Error("no relay session has established a tunnel endpoint yet");
        }
        return openTunnelSocket({
          tunnelUrl: this.tunnelUrl,
          controlUrl: this.config.url,
          streamNonce,
          createSocket: createTunnelSocket,
        });
      },
      localBaseUrl: this.options.localBaseUrl,
      localAuthority: this.options.localAuthority,
      maxConcurrentStreams: this.config.maxConcurrentStreams,
    });

    this.dialer = new RelayDialer({
      url: this.config.url,
      instanceSlug: this.config.instanceSlug,
      resolveCredential: () => this.resolveCredential(store),
      createSocket: createControlSocket,
      paperclipVersion: this.options.paperclipVersion ?? null,
      maxConcurrentStreams: this.config.maxConcurrentStreams,
      ...(this.options.now === undefined ? {} : { now: this.options.now }),
    });

    this.dialer.on((event) => this.onDialerEvent(event));
    this.dialer.start();

    this.status = {
      ...this.status,
      enabled: true,
      instanceSlug: this.config.instanceSlug,
      state: "connecting",
    };
    this.publishStatus();

    logger.info(
      {
        instanceSlug: this.config.instanceSlug,
        relayUrl: this.config.url,
        insecureTransport: this.config.insecureTransportAllowed,
        maxConcurrentStreams: this.config.maxConcurrentStreams,
      },
      "relay publishing starting",
    );
    return this;
  }

  /**
   * Read the stored token and confirm it is still usable locally.
   *
   * Checking the store before presenting means a revocation takes effect at once,
   * rather than whenever the relay next notices. An unusable credential resolves
   * to null, which the dialer treats as a permanent refusal rather than retrying
   * forever against a relay that would refuse it anyway.
   */
  private async resolveCredential(store: RelayCredentialStore): Promise<string | null> {
    const token = await readRelayToken(this.tokenStorePath);
    if (token === null) return null;

    const resolution = await store.resolveByToken(token);
    if (!resolution.ok) {
      logger.warn(
        { credentialId: resolution.reason },
        "the stored relay credential is not usable; not presenting it",
      );
      return null;
    }
    return token;
  }

  /** Stop publishing and tear down every live stream. */
  stop(): void {
    this.handler?.closeAll("this instance stopped publishing");
    this.handler?.setSession(null);
    this.dialer?.stop();
    this.dialer = null;
    this.handler = null;
    this.tunnelUrl = null;
    this.status = this.status.enabled
      ? {
          ...this.status,
          published: false,
          sessionId: null,
          protocolVersion: null,
          maxConcurrentStreams: null,
          state: "disconnected",
        }
      : { ...DISABLED_STATUS };
    this.publishStatus();
  }

  /** Ask a permanently refused dialer to try again after an operator fixed it. */
  retry(): void {
    this.dialer?.retryAfterRefusal();
  }

  onStatus(listener: (status: RelayRuntimeStatus) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private onDialerEvent(event: RelayDialerEvent): void {
    switch (event.type) {
      case "ready":
        this.tunnelUrl = event.tunnelUrl;
        this.handler?.setSession({
          controlUrl: this.config?.url ?? "",
          tunnelUrl: event.tunnelUrl,
        });
        this.status = {
          ...this.status,
          published: true,
          state: "connected",
          sessionId: event.sessionId,
          protocolVersion: event.protocolVersion,
          maxConcurrentStreams: event.maxConcurrentStreams,
          lastErrorCode: null,
          lastErrorMessage: null,
        };
        logger.info(
          {
            sessionId: event.sessionId,
            protocolVersion: event.protocolVersion,
            maxConcurrentStreams: event.maxConcurrentStreams,
          },
          "relay session established",
        );
        break;

      case "open_stream":
      case "close_stream":
        this.handler?.handleDialerEvent(event);
        break;

      case "connecting":
        this.status = { ...this.status, state: "connecting" };
        break;

      case "refused":
        this.tunnelUrl = null;
        this.handler?.setSession(null);
        this.status = {
          ...this.status,
          published: false,
          state: "refused",
          sessionId: null,
          protocolVersion: null,
          maxConcurrentStreams: null,
          lastErrorCode: event.code,
          lastErrorMessage: event.message,
        };
        logger.error({ code: event.code, message: event.message }, "relay refused this instance");
        break;

      case "disconnected":
        this.tunnelUrl = null;
        this.handler?.setSession(null);
        this.status = {
          ...this.status,
          published: false,
          state: "connecting",
          sessionId: null,
          protocolVersion: null,
          maxConcurrentStreams: null,
          lastErrorCode: event.code,
          lastErrorMessage: event.message,
        };
        logger.warn({ code: event.code, message: event.message }, "relay session ended");
        break;
    }
    this.publishStatus();
  }

  private publishStatus(): void {
    const snapshot = this.currentStatus;
    for (const listener of this.listeners) {
      try {
        listener(snapshot);
      } catch {
        // A status listener must not be able to break the relay lifecycle.
      }
    }
  }
}