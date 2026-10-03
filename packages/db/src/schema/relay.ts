import { index, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { authUsers } from "./auth.js";

/**
 * Credentials that authenticate an instance's dialer to the relay.
 *
 * ONE credential, ONE job: proving "this control socket belongs to the
 * instance that owns this slug". It asserts nothing about which human is using
 * the tunnel.
 *
 * That is deliberate, and it is the most important design decision in the relay.
 * The obvious alternative is for the relay to tell the instance which local board
 * user each stream acts as, with a trusted-header lane that mints an actor — the
 * shape `cloud_tenant` uses. It is unnecessary here, and it would be the largest
 * avoidable risk in the feature:
 *
 * - The browser already authenticates to Paperclip directly. Its session cookie
 *   rides the tunnel, so the instance authenticates the subscriber itself, using
 *   its own session, memberships, and company scoping. The audit log stays
 *   truthful because the *real* session is in play.
 * - The relay has no way to know Paperclip's users or roles. Anything it asserts
 *   would be a claim the instance would have to trust on the relay's word.
 * - A relay operator already sits in the data path and can read or alter bytes;
 *   that is inherent to a relay and is why the server is open source. What they
 *   must not be able to do is *escalate*, and with no actor assertion there is
 *   nothing to escalate into: every injected request still needs a valid
 *   Paperclip credential that originated from the subscriber.
 *
 * So the relay is a byte pipe with a subscription gate, and this table holds
 * exactly the one credential that gate needs.
 *
 * `token_hash` is a lowercase hex SHA-256, never the token. Tokens carry 256 bits
 * of CSPRNG entropy, so a password KDF would buy nothing — there is no
 * low-entropy secret to make guessing expensive. This matches the instance's
 * existing `board_api_keys` and `agent_api_keys`, which hash the same way for the
 * same reason.
 *
 * Revocation is a timestamp rather than a delete so a revoked credential stays
 * auditable. A revoked row must never be treated as an absent row: "absent" and
 * "revoked" are different answers to "may this instance publish?".
 */
export const relayInstanceCredentials = pgTable(
  "relay_instance_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /**
     * Board user who issued this credential. For audit and attribution only —
     * it grants this user nothing, and deleting the user revokes the credential.
     */
    issuedByUserId: text("issued_by_user_id")
      .notNull()
      .references(() => authUsers.id, { onDelete: "cascade" }),
    /** Operator-facing label so rotated credentials can be told apart. */
    label: text("label").notNull(),
    tokenHash: text("token_hash").notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    /** Set when the credential is time-boxed rather than permanent. */
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tokenHashIdx: uniqueIndex("relay_instance_credentials_token_hash_idx").on(table.tokenHash),
    issuerIdx: index("relay_instance_credentials_issuer_idx").on(table.issuedByUserId),
  }),
);

/**
 * Single-row operational state for this instance's relay publishing.
 *
 * The slug and endpoint stay in the environment: they are deployment
 * configuration, they change when an operator redeploys, and mirroring them here
 * would create two sources of truth that can disagree. What lives here is the
 * mutable, operator-driven state the board UI needs — whether publishing is
 * currently paused, and how the last connection attempt went.
 *
 * `connectionState` is a display value only. Nothing in the authorisation path
 * reads it: a stale `connected` row must never be what convinces an operator or
 * the relay that an instance is published, because a paused or crashed instance
 * would then look live. Liveness is a property of the open socket, never of a
 * row.
 */
export const relayInstanceSettings = pgTable(
  "relay_instance_settings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    singletonKey: text("singleton_key").notNull().default("default"),
    /** Operator-requested pause. Survives restart; the dialer stays down. */
    pausedAt: timestamp("paused_at", { withTimezone: true }),
    connectionState: text("connection_state").notNull().default("disconnected"),
    /** Relay-assigned id of the current or last control session. */
    lastSessionId: text("last_session_id"),
    lastConnectedAt: timestamp("last_connected_at", { withTimezone: true }),
    lastDisconnectedAt: timestamp("last_disconnected_at", { withTimezone: true }),
    /**
     * Last failure, as a stable protocol error code plus short prose. Never a
     * stack trace, a URL carrying credentials, or a raw transport message.
     */
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    /** Snapshot for the board UI. Must never contain a credential or its hash. */
    status: jsonb("status").$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    singletonKeyIdx: uniqueIndex("relay_instance_settings_singleton_key_idx").on(table.singletonKey),
  }),
);

/**
 * Display states for the board UI.
 *
 * `refused` is distinct from `disconnected` on purpose: a refused dialer has a
 * concrete, actionable reason (subscription inactive, slug taken, no credential)
 * whereas a disconnected one may simply be a laptop that went to sleep.
 */
export const RELAY_CONNECTION_STATES = [
  "disconnected",
  "connecting",
  "connected",
  "paused",
  "refused",
] as const;

export type RelayConnectionState = (typeof RELAY_CONNECTION_STATES)[number];