/**
 * Preconditions an instance must satisfy before it may publish through a relay.
 *
 * This module exists because the failure it prevents is the worst one available
 * in this feature.
 *
 * In `local_trusted` deployment mode the instance grants an implicit
 * instance-admin board actor to anything that can reach its socket, with no
 * credential at all (`server/src/middleware/auth.ts`). That is a reasonable
 * default for a server bound to loopback on a laptop. A relay inverts the
 * assumption: its whole purpose is to make the instance reachable from the
 * internet. Publishing a `local_trusted` instance would therefore hand a full
 * agent shell — repository contents, terminal, credentials, budget — to every
 * stranger who learns the hostname, and the instance's own docs already warn
 * against exactly this ("Never forward the private `local_trusted` board through
 * a public tunnel").
 *
 * So the check is a hard refusal at startup, not a warning. `authenticated` mode
 * is also what makes the relay actor lane safe to add: in that mode loopback
 * carries no ambient authority, so the relay's stream server is the single
 * additional door into the app rather than one of several unauthenticated ones.
 */

/** Deployment modes the Paperclip server can run in. */
export type RelayDeploymentMode = "local_trusted" | "authenticated";

/**
 * The only deployment mode this build will publish.
 *
 * Named rather than inlined so the allowlist has one definition to audit.
 */
const PUBLISHABLE_DEPLOYMENT_MODE: RelayDeploymentMode = "authenticated";

/** Direct listener exposure the instance declares. */
export type RelayDeploymentExposure = "private" | "public";

export interface RelayGateSubject {
  readonly deploymentMode: RelayDeploymentMode;
  /**
   * Not consulted by the current rules, but accepted so the caller does not have
   * to know that. A relayed instance is publicly reachable regardless of what
   * its own listener claims, and conflating the two is how an operator ends up
   * reasoning about the wrong one.
   */
  readonly deploymentExposure?: RelayDeploymentExposure;
}

export class RelayGateError extends Error {
  /**
   * @param code Stable machine code from the shared protocol vocabulary, so a
   *   CLI or the board UI can react to the refusal instead of matching prose.
   */
  readonly code: "deployment_mode_unsupported";

  constructor(message: string) {
    super(message);
    this.name = "RelayGateError";
    this.code = "deployment_mode_unsupported";
  }

  /** Narrowing guard so callers can re-throw foreign errors unchanged. */
  static is(value: unknown): value is RelayGateError {
    return value instanceof RelayGateError;
  }
}

/**
 * Refuse to publish an instance whose deployment mode would treat any reachable
 * caller as an instance administrator.
 *
 * The check is written as an allowlist of the one mode that is safe to publish,
 * not a denylist of `local_trusted`. A denylist answers "is this mode known to be
 * bad?", so a mode string this build has never heard of passes — which is the
 * wrong default when the consequence of passing is a public shell. An allowlist
 * answers "is this mode known to be good?", and a mode added in a future release
 * is refused until someone has decided it is publishable.
 *
 * @throws RelayGateError for every mode other than `authenticated`.
 */
export function assertRelayPublishable(subject: RelayGateSubject): void {
  if (subject.deploymentMode === PUBLISHABLE_DEPLOYMENT_MODE) return;

  if (subject.deploymentMode === "local_trusted") {
    throw new RelayGateError(
      "refusing to publish this instance through a relay: it runs in "
      + "PAPERCLIP_DEPLOYMENT_MODE=local_trusted, which grants unauthenticated "
      + "instance-admin access to anything that can reach the server. A relay exists "
      + "to make this server reachable from the internet, so publishing it would give "
      + "anyone who learns the hostname a shell on this machine and everything in "
      + "this instance's repositories. Set PAPERCLIP_DEPLOYMENT_MODE=authenticated, "
      + "create a board user, and claim the instance from the browser first.",
    );
  }

  throw new RelayGateError(
    `refusing to publish this instance through a relay: deployment mode `
    + `${JSON.stringify(subject.deploymentMode)} is not ${PUBLISHABLE_DEPLOYMENT_MODE}. `
    + `Only a deployment mode that authenticates its callers may be published, and this `
    + `build does not recognise the configured one.`,
  );
}

/**
 * Non-throwing form, for a board UI that wants to show the problem next to the
 * toggle instead of failing a request.
 */
export function relayPublishBlockedReason(subject: RelayGateSubject): string | null {
  try {
    assertRelayPublishable(subject);
    return null;
  } catch (error) {
    return RelayGateError.is(error) ? error.message : "relay publishing is unavailable";
  }
}