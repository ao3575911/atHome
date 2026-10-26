import {
  creatorProofSchema,
  type CreatorProof,
  type CreatorTrustAnchor,
  verifyCreatorProof,
} from "@athome/creator-proof";
import { isA1Timestamp } from "@athome/identity-core";

export type RegistryResolutionFailure =
  | "not_found"
  | "unavailable"
  | "stale"
  | "untrusted"
  | "invalid_configuration";

export interface CreatorRegistryResolution {
  ok: boolean;
  status?: RegistryResolutionFailure | undefined;
  reason?: string | undefined;
  proof?: CreatorProof | undefined;
  updatedAt?: string | undefined;
}

export interface CreatorRegistryClientOptions {
  baseUrl: string;
  fetch?: typeof fetch | undefined;
  now?: () => Date;
  maxStalenessMs?: number | undefined;
  maxFutureSkewMs?: number | undefined;
}

function failure(
  status: RegistryResolutionFailure,
  reason: string,
): CreatorRegistryResolution {
  return { ok: false, status, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class CreatorRegistryClient {
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;
  private readonly maxStalenessMs: number;
  private readonly maxFutureSkewMs: number;

  constructor(private readonly options: CreatorRegistryClientOptions) {
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? (() => new Date());
    this.maxStalenessMs = options.maxStalenessMs ?? 24 * 60 * 60 * 1000;
    this.maxFutureSkewMs = options.maxFutureSkewMs ?? 5 * 60 * 1000;
  }

  async resolve(input: {
    subject: string;
    trustAnchors: readonly CreatorTrustAnchor[];
  }): Promise<CreatorRegistryResolution> {
    let url: URL;
    try {
      const base = new URL(this.options.baseUrl);
      url = new URL(
        `v1/creator-proofs/${encodeURIComponent(input.subject)}`,
        `${base.toString().replace(/\/$/u, "")}/`,
      );
    } catch {
      return failure("unavailable", "Creator registry URL is invalid");
    }

    let response: Response;
    try {
      response = await this.fetchImpl(url);
    } catch {
      return failure("unavailable", "Creator registry is unavailable");
    }

    if (response.status === 404) {
      return failure("not_found", "Creator proof was not found");
    }

    if (!response.ok) {
      return failure("unavailable", "Creator registry returned an error");
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      return failure("untrusted", "Creator registry response is not JSON");
    }

    if (
      !isRecord(payload) ||
      typeof payload.updatedAt !== "string" ||
      !creatorProofSchema.safeParse(payload.proof).success
    ) {
      return failure("untrusted", "Creator registry response is invalid");
    }

    if (!isA1Timestamp(payload.updatedAt)) {
      return failure(
        "untrusted",
        "Creator registry record timestamp is invalid",
      );
    }

    const updatedAt = Date.parse(payload.updatedAt);
    if (
      !Number.isFinite(this.maxStalenessMs) ||
      this.maxStalenessMs < 0 ||
      !Number.isFinite(this.maxFutureSkewMs) ||
      this.maxFutureSkewMs < 0
    ) {
      return failure(
        "invalid_configuration",
        "Creator registry freshness configuration is invalid",
      );
    }

    const now = this.now();
    if (updatedAt > now.getTime() + this.maxFutureSkewMs) {
      return failure(
        "untrusted",
        "Creator registry record timestamp is in the future",
      );
    }

    if (now.getTime() - updatedAt > this.maxStalenessMs) {
      return failure("stale", "Creator registry record is stale");
    }

    const verification = verifyCreatorProof({
      proof: payload.proof,
      trustAnchors: input.trustAnchors,
      now,
    });
    if (!verification.ok || !verification.proof) {
      return failure("untrusted", "Creator registry proof is not trusted");
    }

    if (verification.proof.subject !== input.subject) {
      return failure(
        "untrusted",
        "Creator registry proof subject does not match the requested subject",
      );
    }

    return {
      ok: true,
      proof: verification.proof,
      updatedAt: payload.updatedAt,
    };
  }
}
