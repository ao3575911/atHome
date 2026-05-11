import type {
  IdentityManifest,
  PublicKey,
  ServiceEndpoint,
  VerificationOutcome,
} from "./types.js";
import { verifyIdentityManifest } from "./manifest.js";

export function inferRootIdentityId(name: string): string {
  const [localPart, ownerPart] = name.split("@");
  if (!localPart || !ownerPart) {
    throw new Error(`Invalid identity name: ${name}`);
  }

  if (ownerPart === "home") {
    return name;
  }

  return `${ownerPart}@home`;
}

function findRelevantPublicKey(
  manifest: IdentityManifest,
  service?: ServiceEndpoint,
  agent?: { publicKeyId: string },
): PublicKey | undefined {
  const keyId =
    service?.publicKeyId ??
    agent?.publicKeyId ??
    manifest.publicKeys.find((key) => key.purpose === "root")?.id;
  if (!keyId) {
    return undefined;
  }

  return manifest.publicKeys.find((key) => key.id === keyId);
}

export async function resolveIdentity(
  manifest: IdentityManifest | null,
  name: string,
): Promise<{
  rootIdentity: IdentityManifest | null;
  resolvedType: "root" | "service" | "agent" | "unknown";
  resolvedEntry?:
    | ServiceEndpoint
    | { id: string; publicKeyId: string }
    | undefined;
  publicKey?: PublicKey | undefined;
  manifestSignatureValid: boolean;
}> {
  if (!manifest) {
    return {
      rootIdentity: null,
      resolvedType: "unknown",
      manifestSignatureValid: false,
    };
  }

  const manifestSignatureValid = verifyIdentityManifest(manifest).ok;
  if (name === manifest.id) {
    return {
      rootIdentity: manifest,
      resolvedType: "root",
      publicKey: manifest.publicKeys.find((key) => key.purpose === "root"),
      manifestSignatureValid,
    };
  }

  const service = manifest.services.find((entry) => entry.id === name);
  if (service) {
    return {
      rootIdentity: manifest,
      resolvedType: "service",
      resolvedEntry: service,
      publicKey: findRelevantPublicKey(manifest, service),
      manifestSignatureValid,
    };
  }

  const agent = manifest.agents.find((entry) => entry.id === name);
  if (agent) {
    return {
      rootIdentity: manifest,
      resolvedType: "agent",
      resolvedEntry: { id: agent.id, publicKeyId: agent.publicKeyId },
      publicKey: findRelevantPublicKey(manifest, undefined, agent),
      manifestSignatureValid,
    };
  }

  return {
    rootIdentity: manifest,
    resolvedType: "unknown",
    manifestSignatureValid,
  };
}
