import { readFile, writeFile } from "node:fs/promises";
import {
  identityDocumentSchema,
  type IdentityKeyMaterial,
  validateIdentityKey,
} from "@athome/identity-core";
import {
  type CreatorTrustAnchor,
  verifyCreatorProof,
} from "@athome/creator-proof";
import { CreatorRegistryClient } from "@athome/registry-client";

export interface CliIo {
  stdout?: (message: string) => void;
  stderr?: (message: string) => void;
  readFile?: (path: string) => Promise<string>;
  writeFile?: (path: string, content: string) => Promise<void>;
  fetch?: typeof fetch;
  now?: () => Date;
  color?: boolean;
}

const usage = `Usage:
  athome identity init <id> --public-key <base64> [--output <file>] [--json]
  athome proof verify <file> --trust-anchor <JSON> [--json]
  athome registry resolve <subject> --url <url> --trust-anchor <JSON> [--json]

Trust anchors are JSON objects: {"issuer":"...","keyId":"...","publicKey":"..."}.
The CLI never generates, prints, or persists private keys.`;

function optionValues(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index + 1];
    if (args[index] === name && value) {
      values.push(value);
    }
  }
  return values;
}

function colorize(
  enabled: boolean,
  code: 31 | 32 | 36,
  message: string,
): string {
  return enabled ? `\u001b[${code}m${message}\u001b[0m` : message;
}

function parseTrustAnchors(
  values: string[],
  createdAt: string,
): CreatorTrustAnchor[] | null {
  const anchors: CreatorTrustAnchor[] = [];

  for (const value of values) {
    let anchor: unknown;
    try {
      anchor = JSON.parse(value);
    } catch {
      return null;
    }
    const record = anchor as Record<string, unknown>;
    if (
      typeof anchor !== "object" ||
      anchor === null ||
      Array.isArray(anchor) ||
      typeof record.issuer !== "string" ||
      typeof record.keyId !== "string" ||
      typeof record.publicKey !== "string" ||
      !record.issuer ||
      !record.keyId ||
      !record.publicKey
    ) {
      return null;
    }

    const key: IdentityKeyMaterial = {
      id: record.keyId,
      algorithm: "Ed25519",
      encoding: "spki-der-base64",
      publicKey: record.publicKey,
      purpose: "root",
      status: "active",
      createdAt,
    };
    anchors.push({ issuer: record.issuer, key });
  }

  return anchors;
}

export async function runCli(
  args: string[],
  overrides: CliIo = {},
): Promise<number> {
  const stdout =
    overrides.stdout ?? ((message) => process.stdout.write(message));
  const stderr =
    overrides.stderr ?? ((message) => process.stderr.write(message));
  const read = overrides.readFile ?? ((path) => readFile(path, "utf8"));
  const write =
    overrides.writeFile ?? ((path, content) => writeFile(path, content));
  const now = overrides.now ?? (() => new Date());
  const color = overrides.color ?? process.stdout.isTTY === true;
  const json = args.includes("--json");
  const error = (message: string, code = 2) => {
    stderr(`${colorize(color, 31, `error: ${message}`)}\n`);
    return code;
  };

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    stdout(`${colorize(color, 36, usage)}\n`);
    return 0;
  }

  if (args[0] === "identity" && args[1] === "init") {
    const id = args[2];
    const publicKey = optionValues(args, "--public-key").at(-1);
    const output = optionValues(args, "--output").at(-1);
    if (!id || !publicKey) {
      return error("identity init requires an id and --public-key");
    }

    const timestamp = now().toISOString();
    const rootKey: IdentityKeyMaterial = {
      id: "root",
      algorithm: "Ed25519",
      encoding: "spki-der-base64",
      publicKey,
      purpose: "root",
      status: "active",
      createdAt: timestamp,
    };
    if (!validateIdentityKey(rootKey).ok) {
      return error("--public-key must be an Ed25519 SPKI DER base64 key");
    }

    const identity = identityDocumentSchema.parse({
      version: "a1",
      id,
      keys: [rootKey],
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const serialized = `${JSON.stringify(identity, null, 2)}\n`;

    try {
      if (output) {
        await write(output, serialized);
      }
    } catch {
      return error("could not write identity document", 1);
    }

    if (json || !output) {
      stdout(serialized);
    } else {
      stdout(
        `${colorize(color, 32, `created public identity document at ${output}`)}\n`,
      );
    }
    return 0;
  }

  if (args[0] === "proof" && args[1] === "verify") {
    const path = args[2];
    if (!path) {
      return error("proof verify requires a proof file");
    }

    let proof: unknown;
    try {
      proof = JSON.parse(await read(path));
    } catch {
      return error("could not read a valid proof document", 1);
    }

    const anchors = parseTrustAnchors(
      optionValues(args, "--trust-anchor"),
      now().toISOString(),
    );
    if (!anchors || anchors.length === 0) {
      return error("proof verification requires --trust-anchor");
    }

    const verification = verifyCreatorProof({
      proof,
      trustAnchors: anchors,
      now: now(),
    });
    if (json) {
      stdout(`${JSON.stringify(verification, null, 2)}\n`);
    } else if (verification.ok) {
      stdout(`${colorize(color, 32, "proof verified")}\n`);
    } else {
      stderr(
        `${colorize(color, 31, `proof rejected: ${verification.reason}`)}\n`,
      );
    }
    return verification.ok ? 0 : 1;
  }

  if (args[0] === "registry" && args[1] === "resolve") {
    const subject = args[2];
    const baseUrl = optionValues(args, "--url").at(-1);
    if (!subject || !baseUrl) {
      return error("registry resolve requires a subject and --url");
    }

    const anchors = parseTrustAnchors(
      optionValues(args, "--trust-anchor"),
      now().toISOString(),
    );
    if (!anchors || anchors.length === 0) {
      return error("registry resolution requires --trust-anchor");
    }

    const resolution = await new CreatorRegistryClient({
      baseUrl,
      fetch: overrides.fetch,
      now,
    }).resolve({ subject, trustAnchors: anchors });
    if (json) {
      stdout(`${JSON.stringify(resolution, null, 2)}\n`);
    } else if (resolution.ok) {
      stdout(`${colorize(color, 32, "registry proof verified")}\n`);
    } else {
      stderr(
        `${colorize(color, 31, `registry resolution failed: ${resolution.reason}`)}\n`,
      );
    }
    return resolution.ok ? 0 : 1;
  }

  return error(`unknown command\n${usage}`);
}
