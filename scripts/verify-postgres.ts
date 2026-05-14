/**
 * Hosted Postgres verification lane.
 *
 * Runs migrations then executes the backend parity suite against a real
 * Postgres database. Requires DATABASE_URL to be set.
 *
 * Usage:
 *   DATABASE_URL=postgres://user:pass@host/db npm run verify:postgres
 */

import { execSync } from "node:child_process";
import { createPostgresRegistryBackend } from "@athome/protocol";
import type { PostgresRegistryBackend } from "@athome/protocol";

const databaseUrl = process.env["DATABASE_URL"];

if (!databaseUrl) {
  console.error("ERROR: DATABASE_URL environment variable is required.");
  process.exit(1);
}

console.log("Running migrations...");
const backend = createPostgresRegistryBackend({
  connectionString: databaseUrl,
}) as PostgresRegistryBackend;

try {
  await backend.runMigrations();
  console.log("Migrations complete.");
} catch (error) {
  console.error("Migration failed:", error);
  process.exit(1);
} finally {
  await backend.end();
}

console.log("Running Postgres parity tests...");
try {
  execSync("npx vitest run packages/protocol/test/backend.test.ts", {
    stdio: "inherit",
    env: { ...process.env, DATABASE_URL: databaseUrl },
  });
  console.log("Postgres verification passed.");
} catch {
  process.exit(1);
}
