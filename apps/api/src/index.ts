import { buildApp } from "./app.js";

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "0.0.0.0";
const demoPrivateKeyExport =
  process.env.NODE_ENV !== "production" &&
  process.env.ATHOME_DEMO_PRIVATE_KEY_EXPORT === "true";
const app = buildApp(undefined, {
  demoPrivateKeyExport,
});

async function main(): Promise<void> {
  const address = await app.listen({ port, host });
  console.log(`Home identity API listening on ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
