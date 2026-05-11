import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { buildApp } from "../apps/api/src/app.js";
import { LocalJsonStore } from "../packages/protocol/src/index.js";

const outputPath = join(
  process.cwd(),
  "packages/sdk/src/openapi-schema-names.ts",
);

function renderSchemaNames(names: string[]): string {
  const lines = names.map((name) => `  '${name}',`).join("\n");
  return `export const OPENAPI_SCHEMA_NAMES = [\n${lines}\n] as const;\n\nexport type OpenApiSchemaName = (typeof OPENAPI_SCHEMA_NAMES)[number];\n`;
}

async function main(): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "home-sdk-generate-"));
  const store = new LocalJsonStore(dir);
  const app = buildApp(store);

  try {
    await app.ready();
    const response = await app.inject({
      method: "GET",
      url: "/openapi.json",
    });

    if (response.statusCode !== 200) {
      throw new Error(
        `OpenAPI generation failed with HTTP ${response.statusCode}`,
      );
    }

    const spec = response.json() as {
      components?: {
        schemas?: Record<string, unknown>;
      };
    };

    const names = Object.keys(spec.components?.schemas ?? {}).sort();
    await mkdir(join(process.cwd(), "packages/sdk/src"), { recursive: true });
    await writeFile(outputPath, renderSchemaNames(names), "utf8");
    console.log(
      `Wrote ${outputPath} with ${names.length} pinned schema names.`,
    );
  } finally {
    await app.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
