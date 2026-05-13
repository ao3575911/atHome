import { PageShell } from "@/components/layout/site-shell";
import { ApiPreview } from "@/components/marketing/sections";

export default function PublicDocsPage() {
  return (
    <PageShell>
      <main>
        <section className="mx-auto max-w-7xl px-6 py-16">
          <h1 className="text-4xl font-bold md:text-6xl"> docs</h1>
          <p className="mt-5 max-w-2xl text-lg text-muted-foreground">
            Concepts for namespaces, signed requests, capability tokens,
            privacy-first profile resolution, and application access grants.
          </p>
        </section>
        <ApiPreview />
      </main>
    </PageShell>
  );
}
