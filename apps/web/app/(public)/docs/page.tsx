import Link from "next/link";
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
          <h2 className="mt-10 text-2xl font-semibold">
            Mesh capability offers
          </h2>
          <p className="mt-3 max-w-2xl text-muted-foreground">
            An MCO offer is a signed catalog of calls for one service, including
            which other services a call may delegate to. The worked example is
            an actor named trust me bro asking pay to reach vault. That hop is
            denied because the offer never lists it.
          </p>
          <Link
            className="mt-4 inline-block font-semibold text-electric-500"
            href="/developer/mco"
          >
            Open the mesh console
          </Link>
        </section>
        <ApiPreview />
      </main>
    </PageShell>
  );
}
