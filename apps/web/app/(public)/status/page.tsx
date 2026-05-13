import { PageShell } from "@/components/layout/site-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getStatusProbes } from "@/lib/api-client";

function statusTone(ok: boolean, status: number | "offline") {
  if (ok) return "healthy";
  if (status === "offline") return "blocked";
  if (status === 404) return "restricted";
  return "degraded";
}

export default async function StatusPage() {
  const probes = await getStatusProbes();
  const hasHealthyEndpoint = probes.some((probe) => probe.ok);

  return (
    <PageShell>
      <main className="mx-auto max-w-5xl px-6 py-16">
        <Badge tone={hasHealthyEndpoint ? "healthy" : "blocked"}>
          {hasHealthyEndpoint ? "API reachable" : "API unavailable"}
        </Badge>
        <h1 className="mt-4 text-4xl font-bold md:text-6xl">Platform status</h1>
        <div className="mt-10 space-y-4">
          {probes.map((probe) => (
            <Card key={probe.endpoint}>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>{probe.endpoint}</CardTitle>
                <Badge tone={statusTone(probe.ok, probe.status)}>
                  {probe.ok ? "healthy" : probe.status}
                </Badge>
              </CardHeader>
              <CardContent className="grid gap-3 text-sm text-muted-foreground md:grid-cols-3">
                <span>
                  Latency{" "}
                  {probe.latencyMs === null
                    ? "unavailable"
                    : `${probe.latencyMs} ms`}
                </span>
                <span>HTTP {probe.status}</span>
                <span>{probe.error ?? "JSON response received"}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </PageShell>
  );
}
