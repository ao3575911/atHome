import { PageShell } from "@/components/layout/site-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchApiHealth } from "@/lib/api";
import { serviceHealth } from "@/lib/mock-data";

export default async function StatusPage() {
  const apiHealth = await fetchApiHealth();
  const apiStatus = apiHealth.mode === "live" ? "healthy" : "degraded";

  return (
    <PageShell>
      <main className="mx-auto max-w-5xl px-6 py-16">
        <Badge tone={apiStatus}>Operational status</Badge>
        <h1 className="mt-4 text-4xl font-bold md:text-6xl">Platform status</h1>
        <div className="mt-10 space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Registry API</CardTitle>
              <Badge tone={apiStatus}>
                {apiHealth.mode === "live" ? "healthy" : "api offline"}
              </Badge>
            </CardHeader>
            <CardContent className="grid gap-3 text-sm text-muted-foreground md:grid-cols-3">
              <span>Endpoint {apiHealth.baseUrl}</span>
              <span>
                Source {apiHealth.mode === "live" ? "live /health" : "fallback"}
              </span>
              <span>
                {apiHealth.mode === "live"
                  ? "Health check passed"
                  : apiHealth.error}
              </span>
            </CardContent>
          </Card>
          {serviceHealth.map((service) => (
            <Card key={service.name}>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>{service.name}</CardTitle>
                <Badge tone={service.status}>{service.status}</Badge>
              </CardHeader>
              <CardContent className="grid gap-3 text-sm text-muted-foreground md:grid-cols-3">
                <span>Latency {service.latency}</span>
                <span>Uptime {service.uptime}</span>
                <span>Owner {service.owner} · demo signal</span>
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </PageShell>
  );
}
