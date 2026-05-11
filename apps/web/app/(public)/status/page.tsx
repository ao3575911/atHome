import { PageShell } from "@/components/layout/site-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serviceHealth } from "@/lib/mock-data";

export default function StatusPage() {
  return (
    <PageShell>
      <main className="mx-auto max-w-5xl px-6 py-16">
        <Badge tone="healthy">Operational status</Badge>
        <h1 className="mt-4 text-4xl font-bold md:text-6xl">Platform status</h1>
        <div className="mt-10 space-y-4">
          {serviceHealth.map((service) => (
            <Card key={service.name}>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>{service.name}</CardTitle>
                <Badge tone={service.status}>{service.status}</Badge>
              </CardHeader>
              <CardContent className="grid gap-3 text-sm text-muted-foreground md:grid-cols-3">
                <span>Latency {service.latency}</span>
                <span>Uptime {service.uptime}</span>
                <span>Owner {service.owner}</span>
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </PageShell>
  );
}
