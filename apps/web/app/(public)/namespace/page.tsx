import { NamespaceChecker } from "@/components/marketing/sections";
import { PageShell } from "@/components/layout/site-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function NamespacePage() {
  return (
    <PageShell>
      <main className="mx-auto max-w-7xl px-6 py-16">
        <div className="max-w-3xl">
          <h1 className="text-4xl font-bold tracking-tight md:text-6xl">
            Find your home namespace.
          </h1>
          <p className="mt-5 text-lg text-muted-foreground">
            Search personal, organization/team, and application namespaces with
            realistic availability states: available, reserved, taken, and
            restricted.
          </p>
        </div>
        <div className="mt-10 grid gap-8 lg:grid-cols-[0.9fr_1.1fr]">
          <Card>
            <CardHeader>
              <CardTitle>Namespace examples</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-muted-foreground">
              <p>
                <strong className="text-foreground">alex@atHome</strong> —
                personal identity namespace.
              </p>
              <p>
                <strong className="text-foreground">org/team</strong> — verified
                team namespace for groups.
              </p>
              <p>
                <strong className="text-foreground">app.billing@atHome</strong>{" "}
                — application namespace for services and agents.
              </p>
              <Button variant="primary" className="mt-4">
                Reserve namespace
              </Button>
            </CardContent>
          </Card>
          <NamespaceChecker />
        </div>
      </main>
    </PageShell>
  );
}
