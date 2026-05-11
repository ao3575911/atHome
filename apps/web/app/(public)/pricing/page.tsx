import { PageShell } from "@/components/layout/site-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const tiers = [
  [
    "Personal",
    "$0",
    "Claim one namespace, manage profile permissions, connect trusted apps.",
  ],
  [
    "Developer",
    "$29",
    "API access, test keys, webhooks, SDK support, and usage analytics.",
  ],
  [
    "Infrastructure",
    "Custom",
    "Enterprise custody, audit exports, org namespaces, and SSO controls.",
  ],
];
export default function PricingPage() {
  return (
    <PageShell>
      <main className="mx-auto max-w-7xl px-6 py-16">
        <Badge>Pricing</Badge>
        <h1 className="mt-4 text-4xl font-bold md:text-6xl">
          Start private. Scale programmable.
        </h1>
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          {tiers.map(([name, price, text]) => (
            <Card key={name}>
              <CardHeader>
                <CardTitle>{name}</CardTitle>
                <p className="text-4xl font-bold">{price}</p>
              </CardHeader>
              <CardContent>
                <p className="min-h-20 text-sm leading-6 text-muted-foreground">
                  {text}
                </p>
                <Button
                  className="mt-6 w-full"
                  variant={name === "Developer" ? "primary" : "outline"}
                >
                  Choose {name}
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </PageShell>
  );
}
