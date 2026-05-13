"use client";

import { type FormEvent, useState } from "react";
import {
  Code2,
  Copy,
  KeyRound,
  Play,
  Plus,
  RotateCcw,
  Trash2,
  Webhook,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Textarea } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import {
  apiKeys,
  developerMetrics,
  sdkCards,
  webhookEvents,
} from "@/lib/mock-data";
import { resolveNamespace, type ResolveLookup } from "@/lib/api-client";
import { maskSensitiveFields } from "@/lib/sensitive";

export function MetricsGrid() {
  return (
    <div className="grid gap-4 md:grid-cols-4">
      {developerMetrics.map((metric) => (
        <Card key={metric.label}>
          <CardHeader className="pb-2">
            <CardDescription>{metric.label}</CardDescription>
            <CardTitle className="text-3xl">{metric.value}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{metric.delta}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function ApiKeysPanel() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>API keys</CardTitle>
          <CardDescription>
            Mocked controls. Keys stay masked and destructive actions are
            clearly labeled.
          </CardDescription>
        </div>
        <Button variant="primary">
          <Plus className="size-4" /> Create key
        </Button>
      </CardHeader>
      <CardContent>
        <Table>
          <THead>
            <TR>
              <TH>Name</TH>
              <TH>Key</TH>
              <TH>Scope</TH>
              <TH>Status</TH>
              <TH className="text-right">Actions</TH>
            </TR>
          </THead>
          <TBody>
            {apiKeys.map((key) => (
              <TR key={key.id}>
                <TD>
                  <p className="font-semibold">{key.name}</p>
                  <p className="text-xs text-muted-foreground">
                    Created {key.createdAt} · last used {key.lastUsed}
                  </p>
                </TD>
                <TD className="font-mono">{key.key}</TD>
                <TD>{key.scope}</TD>
                <TD>
                  <Badge
                    tone={key.status === "active" ? "healthy" : "restricted"}
                  >
                    {key.status}
                  </Badge>
                </TD>
                <TD className="space-x-2 text-right">
                  <Button variant="outline" size="sm">
                    <RotateCcw className="size-3" /> Rotate
                  </Button>
                  <Button variant="destructive" size="sm">
                    <Trash2 className="size-3" /> Revoke
                  </Button>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </CardContent>
    </Card>
  );
}

export function PlaygroundPanel() {
  const [namespace, setNamespace] = useState("alex@home");
  const [lookup, setLookup] = useState<ResolveLookup | null>(null);
  const [loading, setLoading] = useState(false);

  async function submitLookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    try {
      setLookup(await resolveNamespace(namespace));
    } finally {
      setLoading(false);
    }
  }

  const responsePreview =
    lookup?.result ??
    maskSensitiveFields({
      ok: true,
      resolvedType: "root",
      rootIdentity: { id: "alex@home" },
      manifestSignatureValid: true,
    });

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Play className="size-5 text-electric-500" /> API playground
          </CardTitle>
          <CardDescription>
            Calls the local API when available and keeps response secrets masked
            by default.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <Badge tone="healthy">POST</Badge>
            <code className="rounded-full bg-muted px-3 py-1 text-sm">
              /resolve
            </code>
          </div>
          <form className="space-y-4" onSubmit={submitLookup}>
            <Textarea
              value={JSON.stringify({ name: namespace }, null, 2)}
              onChange={(event) => {
                try {
                  const parsed = JSON.parse(event.target.value) as {
                    name?: unknown;
                  };
                  if (typeof parsed.name === "string") {
                    setNamespace(parsed.name);
                  }
                } catch {
                  setNamespace(event.target.value);
                }
              }}
              aria-label="Resolve request body"
            />
            <Button variant="primary" type="submit" disabled={loading}>
              {loading ? "Sending" : "Send request"}
            </Button>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Response</CardTitle>
          <CardDescription>
            {lookup?.source === "api"
              ? "Live API response with sensitive fields masked."
              : "Fixture preview until the local API responds."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="overflow-x-auto rounded-2xl bg-navy-950 p-5 text-sm leading-7 text-blue-50">
            <code>{JSON.stringify(responsePreview, null, 2)}</code>
          </pre>
          {lookup?.error ? (
            <p className="mt-3 text-sm text-muted-foreground">
              API unavailable: {lookup.error}
            </p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

export function SdkCards() {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {sdkCards.map((sdk) => (
        <Card key={sdk.name}>
          <CardHeader>
            <Code2 className="size-5 text-electric-500" />
            <CardTitle>{sdk.name}</CardTitle>
            <CardDescription>
              Official SDK package for namespace lookup, profile resolution, and
              permission grants.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between rounded-2xl bg-muted p-3">
              <code className="text-xs">{sdk.command}</code>
              <Copy className="size-4 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function WebhooksPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Webhook className="size-5 text-electric-500" /> Webhook events
        </CardTitle>
        <CardDescription>
          Event delivery metrics use mock but operationally realistic values.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <THead>
            <TR>
              <TH>Event</TH>
              <TH>Deliveries</TH>
              <TH>Success</TH>
              <TH>Last delivery</TH>
            </TR>
          </THead>
          <TBody>
            {webhookEvents.map((event) => (
              <TR key={event.event}>
                <TD className="font-mono">{event.event}</TD>
                <TD>{event.deliveries}</TD>
                <TD>{event.success}</TD>
                <TD>{event.last}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </CardContent>
    </Card>
  );
}

export function DocsPanel() {
  const examples = [
    "authentication",
    "namespace lookup",
    "profile resolution",
    "permission grant",
  ];
  return (
    <div className="grid gap-6 lg:grid-cols-[260px_1fr]">
      <Card>
        <CardHeader>
          <CardTitle>Docs</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {examples.map((item) => (
            <a
              className="block rounded-2xl px-3 py-2 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
              href={`#${item.replaceAll(" ", "-")}`}
              key={item}
            >
              {item}
            </a>
          ))}
        </CardContent>
      </Card>
      <div className="space-y-5">
        {examples.map((item) => (
          <Card id={item.replaceAll(" ", "-")} key={item}>
            <CardHeader>
              <CardTitle className="capitalize">{item}</CardTitle>
              <CardDescription>
                Copy-ready implementation example with fake data only.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-2xl bg-navy-950 p-5 text-sm leading-7 text-blue-50">
                <code>{`await athome.${item.replaceAll(" ", ".")}({\n  namespace: "alex@home",\n  apiKey: "ah_live_••••••••••••4f9a"\n});`}</code>
              </pre>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function LoadingAndEmptyStates() {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Loading skeleton</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-5 w-1/2" />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>No failed deliveries</CardTitle>
          <CardDescription>
            Empty states should confirm the system is quiet, not broken.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
            Webhook delivery queue is empty.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function DeveloperQuickstart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="size-5 text-electric-500" /> Quickstart
        </CardTitle>
        <CardDescription>
          Authenticate, resolve, and grant permissions without exposing secrets
          in the browser.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="overflow-x-auto rounded-2xl bg-navy-950 p-5 text-sm leading-7 text-blue-50">
          <code>{`import { AtHome } from "@athome/sdk";\n\nconst athome = new AtHome({\n  apiKey: "ah_live_••••••••••••4f9a"\n});\n\nconst profile = await athome.namespace.lookup("alex@home");`}</code>
        </pre>
      </CardContent>
    </Card>
  );
}
