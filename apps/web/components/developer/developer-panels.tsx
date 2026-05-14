"use client";

import { type FormEvent, useState } from "react";
import {
  AlertTriangle,
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
import { Input, Textarea } from "@/components/ui/input";
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
import {
  sendSignedMutation,
  type MutationOperation,
  type SignedMutationResult,
} from "@/lib/mutation-actions";

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
            Demo-only controls. API key management is not exposed by the local
            protocol API yet.
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

type PlaygroundTab = "resolve" | "registerService" | "issueCapabilityToken";

const TAB_LABELS: Record<PlaygroundTab, string> = {
  resolve: "Resolve",
  registerService: "Register service",
  issueCapabilityToken: "Issue token",
};

const SERVICE_TYPES = [
  "agent",
  "inbox",
  "vault",
  "pay",
  "proof",
  "admin",
  "custom",
] as const;

export function PlaygroundPanel({ name = "krav@atHome" }: { name?: string }) {
  const [tab, setTab] = useState<PlaygroundTab>("resolve");

  // Resolve tab state
  const [namespace, setNamespace] = useState(name);
  const [lookup, setLookup] = useState<ResolveLookup | null>(null);

  // Shared signed-mutation state
  const [identityId, setIdentityId] = useState(name);
  const [privateKey, setPrivateKey] = useState("");
  const [mutationResult, setMutationResult] =
    useState<SignedMutationResult | null>(null);

  // Register service fields
  const [serviceId, setServiceId] = useState("my-agent");
  const [serviceType, setServiceType] =
    useState<(typeof SERVICE_TYPES)[number]>("agent");
  const [serviceEndpoint, setServiceEndpoint] = useState(
    "https://demo.local/agent",
  );

  // Issue token fields
  const [tokenSubject, setTokenSubject] = useState("");
  const [tokenPermissions, setTokenPermissions] = useState("profile:read");
  const [tokenTtl, setTokenTtl] = useState("3600");

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

  async function submitMutation(operation: MutationOperation) {
    setLoading(true);
    try {
      let body: Record<string, unknown>;
      if (operation === "registerService") {
        body = { id: serviceId, type: serviceType, endpoint: serviceEndpoint };
      } else {
        const permissions = tokenPermissions
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean);
        const ttl = parseInt(tokenTtl, 10);
        body = {
          subject: tokenSubject,
          permissions,
          ...(Number.isFinite(ttl) && ttl > 0 ? { ttlSeconds: ttl } : {}),
        };
      }
      setMutationResult(
        await sendSignedMutation({ identityId, privateKey, operation, body }),
      );
    } finally {
      setLoading(false);
    }
  }

  const resolvePreview =
    lookup?.result ??
    maskSensitiveFields({
      ok: true,
      resolvedType: "root",
      rootIdentity: { id: namespace },
      manifestSignatureValid: true,
    });

  const isMutationTab =
    tab === "registerService" || tab === "issueCapabilityToken";

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {(Object.keys(TAB_LABELS) as PlaygroundTab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={[
              "rounded-full px-4 py-1.5 text-sm font-medium transition-colors",
              tab === t
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground",
            ].join(" ")}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left: request form */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Play className="size-5 text-electric-500" /> API playground
            </CardTitle>
            <CardDescription>
              {tab === "resolve"
                ? "Calls the local API when available and keeps response secrets masked by default."
                : "Signs and submits a mutation to the local API. The private key is processed server-side on this machine only."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {tab === "resolve" ? (
              <>
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
              </>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <Badge tone="healthy">POST</Badge>
                  <code className="rounded-full bg-muted px-3 py-1 text-sm">
                    {tab === "registerService"
                      ? "/identities/:id/services"
                      : "/identities/:id/capability-tokens"}
                  </code>
                </div>

                <div className="rounded-2xl border border-amber-500/30 bg-amber-950/20 px-4 py-3 text-xs text-amber-200/80">
                  <AlertTriangle className="mb-1 inline size-3.5" /> DEV ONLY —
                  private key is processed by the local Next.js server, not sent
                  remotely.
                </div>

                <div className="space-y-3">
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      Identity ID
                    </label>
                    <Input
                      value={identityId}
                      onChange={(e) => setIdentityId(e.target.value)}
                      placeholder="krav@atHome"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      Private key (base64 PKCS8)
                    </label>
                    <Input
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      placeholder="From key rotation with export enabled"
                      className="font-mono text-xs"
                    />
                  </div>
                </div>

                {tab === "registerService" ? (
                  <div className="space-y-3">
                    <div>
                      <label className="mb-1 block text-xs text-muted-foreground">
                        Service ID
                      </label>
                      <Input
                        value={serviceId}
                        onChange={(e) => setServiceId(e.target.value)}
                        placeholder="my-agent"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-xs text-muted-foreground">
                        Service type
                      </label>
                      <select
                        value={serviceType}
                        onChange={(e) =>
                          setServiceType(
                            e.target.value as (typeof SERVICE_TYPES)[number],
                          )
                        }
                        className="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                      >
                        {SERVICE_TYPES.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="mb-1 block text-xs text-muted-foreground">
                        Endpoint URL
                      </label>
                      <Input
                        value={serviceEndpoint}
                        onChange={(e) => setServiceEndpoint(e.target.value)}
                        placeholder="https://demo.local/agent"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div>
                      <label className="mb-1 block text-xs text-muted-foreground">
                        Subject identity ID
                      </label>
                      <Input
                        value={tokenSubject}
                        onChange={(e) => setTokenSubject(e.target.value)}
                        placeholder="agent@krav"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-xs text-muted-foreground">
                        Permissions (comma-separated)
                      </label>
                      <Input
                        value={tokenPermissions}
                        onChange={(e) => setTokenPermissions(e.target.value)}
                        placeholder="profile:read, email:draft"
                      />
                    </div>
                    <div>
                      <label className="mb-1 block text-xs text-muted-foreground">
                        TTL seconds
                      </label>
                      <Input
                        value={tokenTtl}
                        onChange={(e) => setTokenTtl(e.target.value)}
                        placeholder="3600"
                        type="number"
                        min="1"
                      />
                    </div>
                  </div>
                )}

                <Button
                  variant="primary"
                  disabled={loading || !identityId || !privateKey}
                  onClick={() => submitMutation(tab as MutationOperation)}
                >
                  {loading ? "Signing…" : "Sign & send"}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Right: response */}
        <Card>
          <CardHeader>
            <CardTitle>Response</CardTitle>
            <CardDescription>
              {isMutationTab
                ? mutationResult
                  ? mutationResult.ok
                    ? "Signed mutation accepted."
                    : "Request failed — check identity ID, key format, and API status."
                  : "Fill in the form and click Sign & send."
                : lookup?.source === "api"
                  ? "Live API response with sensitive fields masked."
                  : "Fixture preview until the local API responds."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {isMutationTab && mutationResult?.authHeader ? (
              <div>
                <p className="mb-1 text-xs text-muted-foreground">
                  X-Home-Authorization
                </p>
                <code className="block break-all rounded-2xl bg-navy-950 p-3 text-xs text-blue-50">
                  {mutationResult.authHeader.slice(0, 60)}…
                </code>
              </div>
            ) : null}
            <pre className="overflow-x-auto rounded-2xl bg-navy-950 p-5 text-sm leading-7 text-blue-50">
              <code>
                {isMutationTab
                  ? mutationResult
                    ? JSON.stringify(mutationResult.response, null, 2)
                    : JSON.stringify(
                        { ok: true, note: "response appears here" },
                        null,
                        2,
                      )
                  : JSON.stringify(resolvePreview, null, 2)}
              </code>
            </pre>
            {isMutationTab && mutationResult?.error ? (
              <p className="text-sm text-muted-foreground">
                {mutationResult.error}
              </p>
            ) : null}
            {!isMutationTab && lookup?.error ? (
              <p className="text-sm text-muted-foreground">
                API unavailable: {lookup.error}
              </p>
            ) : null}
          </CardContent>
        </Card>
      </div>
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
                <code>{`const client = createAtHomeClient("http://127.0.0.1:3000");\n\nawait client.resolve("alex@atHome");`}</code>
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
          <code>{`import { createAtHomeClient } from "@athome/sdk";\n\nconst client = createAtHomeClient("http://127.0.0.1:3000");\n\nconst profile = await client.resolve("alex@atHome");`}</code>
        </pre>
      </CardContent>
    </Card>
  );
}
