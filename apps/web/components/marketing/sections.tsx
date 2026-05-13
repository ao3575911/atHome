"use client";

import { useMemo, useState } from "react";
import {
  ArrowRight,
  Code2,
  Fingerprint,
  Globe2,
  KeyRound,
  Lock,
  Search,
  ShieldCheck,
  UserCheck,
} from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { TrustStrip } from "@/components/layout/site-shell";
import { getNamespaceState, namespaceExamples } from "@/lib/mock-data";

export function Hero() {
  return (
    <section className="relative overflow-hidden border-b border-border">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_right,rgba(22,119,255,0.18),transparent_35%),linear-gradient(180deg,rgba(255,255,255,1),rgba(244,248,255,0.8))] dark:bg-[radial-gradient(circle_at_top_right,rgba(22,119,255,0.24),transparent_35%),linear-gradient(180deg,#07111f,#0a1020)]" />
      <div className="mx-auto grid max-w-7xl gap-12 px-6 py-24 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
        <div className="space-y-8">
          <Badge tone="investigating">
            Secure private namespace infrastructure
          </Badge>
          <div className="space-y-5">
            <h1 className="max-w-4xl text-5xl font-bold tracking-tight text-navy-950 dark:text-white md:text-7xl">
              Your identity. Your home online.
            </h1>
            <p className="max-w-2xl text-lg leading-8 text-muted-foreground">
              gives people, teams, apps, and agents a private programmable
              namespace with signed access, revocable permissions, and
              infrastructure-grade auditability.
            </p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <Button asChild variant="primary" size="lg">
              <Link href="/namespace">
                Check namespace <ArrowRight className="size-4" />
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg">
              <Link href="/developer">Open developer portal</Link>
            </Button>
          </div>
          <TrustStrip />
        </div>
        <NamespaceChecker />
      </div>
    </section>
  );
}

export function NamespaceChecker() {
  const [value, setValue] = useState("alex@atHome");
  const state = useMemo(() => getNamespaceState(value), [value]);
  const message = {
    available: "Available to reserve",
    reserved: "Reserved for verified organization flow",
    taken: "Already claimed",
    restricted: "Restricted for trust and safety review",
  }[state];
  return (
    <Card className="bg-white/85 backdrop-blur dark:bg-white/5">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="size-5 text-electric-500" /> Namespace availability
        </CardTitle>
        <CardDescription>
          Mock lookup UI showing production states without exposing real account
          data.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex gap-3">
          <Input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            aria-label="Namespace search"
            placeholder="alex@atHome"
          />
          <Button>Search</Button>
        </div>
        <div className="rounded-2xl border border-border bg-muted/50 p-4">
          <div className="flex items-center justify-between gap-4">
            <span className="font-mono text-sm">
              {value || "newname@atHome"}
            </span>
            <Badge tone={state}>{state}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">{message}</p>
        </div>
        <div className="grid gap-3">
          {namespaceExamples.map((item) => (
            <div
              key={item.value}
              className="rounded-2xl border border-border p-4"
            >
              <p className="text-sm font-semibold">
                {item.label}:{" "}
                <span className="font-mono text-electric-500">
                  {item.value}
                </span>
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {item.detail}
              </p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function FeatureGrid() {
  const features = [
    [
      ShieldCheck,
      "Secure by design",
      "Signed manifests, scoped tokens, and replay-aware request verification.",
    ],
    [
      Lock,
      "Private by default",
      "Profiles expose only what each application has been granted permission to see.",
    ],
    [
      KeyRound,
      "Yours always",
      "Portable namespaces and key custody patterns keep identity user-controlled.",
    ],
    [
      Globe2,
      "Universal access",
      "Resolve people, teams, apps, and agents from a single namespace layer.",
    ],
    [
      Code2,
      "Developer friendly",
      "Typed SDKs, webhooks, and simple verification endpoints for fast integration.",
    ],
  ] as const;
  return (
    <section className="mx-auto max-w-7xl px-6 py-20">
      <div className="max-w-2xl">
        <Badge>Platform</Badge>
        <h2 className="mt-4 text-3xl font-bold tracking-tight md:text-5xl">
          Identity infrastructure with a front door humans understand.
        </h2>
      </div>
      <div className="mt-10 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
        {features.map(([Icon, title, text]) => (
          <Card key={title}>
            <CardHeader>
              <Icon className="size-6 text-electric-500" />
              <CardTitle>{title}</CardTitle>
              <CardDescription>{text}</CardDescription>
            </CardHeader>
          </Card>
        ))}
      </div>
    </section>
  );
}

export function HowItWorks() {
  const steps = [
    "Claim namespace",
    "Verify identity",
    "Connect applications",
    "Control permissions",
  ];
  return (
    <section className="bg-navy-950 py-20 text-white">
      <div className="mx-auto max-w-7xl px-6">
        <Badge tone="investigating">How it works</Badge>
        <div className="mt-8 grid gap-5 md:grid-cols-4">
          {steps.map((step, i) => (
            <div
              className="rounded-3xl border border-white/10 bg-white/5 p-6"
              key={step}
            >
              <div className="grid size-10 place-items-center rounded-2xl bg-electric-500 font-bold">
                {i + 1}
              </div>
              <h3 className="mt-6 font-semibold">{step}</h3>
              <p className="mt-2 text-sm leading-6 text-white/60">
                {i === 0
                  ? "Reserve a human-readable home for identity."
                  : i === 1
                    ? "Attach verified keys, recovery, and profile claims."
                    : i === 2
                      ? "Connect apps and agents through signed integrations."
                      : "Grant, restrict, rotate, and revoke access anytime."}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export function ApiPreview() {
  return (
    <section className="mx-auto grid max-w-7xl gap-8 px-6 py-20 lg:grid-cols-2 lg:items-center">
      <div>
        <Badge>API-first</Badge>
        <h2 className="mt-4 text-3xl font-bold tracking-tight md:text-5xl">
          Resolve identity and permissions before your app trusts a request.
        </h2>
        <p className="mt-5 text-muted-foreground">
          Use as the namespace, key, and permission layer for secure access
          across apps and agents.
        </p>
      </div>
      <pre className="overflow-x-auto rounded-3xl bg-navy-950 p-6 text-sm leading-7 text-blue-50 shadow-soft">
        <code>{`const profile = await athome.resolve("alex@atHome");\n\nconst grant = await athome.permissions.grant({\n  subject: "agent@alex",\n  permission: "email:draft",\n  audience: "inbox.app@atHome"\n});\n\nawait athome.verifyRequest(request, grant);`}</code>
      </pre>
    </section>
  );
}

export function SecuritySection() {
  return (
    <section className="mx-auto max-w-7xl px-6 pb-20">
      <Card className="bg-gradient-to-br from-white to-blue-50 dark:from-white/10 dark:to-blue-950/20">
        <CardHeader>
          <Badge tone="healthy">Trust & security</Badge>
          <CardTitle className="text-3xl">
            Infrastructure-grade controls from day one.
          </CardTitle>
          <CardDescription>
            No real secrets are displayed in this demo. Keys are masked,
            destructive operations are explicit, and every privileged action
            belongs in an audit log.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-3">
          {[
            "Masked API keys",
            "Revocable capability tokens",
            "Auditable ops workflows",
          ].map((item) => (
            <div
              className="rounded-2xl border border-border bg-white/70 p-4 text-sm font-semibold dark:bg-white/5"
              key={item}
            >
              <Fingerprint className="mb-3 size-5 text-electric-500" />
              {item}
            </div>
          ))}
        </CardContent>
      </Card>
    </section>
  );
}
