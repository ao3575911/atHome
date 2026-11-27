"use client";

import { useState } from "react";
import { Network } from "lucide-react";
import {
  askMcoMesh,
  type McoConsoleDecision,
} from "@/app/developer/mco/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  MCO_DEMO_ACTORS,
  mcoDemoServiceIds,
  mcoDemoServices,
} from "@/lib/mco-demo";

export function McoConsole() {
  const [actor, setActor] = useState<string>(MCO_DEMO_ACTORS.foreman);
  const [serviceId, setServiceId] = useState("inbox");
  const [delegateServiceId, setDelegateServiceId] = useState("pay");
  const [pending, setPending] = useState(false);
  const [decision, setDecision] = useState<McoConsoleDecision | null>(null);
  const [fault, setFault] = useState<string | null>(null);

  const service = mcoDemoServices.find(
    (entry) => entry.serviceId === serviceId,
  );
  const call = service?.calls[0];

  async function ask() {
    setPending(true);
    setFault(null);
    try {
      const next = await askMcoMesh({
        actor,
        serviceId,
        delegateServiceId:
          delegateServiceId.length > 0 ? delegateServiceId : null,
      });
      setDecision(next);
    } catch {
      setDecision(null);
      setFault("The mesh console could not decide this call.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Network className="size-5 text-electric-500" />
            <CardTitle>Offer mesh</CardTitle>
          </div>
          <CardDescription>
            Each service publishes the call it accepts and the other services
            that call may delegate to. A hop that is not on the offer is denied.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {mcoDemoServices.map((entry) => {
            const offered = entry.calls[0];
            if (!offered) return null;
            const hops =
              offered.delegatesTo.length > 0
                ? offered.delegatesTo.join(", ")
                : "none";
            return (
              <div
                className="rounded-2xl border border-border px-4 py-3 text-sm"
                key={entry.serviceId}
              >
                <div className="font-semibold">{entry.serviceId}</div>
                <p className="mt-1 text-muted-foreground">
                  {offered.method} {offered.path} requires {offered.permission}.
                  May call {hops}.
                </p>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Ask the mesh</CardTitle>
          <CardDescription>
            foreman@krav drafts a message and may call pay. trust me bro asks
            pay to reach vault, and that edge was never signed.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button
              type="button"
              variant={
                actor === MCO_DEMO_ACTORS.foreman ? "primary" : "outline"
              }
              onClick={() => {
                setActor(MCO_DEMO_ACTORS.foreman);
                setServiceId("inbox");
                setDelegateServiceId("pay");
              }}
            >
              {MCO_DEMO_ACTORS.foreman}
            </Button>
            <Button
              type="button"
              variant={
                actor === MCO_DEMO_ACTORS.trustMeBro ? "primary" : "outline"
              }
              onClick={() => {
                setActor(MCO_DEMO_ACTORS.trustMeBro);
                setServiceId("pay");
                setDelegateServiceId("vault");
              }}
            >
              {MCO_DEMO_ACTORS.trustMeBro}
            </Button>
          </div>

          <label className="block space-y-2 text-sm font-medium">
            Actor
            <input
              className="h-11 w-full rounded-2xl border border-border bg-white px-4 text-sm outline-none focus:border-electric-500 dark:bg-white/5"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
            />
          </label>

          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block space-y-2 text-sm font-medium">
              Service
              <select
                className="h-11 w-full rounded-2xl border border-border bg-white px-4 text-sm outline-none focus:border-electric-500 dark:bg-white/5"
                value={serviceId}
                onChange={(event) => setServiceId(event.target.value)}
              >
                {mcoDemoServiceIds.map((id) => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </select>
            </label>
            <label className="block space-y-2 text-sm font-medium">
              Delegate
              <select
                className="h-11 w-full rounded-2xl border border-border bg-white px-4 text-sm outline-none focus:border-electric-500 dark:bg-white/5"
                value={delegateServiceId}
                onChange={(event) => setDelegateServiceId(event.target.value)}
              >
                <option value="">none</option>
                {mcoDemoServiceIds.map((id) => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {call ? (
            <p className="text-sm text-muted-foreground">
              Call on offer: {call.method} {call.path} ({call.permission})
            </p>
          ) : null}

          <Button
            type="button"
            variant="primary"
            disabled={pending}
            onClick={() => void ask()}
          >
            {pending ? "Asking…" : "Ask the mesh"}
          </Button>

          <div aria-live="polite" className="min-h-16">
            {fault ? <p className="text-sm text-red-600">{fault}</p> : null}
            {decision ? <Decision decision={decision} /> : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function Decision({ decision }: { decision: McoConsoleDecision }) {
  const hop = decision.delegateServiceId
    ? ` and delegate to ${decision.delegateServiceId}`
    : "";
  const meme =
    !decision.ok &&
    decision.code === "mco_delegation_not_offered" &&
    decision.actor === MCO_DEMO_ACTORS.trustMeBro;

  return (
    <div className="rounded-2xl border border-border p-4">
      <Badge tone={decision.ok ? "healthy" : "blocked"}>
        {decision.ok ? "Allowed" : "Denied"}
      </Badge>
      <p className="mt-3 text-sm">
        {decision.actor || "The actor"} asked {decision.serviceId} to{" "}
        {decision.method} {decision.path}
        {hop}.
      </p>
      <p className="mt-2 text-sm text-muted-foreground">{decision.reason}</p>
      {meme ? (
        <p className="mt-2 text-sm">
          trust me bro does not get an edge the offer never signed.
        </p>
      ) : null}
      {decision.code ? (
        <p className="mt-2 font-mono text-xs text-muted-foreground">
          {decision.code}
        </p>
      ) : null}
    </div>
  );
}
