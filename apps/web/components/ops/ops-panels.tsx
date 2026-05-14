import {
  AlertTriangle,
  Download,
  Lock,
  RotateCcw,
  Search,
  ShieldX,
  UserX,
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
import { Input } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import {
  fetchAuditEvents,
  fetchRegistryFreshness,
  getStatusProbes,
} from "@/lib/api-client";
import type { StatusTone } from "@/lib/types";
import {
  abuseQueue,
  auditLog,
  namespaceModeration,
  opsMetrics,
  serviceHealth,
  users,
} from "@/lib/mock-data";

function endpointTone(
  ok: boolean,
  status: number | "offline",
): Extract<StatusTone, "healthy" | "degraded" | "blocked" | "restricted"> {
  if (ok) return "healthy";
  if (status === "offline") return "blocked";
  if (status === 404) return "restricted";
  return "degraded";
}

export function OpsMetrics() {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
      {opsMetrics.map((metric) => (
        <div
          key={metric.label}
          className="rounded-3xl border border-white/10 bg-white/[0.04] p-5"
        >
          <p className="text-sm text-slate-400">{metric.label}</p>
          <p className="mt-3 text-3xl font-semibold text-white">
            {metric.value}
          </p>
          <p className="mt-2 text-xs text-slate-500">{metric.delta}</p>
        </div>
      ))}
    </div>
  );
}

function OpsCard({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-3xl border border-white/10 bg-white/[0.04] shadow-2xl shadow-black/20">
      <div className="border-b border-white/10 p-6">
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        {description ? (
          <p className="mt-1 text-sm text-slate-400">{description}</p>
        ) : null}
      </div>
      <div className="p-6">{children}</div>
    </section>
  );
}

export function UsersTable() {
  return (
    <OpsCard
      title="User search and inspection"
      description="Operational controls are mocked and intentionally explicit."
    >
      <div className="mb-4 flex gap-3">
        <Input
          className="border-white/10 bg-black/20 text-white"
          placeholder="Search user, email, namespace"
        />
        <Button variant="outline">
          <Search className="size-4" /> Search
        </Button>
      </div>
      <Table>
        <THead>
          <TR>
            <TH>User</TH>
            <TH>Email</TH>
            <TH>Status</TH>
            <TH>Namespaces</TH>
            <TH>Last seen</TH>
            <TH className="text-right">Action</TH>
          </TR>
        </THead>
        <TBody>
          {users.map((user) => (
            <TR key={user.user} className="hover:bg-white/5">
              <TD className="font-mono text-white">{user.user}</TD>
              <TD>{user.email}</TD>
              <TD>
                <Badge tone={user.status as "healthy" | "restricted"}>
                  {user.status}
                </Badge>
              </TD>
              <TD>{user.namespaces}</TD>
              <TD>{user.lastSeen}</TD>
              <TD className="text-right">
                <Button variant="destructive" size="sm">
                  <UserX className="size-3" /> Suspend user
                </Button>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </OpsCard>
  );
}

export function NamespaceModerationTable() {
  return (
    <OpsCard title="Namespace moderation">
      <Table>
        <THead>
          <TR>
            <TH>Namespace</TH>
            <TH>Owner</TH>
            <TH>State</TH>
            <TH>Risk signal</TH>
            <TH className="text-right">Action</TH>
          </TR>
        </THead>
        <TBody>
          {namespaceModeration.map((item) => (
            <TR key={item.namespace} className="hover:bg-white/5">
              <TD className="font-mono text-white">{item.namespace}</TD>
              <TD>{item.owner}</TD>
              <TD>
                <Badge
                  tone={item.state as "healthy" | "reserved" | "restricted"}
                >
                  {item.state}
                </Badge>
              </TD>
              <TD>{item.risk}</TD>
              <TD className="text-right">
                <Button variant="destructive" size="sm">
                  <Lock className="size-3" /> Lock namespace
                </Button>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </OpsCard>
  );
}

export async function AuditTable() {
  const fetched = await fetchAuditEvents();
  const liveRows = fetched.events.map((event) => ({
    time: event.timestamp,
    actor: event.identityId,
    action: event.type,
    target: event.subjectId,
    severity: "healthy" as const,
    source: "api" as const,
  }));
  const rows =
    liveRows.length > 0
      ? liveRows
      : auditLog.map((row) => ({ ...row, source: "fixture" as const }));

  return (
    <OpsCard
      title="Audit log"
      description={
        fetched.source === "api"
          ? "Live registry events from local API."
          : "Fixture fallback — start the API to see live events."
      }
    >
      <div className="mb-4 flex items-center justify-between gap-4">
        {fetched.error ? (
          <span className="text-xs text-slate-500">{fetched.error}</span>
        ) : (
          <span className="text-xs text-slate-500">
            {rows.length} event{rows.length !== 1 ? "s" : ""}
            {fetched.source === "api" ? " — live" : " — fixture"}
          </span>
        )}
        <Button variant="outline">
          <Download className="size-4" /> Export audit log
        </Button>
      </div>
      <Table>
        <THead>
          <TR>
            <TH>Time</TH>
            <TH>Actor</TH>
            <TH>Action</TH>
            <TH>Target</TH>
            <TH>Severity</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((row, idx) => (
            <TR
              key={`${row.time}-${row.target}-${idx}`}
              className="hover:bg-white/5"
            >
              <TD>{row.time}</TD>
              <TD className="font-mono text-white">{row.actor}</TD>
              <TD>{row.action}</TD>
              <TD>{row.target}</TD>
              <TD>
                <Badge
                  tone={row.severity as "healthy" | "investigating" | "blocked"}
                >
                  {row.severity}
                </Badge>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </OpsCard>
  );
}

export function AbuseQueue() {
  return (
    <OpsCard
      title="Abuse review queue"
      description="Warning states make destructive review paths visible."
    >
      <div className="space-y-4">
        {abuseQueue.map((item) => (
          <div
            key={item.id}
            className="flex flex-col gap-4 rounded-2xl border border-white/10 bg-black/20 p-4 md:flex-row md:items-center md:justify-between"
          >
            <div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 text-amber-300" />
                <p className="font-mono text-sm text-white">{item.namespace}</p>
                <Badge
                  tone={
                    item.severity as "investigating" | "blocked" | "restricted"
                  }
                >
                  {item.severity}
                </Badge>
              </div>
              <p className="mt-2 text-sm text-slate-400">
                {item.signal} · age {item.age}
              </p>
            </div>
            <Button variant="outline" size="sm">
              <ShieldX className="size-3" /> Review alert
            </Button>
          </div>
        ))}
      </div>
    </OpsCard>
  );
}

export async function HealthTable() {
  const probes = await getStatusProbes();
  const liveHealthRows = probes.map((probe) => ({
    name: probe.endpoint,
    status: endpointTone(probe.ok, probe.status),
    latency: probe.latencyMs === null ? "unavailable" : `${probe.latencyMs} ms`,
    uptime: probe.ok ? "reachable" : "unavailable",
    owner: "Local API",
    action: probe.error ?? `HTTP ${probe.status}`,
  }));
  const rows = liveHealthRows.some((row) => row.status === "healthy")
    ? liveHealthRows
    : serviceHealth.map((service) => ({
        ...service,
        action: "fixture fallback",
      }));

  return (
    <OpsCard
      title="Service health"
      description="Live local API probes are shown when reachable; otherwise isolated fixtures keep the panel usable."
    >
      <Table>
        <THead>
          <TR>
            <TH>Service</TH>
            <TH>Status</TH>
            <TH>Latency</TH>
            <TH>Uptime</TH>
            <TH>Owner</TH>
            <TH className="text-right">Action</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((service) => (
            <TR key={service.name} className="hover:bg-white/5">
              <TD className="font-semibold text-white">{service.name}</TD>
              <TD>
                <Badge tone={service.status}>{service.status}</Badge>
              </TD>
              <TD>{service.latency}</TD>
              <TD>{service.uptime}</TD>
              <TD>{service.owner}</TD>
              <TD className="text-right">
                <Button variant="outline" size="sm">
                  <RotateCcw className="size-3" /> {service.action}
                </Button>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </OpsCard>
  );
}

export function OpsWarning() {
  return (
    <Card className="border-red-500/30 bg-red-950/20 text-red-100">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="size-5" /> Namespace lifecycle requires
          signed authorization
        </CardTitle>
        <CardDescription className="text-red-100/70">
          Suspend, restore, transfer, and recover operations require a signed{" "}
          <code className="rounded bg-black/20 px-1">X-Home-Authorization</code>{" "}
          header from the identity&apos;s root key (
          <code className="rounded bg-black/20 px-1">ops:namespace:admin</code>
          ). Admin views use fixture data when the local API is not running.
          Never perform destructive operations without audit logging and
          dual-control approval in production.
        </CardDescription>
      </CardHeader>
    </Card>
  );
}

export async function RegistryFreshnessPanel({
  identityId = "krav@atHome",
}: {
  identityId?: string;
}) {
  const fetched = await fetchRegistryFreshness(identityId);
  const f = fetched.freshness;

  return (
    <OpsCard
      title="Registry freshness"
      description={
        fetched.source === "api"
          ? `Live freshness metadata for ${identityId}.`
          : `Fixture fallback — start the API to see live freshness for ${identityId}.`
      }
    >
      {f ? (
        <Table>
          <TBody>
            <TR>
              <TH className="w-40">Identity</TH>
              <TD className="font-mono text-white">{f.identityId}</TD>
            </TR>
            <TR>
              <TH>Events</TH>
              <TD>{f.eventCount}</TD>
            </TR>
            <TR>
              <TH>Witness receipts</TH>
              <TD>{f.witnessReceiptCount}</TD>
            </TR>
            <TR>
              <TH>Latest event</TH>
              <TD>
                {f.latestEventTimestamp
                  ? new Date(f.latestEventTimestamp).toLocaleString()
                  : "—"}
              </TD>
            </TR>
            <TR>
              <TH>Generated at</TH>
              <TD>
                {f.generatedAt === "fixture"
                  ? "fixture"
                  : new Date(f.generatedAt).toLocaleString()}
              </TD>
            </TR>
          </TBody>
        </Table>
      ) : (
        <p className="text-sm text-slate-400">
          {fetched.error ?? `Identity ${identityId} not found in registry.`}
        </p>
      )}
    </OpsCard>
  );
}
