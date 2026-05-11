import type { ApiKey, Metric, NamespaceState, ServiceHealth } from "./types";

export const namespaceExamples = [
  {
    label: "Personal",
    value: "alex@home",
    detail: "Portable identity for people and trusted agents.",
  },
  {
    label: "Team",
    value: "northstar/team",
    detail: "Shared namespace for orgs, teams, and project groups.",
  },
  {
    label: "Application",
    value: "vault.app@home",
    detail: "Programmable identity for private apps and services.",
  },
];

export function getNamespaceState(value: string): NamespaceState {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return "available";
  if (
    ["admin", "root", "security", "support", "trust"].some((term) =>
      normalized.includes(term),
    )
  )
    return "restricted";
  if (["alex@home", "krav@home", "api@home"].includes(normalized))
    return "taken";
  if (normalized.includes("team") || normalized.includes("org"))
    return "reserved";
  return "available";
}

export const developerMetrics: Metric[] = [
  { label: "Requests today", value: "482,019", delta: "+12.4%" },
  { label: "Success rate", value: "99.982%", delta: "24h rolling" },
  { label: "Active keys", value: "18", delta: "3 restricted" },
  { label: "Webhook deliveries", value: "72,441", delta: "99.91% delivered" },
];

export const apiKeys: ApiKey[] = [
  {
    id: "key_prod_1",
    name: "Production resolver",
    key: "ah_live_••••••••••••4f9a",
    scope: "namespace:read profile:resolve",
    createdAt: "May 4, 2026",
    lastUsed: "2 min ago",
    status: "active",
  },
  {
    id: "key_srv_2",
    name: "Server-side grants",
    key: "ah_live_••••••••••••91bc",
    scope: "permission:grant webhook:write",
    createdAt: "May 7, 2026",
    lastUsed: "18 min ago",
    status: "active",
  },
  {
    id: "key_ci_3",
    name: "CI integration",
    key: "ah_test_••••••••••••30ad",
    scope: "namespace:read",
    createdAt: "May 9, 2026",
    lastUsed: "1 day ago",
    status: "restricted",
  },
];

export const webhookEvents = [
  {
    event: "namespace.claimed",
    deliveries: "14,203",
    success: "99.94%",
    last: "31 sec ago",
  },
  {
    event: "permission.granted",
    deliveries: "28,110",
    success: "99.98%",
    last: "1 min ago",
  },
  {
    event: "profile.updated",
    deliveries: "9,871",
    success: "99.89%",
    last: "4 min ago",
  },
  {
    event: "key.revoked",
    deliveries: "257",
    success: "100%",
    last: "37 min ago",
  },
];

export const sdkCards = [
  "JavaScript",
  "Python",
  "Go",
  "PHP",
  ".NET",
  "Java",
].map((name) => ({
  name,
  command:
    name === "JavaScript"
      ? "pnpm add @athome/sdk"
      : name === "Python"
        ? "pip install athome"
        : name === "Go"
          ? "go get athome.dev/sdk"
          : name === "PHP"
            ? "composer require athome/sdk"
            : name === ".NET"
              ? "dotnet add package AtHome.SDK"
              : "mvn install athome-sdk",
}));

export const opsMetrics: Metric[] = [
  { label: "Active users", value: "128,402", delta: "+2,138 this week" },
  { label: "Namespaces claimed", value: "341,980", delta: "71% verified" },
  { label: "API requests", value: "88.4M", delta: "24h" },
  { label: "Failed auth attempts", value: "1,284", delta: "-8.1%" },
  {
    label: "Abuse alerts",
    value: "17",
    delta: "5 high severity",
    tone: "investigating",
  },
  {
    label: "Service health",
    value: "5/6",
    delta: "KMS degraded",
    tone: "degraded",
  },
];

export const users = [
  {
    user: "alex@home",
    email: "alex@example.test",
    status: "healthy",
    namespaces: 3,
    lastSeen: "4 min ago",
  },
  {
    user: "northstar@home",
    email: "ops@northstar.test",
    status: "restricted",
    namespaces: 18,
    lastSeen: "22 min ago",
  },
  {
    user: "maya@home",
    email: "maya@example.test",
    status: "healthy",
    namespaces: 1,
    lastSeen: "1 hour ago",
  },
];

export const namespaceModeration = [
  {
    namespace: "trust-center@home",
    owner: "platform-reserve",
    state: "reserved",
    risk: "Protected platform term",
  },
  {
    namespace: "vault-login@home",
    owner: "unknown",
    state: "restricted",
    risk: "Impersonation review",
  },
  {
    namespace: "northstar/team",
    owner: "northstar@home",
    state: "healthy",
    risk: "Low",
  },
];

export const auditLog = [
  {
    time: "10:14:02",
    actor: "ops.krav",
    action: "rotated webhook signing key",
    target: "northstar@home",
    severity: "healthy",
  },
  {
    time: "10:05:44",
    actor: "abuse.queue",
    action: "flagged namespace",
    target: "vault-login@home",
    severity: "investigating",
  },
  {
    time: "09:58:12",
    actor: "auth.service",
    action: "blocked credential replay",
    target: "api@home",
    severity: "blocked",
  },
  {
    time: "09:41:37",
    actor: "ops.krav",
    action: "exported audit log",
    target: "2026-05-11",
    severity: "healthy",
  },
];

export const abuseQueue = [
  {
    id: "abuse-1841",
    namespace: "vault-login@home",
    signal: "brand impersonation pattern",
    severity: "investigating",
    age: "16 min",
  },
  {
    id: "abuse-1839",
    namespace: "promo-gift@home",
    signal: "phishing language in profile",
    severity: "blocked",
    age: "42 min",
  },
  {
    id: "abuse-1830",
    namespace: "northstar-help@home",
    signal: "user report pending validation",
    severity: "restricted",
    age: "2 hr",
  },
];

export const serviceHealth: ServiceHealth[] = [
  {
    name: "API Gateway",
    status: "healthy",
    latency: "22 ms",
    uptime: "99.999%",
    owner: "Edge",
  },
  {
    name: "Auth Service",
    status: "healthy",
    latency: "31 ms",
    uptime: "99.997%",
    owner: "Identity",
  },
  {
    name: "Namespace Registry",
    status: "healthy",
    latency: "18 ms",
    uptime: "99.998%",
    owner: "Registry",
  },
  {
    name: "Profile Resolver",
    status: "healthy",
    latency: "27 ms",
    uptime: "99.996%",
    owner: "Resolver",
  },
  {
    name: "Webhook Dispatcher",
    status: "investigating",
    latency: "81 ms",
    uptime: "99.91%",
    owner: "Events",
  },
  {
    name: "Key Management Service",
    status: "degraded",
    latency: "104 ms",
    uptime: "99.94%",
    owner: "Security",
  },
];
