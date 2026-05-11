export type StatusTone =
  | "healthy"
  | "degraded"
  | "investigating"
  | "blocked"
  | "restricted"
  | "available"
  | "reserved"
  | "taken";

export type Metric = {
  label: string;
  value: string;
  delta?: string;
  tone?: StatusTone;
};

export type ApiKey = {
  id: string;
  name: string;
  key: string;
  scope: string;
  createdAt: string;
  lastUsed: string;
  status: "active" | "restricted" | "revoked";
};

export type ServiceHealth = {
  name: string;
  status: Extract<StatusTone, "healthy" | "degraded" | "investigating">;
  latency: string;
  uptime: string;
  owner: string;
};

export type NamespaceState = Extract<
  StatusTone,
  "available" | "reserved" | "taken" | "restricted"
>;
