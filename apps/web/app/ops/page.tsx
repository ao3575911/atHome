import { OpsShell } from "@/components/layout/app-shell";
import {
  AbuseQueue,
  AuditTable,
  HealthTable,
  NamespaceModerationTable,
  OpsMetrics,
  OpsWarning,
  UsersTable,
} from "@/components/ops/ops-panels";

export default function OpsPageHome() {
  return (
    <OpsShell title="Ops Command Center">
      <div className="space-y-6">
        <OpsWarning />
        <OpsMetrics />
        <div className="grid gap-6 xl:grid-cols-2">
          <AbuseQueue />
          <HealthTable />
        </div>
      </div>
    </OpsShell>
  );
}
