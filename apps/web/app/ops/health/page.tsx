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

export default function OpsPageHealth() {
  return (
    <OpsShell title="Service Health">
      <div className="space-y-6">
        <HealthTable />
      </div>
    </OpsShell>
  );
}
