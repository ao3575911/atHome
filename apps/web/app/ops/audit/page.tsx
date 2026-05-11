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

export default function OpsPageAudit() {
  return (
    <OpsShell title="Audit Log">
      <div className="space-y-6">
        <AuditTable />
      </div>
    </OpsShell>
  );
}
