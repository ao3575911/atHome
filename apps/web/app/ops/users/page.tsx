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

export default function OpsPageUsers() {
  return (
    <OpsShell title="Users">
      <div className="space-y-6">
        <UsersTable />
      </div>
    </OpsShell>
  );
}
