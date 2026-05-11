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

export default function OpsPageNamespaces() {
  return (
    <OpsShell title="Namespaces">
      <div className="space-y-6">
        <NamespaceModerationTable />
      </div>
    </OpsShell>
  );
}
