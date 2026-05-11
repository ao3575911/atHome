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

export default function OpsPageAbuse() {
  return (
    <OpsShell title="Abuse Review">
      <div className="space-y-6">
        <AbuseQueue />
      </div>
    </OpsShell>
  );
}
