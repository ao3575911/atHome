import { OpsShell } from "@/components/layout/app-shell";
import {
  HealthTable,
  RegistryFreshnessPanel,
} from "@/components/ops/ops-panels";

export default function OpsPageHealth() {
  return (
    <OpsShell title="Service Health">
      <div className="space-y-6">
        <HealthTable />
        <RegistryFreshnessPanel identityId="krav@atHome" />
      </div>
    </OpsShell>
  );
}
