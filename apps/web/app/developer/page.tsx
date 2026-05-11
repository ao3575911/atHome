import { DeveloperShell } from "@/components/layout/app-shell";
import {
  ApiKeysPanel,
  DeveloperQuickstart,
  DocsPanel,
  LoadingAndEmptyStates,
  MetricsGrid,
  PlaygroundPanel,
  SdkCards,
  WebhooksPanel,
} from "@/components/developer/developer-panels";

export default function DeveloperPageHome() {
  return (
    <DeveloperShell title="Developer Portal">
      <div className="space-y-6">
        <MetricsGrid />
        <div className="mt-6 grid gap-6">
          <DeveloperQuickstart />
          <ApiKeysPanel />
          <LoadingAndEmptyStates />
        </div>
      </div>
    </DeveloperShell>
  );
}
