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

export default function DeveloperPageSdks() {
  return (
    <DeveloperShell title="SDKs">
      <div className="space-y-6">
        <SdkCards />
      </div>
    </DeveloperShell>
  );
}
