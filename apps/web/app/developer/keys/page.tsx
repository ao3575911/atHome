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

export default function DeveloperPageKeys() {
  return (
    <DeveloperShell title="API Keys">
      <div className="space-y-6">
        <ApiKeysPanel />
      </div>
    </DeveloperShell>
  );
}
