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

export default function DeveloperPagePlayground() {
  return (
    <DeveloperShell title="API Playground">
      <div className="space-y-6">
        <PlaygroundPanel />
      </div>
    </DeveloperShell>
  );
}
