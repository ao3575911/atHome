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

export default function DeveloperPageDocs() {
  return (
    <DeveloperShell title="Developer Docs">
      <div className="space-y-6">
        <DocsPanel />
      </div>
    </DeveloperShell>
  );
}
