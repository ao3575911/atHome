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

export default function DeveloperPageWebhooks() {
  return (
    <DeveloperShell title="Webhooks">
      <div className="space-y-6">
        <WebhooksPanel />
      </div>
    </DeveloperShell>
  );
}
