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

export default async function DeveloperPagePlayground({
  searchParams,
}: {
  searchParams?: Promise<{ name?: string }>;
}) {
  const params = await searchParams;
  const name = params?.name ?? "krav@atHome";

  return (
    <DeveloperShell title="API Playground">
      <div className="space-y-6">
        <PlaygroundPanel name={name} />
      </div>
    </DeveloperShell>
  );
}
