import { DeveloperShell } from "@/components/layout/app-shell";
import { McoConsole } from "@/components/developer/mco-console";

export default function DeveloperMcoPage() {
  return (
    <DeveloperShell title="Mesh capability offers">
      <div className="space-y-4">
        <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
          MCO is the mesh of calls a service will accept. The offer is signed by
          the root key, stored as a manifest claim, and checked before a
          delegation is treated as authority. This console runs that check on a
          fixed demo mesh. Publishing an offer on a live identity uses{" "}
          <span className="font-mono">POST /identities/:id/mco</span>.
        </p>
        <McoConsole />
      </div>
    </DeveloperShell>
  );
}
