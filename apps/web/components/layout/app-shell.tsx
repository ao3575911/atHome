import Link from "next/link";
import { LockKeyhole, ShieldAlert } from "lucide-react";
import { Wordmark } from "@/components/brand/logo";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { developerNav, opsNav } from "@/lib/navigation";
import { cn } from "@/lib/utils";

export function DeveloperShell({
  children,
  title = "Developer Portal",
}: {
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <div className="min-h-screen bg-muted/40">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-border bg-background p-6 lg:block">
        <Link href="/">
          <Wordmark />
        </Link>
        <div className="mt-8 rounded-3xl bg-navy-950 p-5 text-white">
          <LockKeyhole className="mb-3 size-5 text-electric-500" />
          <p className="text-sm font-semibold">Signed API access</p>
          <p className="mt-2 text-xs leading-5 text-white/60">
            Mock console data. Secrets stay masked in every surface.
          </p>
        </div>
        <nav className="mt-8 space-y-1" aria-label="Developer navigation">
          {developerNav.map((item) => (
            <Link
              className="block rounded-2xl px-4 py-3 text-sm font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
              href={item.href}
              key={item.href}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="lg:pl-72">
        <header className="border-b border-border bg-background/90 px-6 py-5 backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-between">
            <h1 className="text-xl font-semibold">{title}</h1>
            <div className="flex items-center gap-3">
              <ThemeToggle />
              <Badge tone="healthy">Sandbox workspace</Badge>
            </div>
          </div>
        </header>
        <div className="mx-auto max-w-6xl px-6 py-8">{children}</div>
      </main>
    </div>
  );
}

export function OpsShell({
  children,
  title = "Internal Ops",
}: {
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <div className="min-h-screen bg-[#080b12] text-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-white/10 bg-[#0b101b] p-6 xl:block">
        <Link href="/ops">
          <Wordmark />
        </Link>
        <div className="mt-6 flex items-center gap-2 rounded-2xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          <ShieldAlert className="size-4" /> Internal Ops
        </div>
        <nav className="mt-8 space-y-1" aria-label="Ops navigation">
          {opsNav.map((item) => (
            <Link
              className="block rounded-2xl px-4 py-3 text-sm font-medium text-slate-400 hover:bg-white/10 hover:text-white"
              href={item.href}
              key={item.href}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="xl:pl-72">
        <header className="border-b border-white/10 bg-[#0b101b]/90 px-6 py-5 backdrop-blur">
          <div className="mx-auto flex max-w-7xl items-center justify-between">
            <h1 className="text-xl font-semibold">{title}</h1>
            <Badge
              tone="investigating"
              className={cn(
                "border-amber-400/40 bg-amber-400/10 text-amber-200",
              )}
            >
              Internal Ops
            </Badge>
          </div>
        </header>
        <div className="mx-auto max-w-7xl px-6 py-8">{children}</div>
      </main>
    </div>
  );
}
