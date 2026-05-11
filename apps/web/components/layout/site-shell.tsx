import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { Wordmark } from "@/components/brand/logo";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { publicNav } from "@/lib/navigation";

export function PublicHeader() {
  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/85 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
        <Link href="/" aria-label="atHome home">
          <Wordmark />
        </Link>
        <nav
          className="hidden items-center gap-6 md:flex"
          aria-label="Public navigation"
        >
          {publicNav.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="text-sm font-medium text-muted-foreground hover:text-foreground"
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <Button asChild variant="ghost" className="hidden sm:inline-flex">
            <Link href="/developer">Developers</Link>
          </Button>
          <Button asChild variant="primary">
            <Link href="/namespace">Claim namespace</Link>
          </Button>
        </div>
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="border-t border-border bg-navy-950 text-white dark:bg-black">
      <div className="mx-auto grid max-w-7xl gap-8 px-6 py-12 md:grid-cols-[1.5fr_1fr_1fr_1fr]">
        <div className="space-y-4">
          <Wordmark />
          <p className="max-w-sm text-sm leading-6 text-white/65">
            Secure identity. Seamless access. Always yours. Built for private
            namespaces, signed permissions, and programmable trust.
          </p>
        </div>
        {["Platform", "Developers", "Company"].map((group) => (
          <div key={group}>
            <h2 className="font-semibold">{group}</h2>
            <ul className="mt-4 space-y-3 text-sm text-white/65">
              <li>
                <Link href="/namespace">Namespace</Link>
              </li>
              <li>
                <Link href="/docs">Docs</Link>
              </li>
              <li>
                <Link href="/status">Status</Link>
              </li>
            </ul>
          </div>
        ))}
      </div>
    </footer>
  );
}

export function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <>
      <PublicHeader />
      {children}
      <Footer />
    </>
  );
}

export function TrustStrip() {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-3xl border border-border bg-white/70 p-4 text-sm text-muted-foreground shadow-soft dark:bg-white/5">
      <ShieldCheck className="size-5 text-electric-500" /> Local-first keys,
      masked secrets, revocable permissions, and auditable access by design.
    </div>
  );
}
