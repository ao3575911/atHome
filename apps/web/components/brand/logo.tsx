import { AtSign, Home } from "lucide-react";
import { cn } from "@/lib/utils";

export function LogoMark({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "relative grid size-10 place-items-center rounded-2xl bg-navy-950 text-white shadow-soft dark:bg-white dark:text-navy-950",
        className,
      )}
      aria-hidden="true"
    >
      <Home className="size-6" strokeWidth={2.2} />
      <AtSign className="absolute size-4 text-electric-500" strokeWidth={2.5} />
    </div>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <LogoMark />
      <span className="text-lg font-bold tracking-tight">atHome</span>
    </div>
  );
}
