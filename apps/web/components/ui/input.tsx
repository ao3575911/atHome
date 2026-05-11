import * as React from "react";
import { cn } from "@/lib/utils";

export function Input({
  className,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-11 w-full rounded-2xl border border-border bg-white px-4 text-sm outline-none transition focus:border-electric-500 focus:ring-4 focus:ring-blue-500/10 dark:bg-white/5",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({
  className,
  ...props
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "min-h-40 w-full rounded-2xl border border-border bg-white p-4 font-mono text-sm outline-none transition focus:border-electric-500 focus:ring-4 focus:ring-blue-500/10 dark:bg-white/5",
        className,
      )}
      {...props}
    />
  );
}
