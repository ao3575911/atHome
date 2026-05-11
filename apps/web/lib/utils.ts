import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function maskKey(key: string) {
  if (key.includes("••")) return key;
  return `${key.slice(0, 8)}••••••••••••${key.slice(-4)}`;
}
