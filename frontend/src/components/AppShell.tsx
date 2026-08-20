// AppShell — the outer layout (TopBar + content). Dark-first (UX-001).
import type { JSX, ReactNode } from "react";
import { TopBar } from "./TopBar";

export function AppShell({ children }: { children: ReactNode }): JSX.Element {
  return (
    <div className="min-h-screen flex flex-col bg-surface-base">
      <TopBar />
      <main className="flex-1">{children}</main>
      <footer className="px-6 py-3 border-t border-surface-border text-xs text-slate-500">
        Local target · synthetic data only · emits evidence, never a verdict
      </footer>
    </div>
  );
}
