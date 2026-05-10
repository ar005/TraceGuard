"use client";

import { AppShell } from "@/components/shell/app-shell";
import { AuthGuard } from "@/components/shell/auth-guard";

export default function AuthenticatedLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <AppShell>{children}</AppShell>
    </AuthGuard>
  );
}
