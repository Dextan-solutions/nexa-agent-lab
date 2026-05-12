"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Card } from "@/components/ui/card";

const nav = [
  { href: "/lab", label: "Console" },
  { href: "/security-level", label: "Security Level" },
  { href: "/objectives", label: "Objectives" },
  { href: "/telemetry", label: "Telemetry" },
  { href: "/replay", label: "Replay" },
];

export default function LabLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isConsole = pathname === "/lab";

  if (isConsole) {
    return <>{children}</>;
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <Card className="mb-6 flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-sm font-semibold">NexaBank Agent Lab</div>
            <div className="text-xs text-muted-foreground">Training controls and visibility layer (separate from NexaBank UI)</div>
          </div>
          <div className="flex items-center gap-3 text-sm">
            {nav.map((n) => (
              <Link
                key={n.href}
                href={n.href}
                className={
                  pathname === n.href ? "font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
                }
              >
                {n.label}
              </Link>
            ))}
            <span className="text-muted-foreground">|</span>
            <Link href="/dashboard" className="hover:text-foreground">
              Back to NexaBank
            </Link>
          </div>
        </Card>

        {children}
      </div>
    </div>
  );
}
