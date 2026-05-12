"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import { CreditCard, FileText, FlaskConical, HelpCircle, Home, ShieldCheck, Wallet } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/bank/theme-toggle";

const nav = [
  { href: "/dashboard", label: "Dashboard", icon: Home },
  { href: "/transactions", label: "Transactions", icon: Wallet },
  { href: "/loan-application", label: "Loan Application", icon: FileText },
  { href: "/kyc", label: "KYC Verification", icon: ShieldCheck },
  { href: "/support", label: "Support", icon: HelpCircle },
  { href: "/lab", label: "Lab", icon: FlaskConical, lab: true },
];

export function PortalShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="mx-auto grid w-full max-w-[1400px] flex-1 grid-cols-12 gap-6 px-4 py-6">
        <aside className="col-span-12 rounded-xl border bg-card p-4 shadow-sm md:col-span-3 lg:col-span-2">
          <div className="flex items-center gap-2 px-2 py-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <CreditCard className="h-5 w-5" />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-semibold">NexaBank</div>
              <div className="text-xs text-muted-foreground">Digital Banking</div>
            </div>
          </div>

          <nav className="mt-4 space-y-1">
            {nav.map((item) => {
              const active = pathname === item.href || pathname?.startsWith(item.href + "/");
              const Icon = item.icon;
              const isLab = "lab" in item && item.lab;
              return (
                <Link key={item.href} href={item.href} className="block">
                  <div
                    className={cn(
                      "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                      isLab &&
                        "border border-amber-600/40 bg-amber-500/10 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200",
                      !isLab &&
                        (active ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground")
                    )}
                  >
                    <Icon className={cn("h-4 w-4", isLab && "text-amber-600 dark:text-amber-400")} />
                    <span>{item.label}</span>
                  </div>
                </Link>
              );
            })}
          </nav>
        </aside>

        <section className="col-span-12 md:col-span-9 lg:col-span-10">
          <header className="mb-6 flex items-center justify-between rounded-xl border bg-card px-4 py-3 shadow-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className="rounded border border-amber-600/35 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100"
                title="This portal is a security training lab, not a real bank."
              >
                Training environment
              </span>
              <div>
                <div className="text-sm font-medium">Welcome back</div>
                <div className="text-xs text-muted-foreground">Secure access to your accounts</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <ThemeToggle />
              <Button variant="outline" size="sm" asChild>
                <a href="/support">Contact support</a>
              </Button>
            </div>
          </header>

          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
          >
            {children}
          </motion.div>
        </section>
      </div>

      <footer className="mt-auto border-t bg-muted/30 py-3 text-center text-[11px] text-muted-foreground">
        NexaBank is a fictional company for security training purposes only.
      </footer>
    </div>
  );
}

