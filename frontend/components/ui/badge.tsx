"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium",
  {
    variants: {
      variant: {
        default: "bg-accent/40 text-foreground",
        low: "border-emerald-500/20 bg-emerald-500/10 text-emerald-200",
        medium: "border-amber-500/20 bg-amber-500/10 text-amber-200",
        hard: "border-sky-500/20 bg-sky-500/10 text-sky-200",
        chained: "border-rose-500/20 bg-rose-500/10 text-rose-200",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

