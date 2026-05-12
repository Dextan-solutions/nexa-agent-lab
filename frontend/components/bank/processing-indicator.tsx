"use client";

import * as React from "react";

export function ProcessingIndicator({
  show,
  className,
}: {
  show: boolean;
  className?: string;
}) {
  if (!show) return null;

  return (
    <div
      className={[
        "rounded-md border bg-background/40 px-4 py-3 text-sm",
        "flex items-center justify-between gap-3",
        className ?? "",
      ].join(" ")}
      role="status"
      aria-live="polite"
    >
      <div className="leading-snug">
        <div className="font-medium">Your request is being processed.</div>
        <div className="text-muted-foreground">This may take a moment.</div>
      </div>
      <div className="flex items-center gap-1.5">
        <span
          className="h-1.5 w-1.5 rounded-full bg-muted-foreground/70"
          style={{ animation: "agenthiveDots 1.2s infinite ease-in-out", animationDelay: "0ms" }}
        />
        <span
          className="h-1.5 w-1.5 rounded-full bg-muted-foreground/70"
          style={{ animation: "agenthiveDots 1.2s infinite ease-in-out", animationDelay: "200ms" }}
        />
        <span
          className="h-1.5 w-1.5 rounded-full bg-muted-foreground/70"
          style={{ animation: "agenthiveDots 1.2s infinite ease-in-out", animationDelay: "400ms" }}
        />
        <style jsx>{`
          @keyframes agenthiveDots {
            0%,
            100% {
              opacity: 0.35;
              transform: translateY(0);
            }
            50% {
              opacity: 0.95;
              transform: translateY(-2px);
            }
          }
        `}</style>
      </div>
    </div>
  );
}

