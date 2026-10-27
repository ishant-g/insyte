import type { ReactNode } from "react";

import { Card, CardContent } from "@/components/ui/card";

function Wordmark() {
  return (
    <div className="flex items-center justify-center gap-2">
      <svg viewBox="0 0 28 28" className="h-7 w-7 shrink-0" aria-hidden="true">
        <rect
          x="1"
          y="1"
          width="26"
          height="26"
          rx="7"
          className="fill-primary/15 stroke-primary"
          strokeWidth="1.5"
        />
        <circle cx="12" cy="12" r="5.5" fill="none" className="stroke-primary" strokeWidth="1.75" />
        <line
          x1="16"
          y1="16"
          x2="21.5"
          y2="21.5"
          className="stroke-primary"
          strokeWidth="1.75"
          strokeLinecap="round"
        />
      </svg>
      <span className="font-mono text-lg font-bold tracking-[0.25em] text-foreground">INSYTE</span>
    </div>
  );
}

export function AuthCard({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <Wordmark />
          <p className="text-xs uppercase tracking-widest text-muted-foreground">
            Passive Exposure Intelligence
          </p>
        </div>
        <Card>
          <CardContent className="pt-6">
            <div className="mb-5">
              <h1 className="text-lg font-semibold text-foreground">{title}</h1>
              {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
            </div>
            {children}
          </CardContent>
        </Card>
        {footer && (
          <p className="mt-4 text-center text-sm text-muted-foreground">{footer}</p>
        )}
      </div>
    </div>
  );
}
