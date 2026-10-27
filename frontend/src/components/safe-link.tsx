import { ExternalLink } from "lucide-react";

import { cn } from "@/lib/utils";
import { isSafeUrl } from "@/lib/format";

/** Renders a target-supplied URL as a real link only when it is http(s).
 * Anything else (javascript:, data:, malformed) renders as inert text so it
 * can never be used to smuggle a dangerous href. */
export function SafeLink({
  url,
  className,
  children,
  showIcon = false,
}: {
  url: string | null | undefined;
  className?: string;
  children?: React.ReactNode;
  showIcon?: boolean;
}) {
  const label = children ?? url ?? "";
  if (!isSafeUrl(url)) {
    return <span className={cn("text-foreground", className)}>{label}</span>;
  }
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className={cn(
        "inline-flex items-center gap-1 text-primary underline-offset-2 hover:underline break-all",
        className,
      )}
    >
      {label}
      {showIcon && <ExternalLink className="h-3 w-3 shrink-0" />}
    </a>
  );
}
