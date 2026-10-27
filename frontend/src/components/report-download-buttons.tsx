import { useState } from "react";
import { FileDown, FileText, FileJson2, FileType2 } from "lucide-react";
import { toast } from "sonner";

import { scansApi } from "@/api/scans";
import { ApiError } from "@/lib/api-client";
import { cn } from "@/lib/utils";

const FORMATS: { value: "pdf" | "md" | "json"; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { value: "pdf", label: "PDF", icon: FileType2 },
  { value: "md", label: "Markdown", icon: FileText },
  { value: "json", label: "JSON", icon: FileJson2 },
];

export function ReportDownloadButtons({ scanId }: { scanId: string }) {
  const [pending, setPending] = useState<string | null>(null);

  async function download(format: "pdf" | "md" | "json") {
    setPending(format);
    try {
      const { blob, filename } = await scansApi.downloadReport(scanId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success(`Report downloaded as ${format.toUpperCase()}.`);
    } catch (error) {
      toast.error(error instanceof ApiError ? error.message : "Report download failed.");
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="flex items-center rounded-xl border border-border/70 bg-card p-1 shadow-sm">
      <span className="hidden items-center gap-1.5 px-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground sm:flex">
        <FileDown className="h-3.5 w-3.5" />
        Report
      </span>
      <div className="flex items-center gap-0.5">
        {FORMATS.map((f) => {
          const Icon = f.icon;
          const isPending = pending === f.value;
          return (
            <button
              key={f.value}
              type="button"
              disabled={pending !== null}
              onClick={() => download(f.value)}
              className={cn(
                "flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all duration-150",
                "hover:bg-primary/10 hover:text-primary active:scale-95",
                "disabled:cursor-wait disabled:opacity-60",
                isPending ? "bg-primary/10 text-primary" : "text-muted-foreground",
              )}
            >
              <Icon className={cn("h-3.5 w-3.5", isPending && "insyte-loader")} />
              {isPending ? "…" : f.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
