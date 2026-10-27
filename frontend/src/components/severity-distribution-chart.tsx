import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from "recharts";

import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { titleCase } from "@/lib/format";

const ORDER = ["critical", "high", "medium", "low", "informational"] as const;

const SEVERITY_FILL: Record<(typeof ORDER)[number], string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  informational: "var(--severity-informational)",
};

const config: ChartConfig = {
  count: { label: "Findings" },
  critical: { label: "Critical", color: "var(--severity-critical)" },
  high: { label: "High", color: "var(--severity-high)" },
  medium: { label: "Medium", color: "var(--severity-medium)" },
  low: { label: "Low", color: "var(--severity-low)" },
  informational: { label: "Informational", color: "var(--severity-informational)" },
};

export function SeverityDistributionChart({ counts }: { counts: Record<string, number> }) {
  const data = ORDER.filter((s) => (counts[s] ?? 0) > 0 || Object.keys(counts).length === 0).map((s) => ({
    severity: s,
    label: titleCase(s),
    count: counts[s] ?? 0,
  }));

  return (
    <ChartContainer config={config} className="aspect-auto h-52 w-full">
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16, top: 4, bottom: 4 }} barCategoryGap="28%">
        <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="var(--border)" opacity={0.6} />
        <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
        <YAxis dataKey="label" type="category" tickLine={false} axisLine={false} width={96} tick={{ fontSize: 12, fontWeight: 600 }} />
        <ChartTooltip content={<ChartTooltipContent hideLabel />} cursor={{ fill: "var(--accent)", opacity: 0.5 }} />
        <Bar dataKey="count" radius={[0, 8, 8, 0]} barSize={20} animationDuration={700}>
          {data.map((entry) => (
            <Cell key={entry.severity} fill={SEVERITY_FILL[entry.severity]} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}
