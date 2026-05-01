import type { DashboardData } from "../types";

export function protoClass(protocol: string): string {
  const p = protocol.toLowerCase();
  if (p === "tcp") return "proto-tcp";
  if (p === "udp") return "proto-udp";
  if (p.includes("icmp")) return "proto-icmp";
  if (p.includes("http")) return "proto-http";
  if (p.includes("tls") || p.includes("ssl")) return "proto-tls";
  if (p.includes("dns")) return "proto-dns";
  return "";
}

export function savePacketsAsCsv(dashboard: DashboardData) {
  const header = "Time,Protocol,Source,Destination,Size,RiskScore,Flags\n";
  const rows = dashboard.enhancedPackets
    .map((p) =>
      [
        new Date(p.timestamp).toLocaleTimeString(),
        p.protocol,
        p.sourceIP,
        p.destinationIP,
        p.size,
        p.riskScore,
        p.securityFlags.join("|"),
      ].join(",")
    )
    .join("\n");

  const blob = new Blob([header + rows], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `packets_${Date.now()}.csv`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function formatMetadata(value: unknown): string {
  if (value === null || value === undefined) {
    return "No metadata available";
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function formatGeo(value?: { displayName?: string; isp?: string }): string {
  if (!value) return "Unknown";
  const place = value.displayName && value.displayName.length > 0 ? value.displayName : "Unknown";
  const isp = value.isp && value.isp.length > 0 ? value.isp : "Unknown ISP";
  return `${place} (${isp})`;
}

export function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }

  return `${value.toFixed(unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
}

export function formatMetricName(name: string): string {
  return name
    .split("_")
    .join(" ")
    .replace(/\b\w/g, (c: string) => c.toUpperCase());
}

export function severityClass(severity: string): string {
  const level = severity.toLowerCase();
  if (level === "critical" || level === "high") return "badge-red";
  if (level === "medium") return "badge-green";
  return "no-warn";
}
