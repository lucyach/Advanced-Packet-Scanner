import type { AlertsPayload, Config, DashboardData, DashboardFilters, Device } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json"
    },
    ...init
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export const api = {
  getDashboard: (filters?: DashboardFilters) => {
    const params = new URLSearchParams();
    if (filters?.protocol) params.set("protocol", filters.protocol);
    if (filters?.minRisk !== undefined) params.set("minRisk", String(filters.minRisk));
    if (filters?.maxRisk !== undefined) params.set("maxRisk", String(filters.maxRisk));
    if (filters?.payloadContains) params.set("payloadContains", filters.payloadContains);

    const query = params.toString();
    return request<DashboardData>(query ? `/api/dashboard?${query}` : "/api/dashboard");
  },
  getDevices: () => request<Device[]>("/api/devices"),
  startCapture: (deviceIndex: number) =>
    request<{ message: string }>("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({ deviceIndex })
    }),
  pauseCapture: () => request<{ message: string }>("/api/capture/pause", { method: "POST" }),
  resumeCapture: () => request<{ message: string }>("/api/capture/resume", { method: "POST" }),
  getAlerts: () => request<AlertsPayload>("/api/alerts"),
  clearAlerts: () => request<{ message: string }>("/api/alerts", { method: "DELETE" }),
  getConfig: () => request<Config>("/api/config"),
  updateConfig: (config: Config) =>
    request<Config>("/api/config", {
      method: "PUT",
      body: JSON.stringify(config)
    })
};
