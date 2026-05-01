import { FormEvent, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { AlertsPayload, Config, DashboardData, Device } from "./types";
import { AlertsView } from "./app/AlertsView";
import { AdvancedView } from "./app/AdvancedView";
import { DashboardView } from "./app/DashboardView";
import { OptionsView } from "./app/OptionsView";
import type { View } from "./app/viewTypes";

function normalizeConfig(config: Config): Config {
  return {
    ...config,
    payloadFilteringEnabled: config.payloadFilteringEnabled ?? true,
    payloadPreviewLength: config.payloadPreviewLength ?? 200,
    blockedPayloadKeywords: config.blockedPayloadKeywords ?? [],
    blockedPayloadPatterns: config.blockedPayloadPatterns ?? [],
  };
}

function App() {
  const [view, setView] = useState<View>("dashboard");
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<number>(-1);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [alerts, setAlerts] = useState<AlertsPayload | null>(null);
  const [config, setConfig] = useState<Config | null>(null);
  const [error, setError] = useState<string>("");
  const [packetRate, setPacketRate] = useState(0);
  const [lastUpdateTime, setLastUpdateTime] = useState("");
  const prevRef = useRef<{ count: number; time: number }>({ count: 0, time: Date.now() });

  async function loadBootstrap() {
    try {
      setError("");
      const [deviceData, dashboardData, alertsData, configData] = await Promise.all([
        api.getDevices(),
        api.getDashboard(),
        api.getAlerts(),
        api.getConfig(),
      ]);
      setDevices(deviceData);
      const selected = deviceData.find((d) => d.isSelected);
      setSelectedDevice(selected ? selected.index : deviceData[0]?.index ?? -1);
      setDashboard(dashboardData);
      setAlerts(alertsData);
      setConfig(normalizeConfig(configData));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load data");
    }
  }

  useEffect(() => {
    void loadBootstrap();
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      void api
        .getDashboard()
        .then((data) => {
          const now = Date.now();
          const prev = prevRef.current;
          const elapsed = (now - prev.time) / 1000;
          if (elapsed > 0) {
            setPacketRate(Math.max(0, (data.totalPacketsCaptured - prev.count) / elapsed));
          }
          prevRef.current = { count: data.totalPacketsCaptured, time: now };
          setDashboard(data);
          const now2 = new Date();
          setLastUpdateTime(
            now2.toLocaleTimeString("en-US", { hour12: false }) +
              "." +
              String(now2.getMilliseconds()).padStart(3, "0")
          );
          setError("");
        })
        .catch((err: unknown) => {
          setError(err instanceof Error ? err.message : "Refresh failed");
        });
    }, 800);
    return () => clearInterval(id);
  }, []);

  async function handleStartCapture() {
    if (selectedDevice < 0) return;
    try {
      await api.startCapture(selectedDevice);
      setError("");
      await loadBootstrap();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start capture");
    }
  }

  async function handleRefresh() {
    await loadBootstrap();
  }

  async function handleClearPackets() {
    return;
  }

  async function handleClearAlerts() {
    try {
      await api.clearAlerts();
      setError("");
      setAlerts(await api.getAlerts());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not clear alerts");
    }
  }

  async function handleSaveConfig(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!config) return;
    try {
      const updated = await api.updateConfig(config);
      setConfig(normalizeConfig(updated));
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save settings");
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <nav className="sidebar-nav">
          <button
            className={`nav-btn${view === "dashboard" ? " active" : ""}`}
            onClick={() => setView("dashboard")}
          >
            Dashboard
          </button>
          <button
            className={`nav-btn${view === "advanced" ? " active" : ""}`}
            onClick={() => setView("advanced")}
          >
            Advanced
          </button>
          <button
            className={`nav-btn${view === "alerts" ? " active" : ""}`}
            onClick={() => setView("alerts")}
          >
            Alerts
          </button>
          <button
            className={`nav-btn${view === "options" ? " active" : ""}`}
            onClick={() => setView("options")}
          >
            Options
          </button>
        </nav>
        <div className="sidebar-bottom">
          <button className="refresh-btn" onClick={handleRefresh}>
            ⟳ Refresh
          </button>
        </div>
      </aside>

      <main className="main-content">
        {error ? <div className="error-bar">{error}</div> : null}

        {view === "dashboard" ? (
          <DashboardView
            devices={devices}
            selectedDevice={selectedDevice}
            setSelectedDevice={setSelectedDevice}
            dashboard={dashboard}
            packetRate={packetRate}
            lastUpdateTime={lastUpdateTime}
            onStartCapture={handleStartCapture}
            onClearPackets={handleClearPackets}
          />
        ) : null}

        {view === "advanced" ? <AdvancedView dashboard={dashboard} /> : null}

        {view === "alerts" ? <AlertsView alerts={alerts} onClearAlerts={handleClearAlerts} /> : null}

        {view === "options" && config ? (
          <OptionsView
            config={config}
            setConfig={(updater) => setConfig((prev) => (prev ? updater(prev) : prev))}
            onSaveConfig={handleSaveConfig}
          />
        ) : null}
      </main>
    </div>
  );
}

export default App;
