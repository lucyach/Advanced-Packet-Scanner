import { FormEvent, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { AlertsPayload, Config, DashboardData, Device, EnhancedPacket } from "./types";

type View = "dashboard" | "alerts" | "options";

function protoClass(protocol: string): string {
  const p = protocol.toLowerCase();
  if (p === "tcp") return "proto-tcp";
  if (p === "udp") return "proto-udp";
  if (p.includes("icmp")) return "proto-icmp";
  if (p.includes("http")) return "proto-http";
  if (p.includes("tls") || p.includes("ssl")) return "proto-tls";
  if (p.includes("dns")) return "proto-dns";
  return "";
}

function savePacketsAsCsv(dashboard: DashboardData) {
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
  const a = document.createElement("a");
  a.href = url;
  a.download = `packets_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function formatMetadata(value: unknown): string {
  if (value === null || value === undefined) {
    return "No metadata available";
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
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
  const [clearedPackets, setClearedPackets] = useState(false);
  const [modalPacket, setModalPacket] = useState<EnhancedPacket | null>(null);
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
      setConfig(configData);
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
    setClearedPackets(true);
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
      setConfig(updated);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save settings");
    }
  }

  const currentDeviceName = devices.find((d) => d.index === selectedDevice)?.name ?? "";
  const displayedPackets = clearedPackets
    ? []
    : (dashboard?.enhancedPackets ?? []).slice().reverse();

  return (
    <div className="app-shell">
      {/* ── SIDEBAR ── */}
      <aside className="sidebar">
        <nav className="sidebar-nav">
          <button
            className={`nav-btn${view === "dashboard" ? " active" : ""}`}
            onClick={() => setView("dashboard")}
          >
            Dashboard
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

      {/* ── MAIN ── */}
      <main className="main-content">
        {error ? <div className="error-bar">{error}</div> : null}

        {/* ── DASHBOARD ── */}
        {view === "dashboard" && (
          <>
            <h1 className="page-title">Dashboard</h1>

            {/* System Information box */}
            <div className="sysinfo-box">
              <div className="sysinfo-title">System Information</div>

              {/* Row 1: Adapter */}
              <div className="sysinfo-row">
                <span className="sysinfo-label">Network Adapter:</span>
                <select
                  className="adapter-select"
                  value={selectedDevice}
                  onChange={(e) => setSelectedDevice(Number(e.target.value))}
                >
                  {devices.map((d) => (
                    <option key={d.index} value={d.index}>
                      {d.name}
                    </option>
                  ))}
                </select>
                <button className="start-btn" onClick={handleStartCapture}>
                  Start
                </button>
              </div>

              {/* Row 2: Time + Computer */}
              <div className="sysinfo-row">
                <span className="sysinfo-label">Time:</span>
                <span className="badge-red">{dashboard?.currentTime ?? "--:--:--"}</span>
                <span className="sysinfo-label" style={{ marginLeft: 24 }}>Computer:</span>
                <span className="value-blue">{dashboard?.computerName ?? "—"}</span>
              </div>

              {/* Row 3: Packets + Rate */}
              <div className="sysinfo-row">
                <span className="sysinfo-label">Packets Captured:</span>
                <span className="badge-green">{dashboard?.totalPacketsCaptured ?? 0}</span>
                <span className="sysinfo-label" style={{ marginLeft: 24 }}>Rate (pkt/sec):</span>
                <span className="badge-red">{packetRate.toFixed(1)}</span>
              </div>
            </div>

            {/* Live Packets table */}
            <div className="packets-panel">
              <div className="packets-header">
                <span className="packets-title">
                  <span className="packets-title-dot" />
                  Live Network Packets (Streaming)
                </span>
                <div className="packets-actions">
                  <button
                    className="btn-clear"
                    onClick={handleClearPackets}
                  >
                    Clear
                  </button>
                  <button
                    className="btn-save"
                    onClick={() => dashboard && savePacketsAsCsv(dashboard)}
                  >
                    Save
                  </button>
                </div>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 80 }}>Time</th>
                      <th style={{ width: 90 }}>Protocol</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th style={{ width: 60 }}>Size</th>
                      <th style={{ width: 260 }}>Details</th>
                      <th style={{ width: 36 }}>⚠</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedPackets.map((pkt, i) => (
                      <tr
                        key={`${pkt.timestamp}-${pkt.sourceIP}-${i}`}
                        onClick={() => setModalPacket(pkt)}
                        title="Click to inspect full analyzer output"
                      >
                        <td>{new Date(pkt.timestamp).toLocaleTimeString("en-US", { hour12: false })}</td>
                        <td className={protoClass(pkt.protocol)}>{pkt.protocol}</td>
                        <td className="td-mono">{pkt.sourceIP}</td>
                        <td className="td-mono">{pkt.destinationIP}</td>
                        <td>{pkt.size}</td>
                        <td>{pkt.details || "-"}</td>
                        <td>
                          {pkt.securityFlags.length > 0 || pkt.riskScore > 50 ? (
                            <span className="warn-icon" title={pkt.securityFlags.join(", ")}>⚠</span>
                          ) : (
                            <span className="no-warn">–</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="packets-footer">
                ⟳ Live Updates &bull; Last: {lastUpdateTime || "--:--:--"} &bull; Rows:{" "}
                {dashboard?.totalPacketsCaptured ?? 0} &bull; Monitoring: {currentDeviceName || "No device"}
              </div>
            </div>

            {modalPacket ? (
              <div className="packet-modal-backdrop">
                <div className="packet-modal" role="dialog" aria-modal="true" aria-label="Packet analyzer details">
                  <button
                    className="packet-modal-close"
                    onClick={() => setModalPacket(null)}
                    aria-label="Close packet analyzer details"
                  >
                    ×
                  </button>
                  <div className="packet-details-title">Packet Analyzer Details</div>
                  <div className="packet-details-meta">
                    <span><strong>Protocol:</strong> {modalPacket.protocol}</span>
                    <span><strong>Risk:</strong> {modalPacket.riskScore}</span>
                    <span><strong>Size:</strong> {modalPacket.size} bytes</span>
                    <span><strong>Source:</strong> {modalPacket.sourceIP}</span>
                    <span><strong>Destination:</strong> {modalPacket.destinationIP}</span>
                  </div>
                  <div className="packet-details-line">
                    <strong>Summary:</strong> {modalPacket.details || "No summary"}
                  </div>
                  <div className="packet-details-line">
                    <strong>Security Flags:</strong>{" "}
                    {modalPacket.securityFlags.length > 0
                      ? modalPacket.securityFlags.join(" | ")
                      : "None"}
                  </div>
                  <pre className="packet-metadata-json">{formatMetadata(modalPacket.metadata)}</pre>
                </div>
              </div>
            ) : null}
          </>
        )}

        {/* ── ALERTS ── */}
        {view === "alerts" && (
          <>
            <h1 className="page-title">Alerts</h1>
            <div className="packets-panel">
              <div className="packets-header">
                <span className="packets-title">
                  <span className="packets-title-dot" />
                  Security Alerts
                </span>
                <div className="packets-actions">
                  <button className="btn-clear" onClick={handleClearAlerts}>
                    Clear
                  </button>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 80 }}>Time</th>
                      <th style={{ width: 130 }}>Type</th>
                      <th>Description</th>
                      <th style={{ width: 140 }}>Source</th>
                      <th style={{ width: 140 }}>Destination</th>
                      <th style={{ width: 80 }}>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(alerts?.securityAlerts ?? []).slice().reverse().map((alert, i) => (
                      <tr key={`${alert.timestamp}-${i}`}>
                        <td>{new Date(alert.timestamp).toLocaleTimeString("en-US", { hour12: false })}</td>
                        <td className="proto-http">{alert.alertType}</td>
                        <td>{alert.description}</td>
                        <td className="td-mono">{alert.sourceIP}</td>
                        <td className="td-mono">{alert.destinationIP}</td>
                        <td>
                          <span className={alert.severity > 7 ? "badge-red" : "badge-green"}>
                            {alert.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="packets-footer">
                Total alerts: {alerts?.securityAlerts.length ?? 0}
              </div>
            </div>
          </>
        )}

        {/* ── OPTIONS ── */}
        {view === "options" && config && (
          <>
            <h1 className="page-title">Options</h1>
            <div className="sysinfo-box" style={{ maxWidth: 480 }}>
              <div className="sysinfo-title">Configuration</div>
              <form className="options-form" onSubmit={handleSaveConfig}>
                <div className="form-field">
                  <label htmlFor="maxPackets">Max packets stored</label>
                  <input
                    id="maxPackets"
                    type="number"
                    min={100}
                    max={50000}
                    value={config.maxPackets}
                    onChange={(e) =>
                      setConfig((prev) => prev ? { ...prev, maxPackets: Number(e.target.value) } : prev)
                    }
                  />
                </div>
                <div className="form-field">
                  <label htmlFor="maxAlerts">Max alerts stored</label>
                  <input
                    id="maxAlerts"
                    type="number"
                    min={50}
                    max={5000}
                    value={config.maxAlerts}
                    onChange={(e) =>
                      setConfig((prev) => prev ? { ...prev, maxAlerts: Number(e.target.value) } : prev)
                    }
                  />
                </div>
                <div className="form-field">
                  <label htmlFor="packetSaveCount">Packet save count</label>
                  <input
                    id="packetSaveCount"
                    type="number"
                    min={1}
                    max={10000}
                    value={config.packetSaveCount}
                    onChange={(e) =>
                      setConfig((prev) => prev ? { ...prev, packetSaveCount: Number(e.target.value) } : prev)
                    }
                  />
                </div>
                <button type="submit" className="save-btn">Save Settings</button>
              </form>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
