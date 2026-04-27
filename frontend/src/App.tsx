import { FormEvent, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { AlertsPayload, Config, DashboardData, Device } from "./types";

type View = "dashboard" | "alerts" | "options";

function App() {
  const [view, setView] = useState<View>("dashboard");
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<number>(-1);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [alerts, setAlerts] = useState<AlertsPayload | null>(null);
  const [config, setConfig] = useState<Config | null>(null);
  const [message, setMessage] = useState<string>("");
  const [error, setError] = useState<string>("");

  const protocolSummary = useMemo(() => {
    if (!dashboard) return "No traffic yet";
    return Object.entries(dashboard.statistics.protocolCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([protocol, count]) => `${protocol}: ${count}`)
      .join(" | ");
  }, [dashboard]);

  async function loadBootstrap() {
    try {
      setError("");
      const [deviceData, dashboardData, alertsData, configData] = await Promise.all([
        api.getDevices(),
        api.getDashboard(),
        api.getAlerts(),
        api.getConfig()
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
          setDashboard(data);
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
      const result = await api.startCapture(selectedDevice);
      setMessage(result.message);
      setError("");
      await loadBootstrap();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start capture");
    }
  }

  async function handlePauseCapture() {
    try {
      const result = await api.pauseCapture();
      setMessage(result.message);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not pause capture");
    }
  }

  async function handleResumeCapture() {
    try {
      const result = await api.resumeCapture();
      setMessage(result.message);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not resume capture");
    }
  }

  async function handleClearAlerts() {
    try {
      await api.clearAlerts();
      setMessage("Alerts cleared");
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
      setMessage("Settings saved");
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save settings");
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h1>Network Monitor</h1>
        <button className={view === "dashboard" ? "nav active" : "nav"} onClick={() => setView("dashboard")}>Dashboard</button>
        <button className={view === "alerts" ? "nav active" : "nav"} onClick={() => setView("alerts")}>Alerts</button>
        <button className={view === "options" ? "nav active" : "nav"} onClick={() => setView("options")}>Options</button>

        <div className="controls">
          <label htmlFor="devices">Adapter</label>
          <select
            id="devices"
            value={selectedDevice}
            onChange={(e) => setSelectedDevice(Number(e.target.value))}
          >
            {devices.map((device) => (
              <option value={device.index} key={device.index}>
                {device.name}
              </option>
            ))}
          </select>

          <div className="button-row">
            <button onClick={handleStartCapture}>Start</button>
            <button onClick={handlePauseCapture}>Pause</button>
            <button onClick={handleResumeCapture}>Resume</button>
          </div>
        </div>
      </aside>

      <main className="content">
        <header className="status-bar">
          <p>{dashboard?.message ?? "No device selected"}</p>
          <p>{dashboard?.computerName ?? "Unknown machine"}</p>
          <p>{dashboard?.currentTime ?? "--:--:--"}</p>
        </header>

        {message ? <div className="notice success">{message}</div> : null}
        {error ? <div className="notice error">{error}</div> : null}

        {view === "dashboard" && dashboard ? (
          <section className="panel-grid">
            <article className="panel">
              <h2>Capture Stats</h2>
              <p>Total packets: {dashboard.totalPacketsCaptured}</p>
              <p>Average risk score: {dashboard.statistics.averageRiskScore.toFixed(1)}</p>
              <p>High risk packets: {dashboard.statistics.highRiskPackets}</p>
              <p>Protocols: {protocolSummary}</p>
            </article>

            <article className="panel table-panel">
              <h2>Live Packet Stream</h2>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Risk</th>
                      <th>Protocol</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboard.enhancedPackets.slice(-50).reverse().map((packet) => (
                      <tr key={`${packet.timestamp}-${packet.sourceIP}-${packet.destinationIP}-${packet.size}`}>
                        <td>{new Date(packet.timestamp).toLocaleTimeString()}</td>
                        <td>{packet.riskScore}</td>
                        <td>{packet.protocol}</td>
                        <td>{packet.sourceIP}</td>
                        <td>{packet.destinationIP}</td>
                        <td>{packet.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          </section>
        ) : null}

        {view === "alerts" && alerts ? (
          <section className="panel-grid one-col">
            <article className="panel">
              <div className="panel-title-row">
                <h2>Security Alerts</h2>
                <button onClick={handleClearAlerts}>Clear Alerts</button>
              </div>
              <p>Total alerts: {alerts.stats.Total ?? 0}</p>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Type</th>
                      <th>Description</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.securityAlerts.slice().reverse().map((alert, index) => (
                      <tr key={`${alert.timestamp}-${index}`}>
                        <td>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                        <td>{alert.alertType}</td>
                        <td>{alert.description}</td>
                        <td>{alert.sourceIP}</td>
                        <td>{alert.destinationIP}</td>
                        <td>{alert.severity}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          </section>
        ) : null}

        {view === "options" && config ? (
          <section className="panel-grid one-col">
            <article className="panel">
              <h2>Configuration</h2>
              <form className="config-form" onSubmit={handleSaveConfig}>
                <label>
                  Max packets
                  <input
                    type="number"
                    min={100}
                    max={50000}
                    value={config.maxPackets}
                    onChange={(e) =>
                      setConfig((prev) =>
                        prev ? { ...prev, maxPackets: Number(e.target.value) } : prev
                      )
                    }
                  />
                </label>

                <label>
                  Max alerts
                  <input
                    type="number"
                    min={50}
                    max={5000}
                    value={config.maxAlerts}
                    onChange={(e) =>
                      setConfig((prev) =>
                        prev ? { ...prev, maxAlerts: Number(e.target.value) } : prev
                      )
                    }
                  />
                </label>

                <label>
                  Packet save count
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={config.packetSaveCount}
                    onChange={(e) =>
                      setConfig((prev) =>
                        prev ? { ...prev, packetSaveCount: Number(e.target.value) } : prev
                      )
                    }
                  />
                </label>

                <button type="submit">Save Settings</button>
              </form>
            </article>
          </section>
        ) : null}
      </main>
    </div>
  );
}

export default App;
