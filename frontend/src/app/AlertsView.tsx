import type { AlertsPayload } from "../types";

type AlertsViewProps = {
  alerts: AlertsPayload | null;
  onClearAlerts: () => void;
};

export function AlertsView({ alerts, onClearAlerts }: AlertsViewProps) {
  return (
    <>
      <h1 className="page-title">Alerts</h1>
      <div className="packets-panel">
        <div className="packets-header">
          <span className="packets-title">
            <span className="packets-title-dot" />
            Security Alerts
          </span>
          <div className="packets-actions">
            <button className="btn-clear" onClick={onClearAlerts}>
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
                    <span className={alert.severity > 7 ? "badge-red" : "badge-green"}>{alert.severity}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="packets-footer">Total alerts: {alerts?.securityAlerts.length ?? 0}</div>
      </div>
    </>
  );
}
