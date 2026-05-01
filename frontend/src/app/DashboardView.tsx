import { useMemo, useState } from "react";
import type { DashboardData, Device, EnhancedPacket } from "../types";
import { formatGeo, formatMetadata, protoClass, savePacketsAsCsv } from "./formatters";

type DashboardViewProps = {
  devices: Device[];
  selectedDevice: number;
  setSelectedDevice: (deviceIndex: number) => void;
  dashboard: DashboardData | null;
  packetRate: number;
  lastUpdateTime: string;
  onStartCapture: () => void;
  onClearPackets: () => void;
};

export function DashboardView({
  devices,
  selectedDevice,
  setSelectedDevice,
  dashboard,
  packetRate,
  lastUpdateTime,
  onStartCapture,
  onClearPackets,
}: DashboardViewProps) {
  const [modalPacket, setModalPacket] = useState<EnhancedPacket | null>(null);
  const [clearedPackets, setClearedPackets] = useState(false);

  const currentDeviceName = useMemo(
    () => devices.find((d) => d.index === selectedDevice)?.name ?? "",
    [devices, selectedDevice]
  );

  const displayedPackets = useMemo(
    () => (clearedPackets ? [] : (dashboard?.enhancedPackets ?? []).slice().reverse()),
    [clearedPackets, dashboard?.enhancedPackets]
  );

  function handleClear() {
    onClearPackets();
    setClearedPackets(true);
    setModalPacket(null);
  }

  return (
    <>
      <h1 className="page-title">Dashboard</h1>

      <div className="sysinfo-box">
        <div className="sysinfo-title">System Information</div>

        <div className="sysinfo-row">
          <span className="sysinfo-label">Network Adapter:</span>
          <select
            className="adapter-select"
            value={selectedDevice}
            onChange={(e) => {
              setClearedPackets(false);
              setSelectedDevice(Number(e.target.value));
            }}
          >
            {devices.map((d) => (
              <option key={d.index} value={d.index}>
                {d.name}
              </option>
            ))}
          </select>
          <button className="start-btn" onClick={onStartCapture}>
            Start
          </button>
        </div>

        <div className="sysinfo-row">
          <span className="sysinfo-label">Time:</span>
          <span className="badge-red">{dashboard?.currentTime ?? "--:--:--"}</span>
          <span className="sysinfo-label" style={{ marginLeft: 24 }}>
            Computer:
          </span>
          <span className="value-blue">{dashboard?.computerName ?? "—"}</span>
        </div>

        <div className="sysinfo-row">
          <span className="sysinfo-label">Packets Captured:</span>
          <span className="badge-green">{dashboard?.totalPacketsCaptured ?? 0}</span>
          <span className="sysinfo-label" style={{ marginLeft: 24 }}>
            Rate (pkt/sec):
          </span>
          <span className="badge-red">{packetRate.toFixed(1)}</span>
        </div>
      </div>

      <div className="packets-panel">
        <div className="packets-header">
          <span className="packets-title">
            <span className="packets-title-dot" />
            Live Network Packets (Streaming)
          </span>
          <div className="packets-actions">
            <button className="btn-clear" onClick={handleClear}>
              Clear
            </button>
            <button
              className="btn-save"
              onClick={() => {
                if (dashboard) {
                  savePacketsAsCsv(dashboard);
                }
              }}
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
                      <span className="warn-icon" title={pkt.securityFlags.join(", ")}>
                        ⚠
                      </span>
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
          ⟳ Live Updates &bull; Last: {lastUpdateTime || "--:--:--"} &bull; Rows: {dashboard?.totalPacketsCaptured ?? 0}
          &bull; Monitoring: {currentDeviceName || "No device"}
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
              <span>
                <strong>Protocol:</strong> {modalPacket.protocol}
              </span>
              <span>
                <strong>Risk:</strong> {modalPacket.riskScore}
              </span>
              <span>
                <strong>Size:</strong> {modalPacket.size} bytes
              </span>
              <span>
                <strong>Source:</strong> {modalPacket.sourceIP}
              </span>
              <span>
                <strong>Destination:</strong> {modalPacket.destinationIP}
              </span>
              <span>
                <strong>Source DNS:</strong> {modalPacket.sourceHostName || "Unresolved"}
              </span>
              <span>
                <strong>Destination DNS:</strong> {modalPacket.destinationHostName || "Unresolved"}
              </span>
            </div>
            <div className="packet-details-line">
              <strong>Source Geo:</strong> {formatGeo(modalPacket.sourceGeoLocation)}
            </div>
            <div className="packet-details-line">
              <strong>Destination Geo:</strong> {formatGeo(modalPacket.destinationGeoLocation)}
            </div>
            <div className="packet-details-line">
              <strong>Summary:</strong> {modalPacket.details || "No summary"}
            </div>
            <div className="packet-details-line">
              <strong>Security Flags:</strong>{" "}
              {modalPacket.securityFlags.length > 0 ? modalPacket.securityFlags.join(" | ") : "None"}
            </div>
            <pre className="packet-metadata-json">{formatMetadata(modalPacket.metadata)}</pre>
          </div>
        </div>
      ) : null}
    </>
  );
}
