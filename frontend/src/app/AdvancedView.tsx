import type { DashboardData } from "../types";
import { formatBytes, formatGeo, formatMetricName, severityClass } from "./formatters";

type AdvancedViewProps = {
  dashboard: DashboardData | null;
};

export function AdvancedView({ dashboard }: AdvancedViewProps) {
  return (
    <>
      <h1 className="page-title">Advanced Analytics</h1>
      <div className="advanced-scroll">
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-label">Current / Avg / Peak Bandwidth</div>
            <div className="metric-value">
              {(dashboard?.statistics?.bandwidth?.currentMbps ?? 0).toFixed(2)} /
              {(dashboard?.statistics?.bandwidth?.averageMbps ?? 0).toFixed(2)} /
              {(dashboard?.statistics?.bandwidth?.peakMbps ?? 0).toFixed(2)} Mbps
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Protocol Throughput</div>
            <div className="metric-value metric-wrap">
              {Object.entries(dashboard?.statistics?.bandwidth?.protocolBandwidthMbps ?? {})
                .sort((a, b) => b[1] - a[1])
                .slice(0, 4)
                .map(([proto, mbps]) => `${proto}: ${mbps.toFixed(2)} Mbps`)
                .join(" | ") || "No throughput data yet"}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Network Jitter / TCP RTT</div>
            <div className="metric-value">
              {(dashboard?.statistics?.performance?.estimatedJitterMs ?? 0).toFixed(2)} ms /
              {(dashboard?.statistics?.performance?.averageTcpHandshakeRttMs ?? 0).toFixed(2)} ms
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">ICMP Reply Rate / Avg Packet Size</div>
            <div className="metric-value">
              {(dashboard?.statistics?.performance?.icmpReplyRatePercent ?? 0).toFixed(1)}% /
              {(dashboard?.statistics?.performance?.averagePacketSizeBytes ?? 0).toFixed(1)} B
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Behavior Baseline Warmup</div>
            <div className="metric-value">
              {(dashboard?.statistics?.baseline?.warmupWindows ?? 0)} /
              {(dashboard?.statistics?.baseline?.minimumWindowsRequired ?? 0)} windows
              {dashboard?.statistics?.baseline?.isEstablished ? " (Ready)" : " (Learning)"}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Protocol Diversity / Anomalies</div>
            <div className="metric-value">
              {(dashboard?.statistics?.protocolDiversityEntropy ?? 0).toFixed(3)} bits /
              {" "}
              {dashboard?.statistics?.anomalyReport?.totalAnomalies ?? 0}
            </div>
          </div>
        </div>

        <div className="insights-grid">
          <div className="packets-panel insights-panel">
            <div className="packets-header">
              <span className="packets-title">
                <span className="packets-title-dot" />
                Top Talkers (Bandwidth Utilization)
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Host</th>
                    <th>Total Bytes</th>
                    <th>Avg Mbps</th>
                  </tr>
                </thead>
                <tbody>
                  {(dashboard?.statistics?.bandwidth?.topTalkers ?? []).map((talker) => (
                    <tr key={talker.ipAddress}>
                      <td className="td-mono">{talker.ipAddress}</td>
                      <td>{talker.hostName || "Unresolved"}</td>
                      <td>{formatBytes(talker.bytes)}</td>
                      <td>{talker.megabitsPerSecond.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="packets-panel insights-panel">
            <div className="packets-header">
              <span className="packets-title">
                <span className="packets-title-dot" />
                Device Fingerprints
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP / Host</th>
                    <th>Type</th>
                    <th>OS Guess</th>
                    <th>Traffic Profile</th>
                    <th>Ports</th>
                  </tr>
                </thead>
                <tbody>
                  {(dashboard?.statistics?.deviceFingerprints ?? []).slice(0, 15).map((fp) => (
                    <tr key={fp.ipAddress}>
                      <td>
                        <div className="td-mono">{fp.ipAddress}</div>
                        <div className="subtle-text">{fp.hostName || formatGeo(fp.geoLocation)}</div>
                      </td>
                      <td>{fp.deviceType}</td>
                      <td>{fp.probableOS}</td>
                      <td>{fp.trafficProfile}</td>
                      <td>{fp.observedPorts.slice(0, 6).join(", ") || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="packets-panel insights-panel">
            <div className="packets-header">
              <span className="packets-title">
                <span className="packets-title-dot" />
                ML Traffic Classifier Distribution
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Class</th>
                    <th>Packets</th>
                    <th>Share</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(dashboard?.statistics?.trafficClassificationCounts ?? {})
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10)
                    .map(([category, count]) => {
                      const total = Math.max(1, dashboard?.statistics?.totalPackets ?? 1);
                      const share = (count * 100) / total;
                      return (
                        <tr key={category}>
                          <td>{category}</td>
                          <td>{count}</td>
                          <td>{share.toFixed(1)}%</td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="packets-panel insights-panel">
            <div className="packets-header">
              <span className="packets-title">
                <span className="packets-title-dot" />
                Application Protocol Detection
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Application Protocol</th>
                    <th>Packets</th>
                    <th>Percent</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(dashboard?.statistics?.applicationProtocolCounts ?? {})
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10)
                    .map(([proto, count]) => {
                      const total = Math.max(1, dashboard?.statistics?.totalPackets ?? 1);
                      const share = (count * 100) / total;
                      return (
                        <tr key={proto}>
                          <td>{proto}</td>
                          <td>{count}</td>
                          <td>{share.toFixed(1)}%</td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="packets-panel insights-panel">
            <div className="packets-header">
              <span className="packets-title">
                <span className="packets-title-dot" />
                Baseline And Statistical Anomalies
              </span>
            </div>
            <div className="packets-footer">
              Baseline: {dashboard?.statistics?.baseline?.isEstablished ? "Established" : "Training"} &bull; Severity:{" "}
              <span className={severityClass(dashboard?.statistics?.anomalyReport?.overallSeverity ?? "none")}>
                {dashboard?.statistics?.anomalyReport?.overallSeverity ?? "None"}
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Current</th>
                    <th>Baseline</th>
                    <th>StdDev</th>
                    <th>Z-Score</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {(dashboard?.statistics?.anomalyReport?.metrics ?? []).slice(0, 12).map((metric) => (
                    <tr key={metric.metric}>
                      <td>{formatMetricName(metric.metric)}</td>
                      <td>{metric.currentValue.toFixed(3)}</td>
                      <td>{metric.baselineMean.toFixed(3)}</td>
                      <td>{metric.baselineStdDev.toFixed(3)}</td>
                      <td>{metric.zScore.toFixed(2)}</td>
                      <td>
                        <span className={severityClass(metric.severity)}>{metric.severity}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="packets-panel insights-panel">
            <div className="packets-header">
              <span className="packets-title">
                <span className="packets-title-dot" />
                Network Topology Links
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Path</th>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Bytes</th>
                    <th>Current Mbps</th>
                  </tr>
                </thead>
                <tbody>
                  {(dashboard?.statistics?.topologyMap?.links ?? []).slice(0, 20).map((link, i) => (
                    <tr key={`${link.sourceNodeId}-${link.destinationNodeId}-${i}`}>
                      <td className="td-mono">
                        {link.sourceNodeId} {"->"} {link.destinationNodeId}
                      </td>
                      <td>{link.dominantProtocol}</td>
                      <td>{link.packetCount}</td>
                      <td>{formatBytes(link.totalBytes)}</td>
                      <td>{link.currentMbps.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="packets-footer">
              Nodes: {dashboard?.statistics?.topologyMap?.totalNodes ?? 0} &bull; Links:{" "}
              {dashboard?.statistics?.topologyMap?.totalLinks ?? 0}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
