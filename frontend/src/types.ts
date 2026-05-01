export type Device = {
  index: number;
  name: string;
  isSelected: boolean;
};

export type SecurityAlert = {
  timestamp: string;
  alertType: string;
  description: string;
  sourceIP: string;
  destinationIP: string;
  severity: number;
};

export type GeoLocationInfo = {
  country: string;
  region: string;
  city: string;
  isp: string;
  latitude?: number;
  longitude?: number;
  isPrivate: boolean;
  displayName: string;
};

export type TopTalkerMetric = {
  ipAddress: string;
  hostName: string;
  bytes: number;
  megabitsPerSecond: number;
};

export type BandwidthUtilizationMetrics = {
  currentMbps: number;
  averageMbps: number;
  peakMbps: number;
  packetsPerSecond: number;
  protocolBandwidthMbps: Record<string, number>;
  topTalkers: TopTalkerMetric[];
};

export type NetworkPerformanceMetrics = {
  averagePacketSizeBytes: number;
  estimatedJitterMs: number;
  averageTcpHandshakeRttMs: number;
  icmpReplyRatePercent: number;
  totalObservedBytes: number;
};

export type DeviceFingerprint = {
  ipAddress: string;
  hostName: string;
  probableOS: string;
  deviceType: string;
  trafficProfile: string;
  isPrivate: boolean;
  geoLocation?: GeoLocationInfo;
  observedPorts: number[];
  observedProtocols: string[];
  protocolDistribution: Record<string, number>;
  bytesSent: number;
  bytesReceived: number;
  packetCount: number;
  firstSeen: string;
  lastSeen: string;
};

export type TopologyNodeInfo = {
  nodeId: string;
  displayName: string;
  hostName: string;
  deviceType: string;
  geoLocation?: GeoLocationInfo;
  degree: number;
  totalBytes: number;
  lastSeen: string;
};

export type TopologyLinkInfo = {
  sourceNodeId: string;
  destinationNodeId: string;
  dominantProtocol: string;
  packetCount: number;
  totalBytes: number;
  currentMbps: number;
  lastSeen: string;
};

export type NetworkTopologyMap = {
  nodes: TopologyNodeInfo[];
  links: TopologyLinkInfo[];
  totalNodes: number;
  totalLinks: number;
};

export type PacketStatistics = {
  totalPackets: number;
  totalBytes: number;
  highRiskPackets: number;
  mediumRiskPackets: number;
  lowRiskPackets: number;
  protocolCounts: Record<string, number>;
  applicationProtocolCounts: Record<string, number>;
  trafficClassificationCounts: Record<string, number>;
  averageRiskScore: number;
  protocolDiversityEntropy: number;
  bandwidth: BandwidthUtilizationMetrics;
  performance: NetworkPerformanceMetrics;
  baseline: BaselineSnapshot;
  patternAnalytics: TrafficPatternAnalytics;
  anomalyReport: TrafficAnomalyReport;
  deviceFingerprints: DeviceFingerprint[];
  topologyMap: NetworkTopologyMap;
};

export type BaselineMetric = {
  name: string;
  mean: number;
  standardDeviation: number;
  samples: number;
};

export type BaselineSnapshot = {
  isEstablished: boolean;
  warmupWindows: number;
  minimumWindowsRequired: number;
  lastUpdatedUtc: string;
  metrics: BaselineMetric[];
};

export type TrafficPatternAnalytics = {
  packetRatePerSecond: number;
  bytesPerSecond: number;
  uniqueSourceIps: number;
  uniqueDestinationIps: number;
  uniqueConversations: number;
  highRiskPacketRatioPercent: number;
  averagePacketSizeBytes: number;
  classificationDistributionPercent: Record<string, number>;
  applicationProtocolDistributionPercent: Record<string, number>;
};

export type TrafficAnomalyMetric = {
  metric: string;
  currentValue: number;
  baselineMean: number;
  baselineStdDev: number;
  zScore: number;
  severity: string;
  direction: string;
};

export type TrafficAnomalyReport = {
  baselineReady: boolean;
  totalAnomalies: number;
  overallSeverity: string;
  generatedAtUtc: string;
  metrics: TrafficAnomalyMetric[];
};

export type EnhancedPacket = {
  timestamp: string;
  sourceIP: string;
  destinationIP: string;
  sourceHostName: string;
  destinationHostName: string;
  sourceGeoLocation?: GeoLocationInfo;
  destinationGeoLocation?: GeoLocationInfo;
  protocol: string;
  size: number;
  details: string;
  riskScore: number;
  securityFlags: string[];
  metadata?: Record<string, unknown>;
};

export type DashboardData = {
  message: string;
  currentTime: string;
  computerName: string;
  totalPacketsCaptured: number;
  enhancedPackets: EnhancedPacket[];
  securityAlerts: SecurityAlert[];
  statistics: PacketStatistics;
};

export type Config = {
  maxPackets: number;
  maxAlerts: number;
  packetSaveCount: number;
  payloadFilteringEnabled?: boolean;
  payloadPreviewLength?: number;
  blockedPayloadKeywords?: string[];
  blockedPayloadPatterns?: string[];
};

export type DashboardFilters = {
  protocol?: string;
  minRisk?: number;
  maxRisk?: number;
  payloadContains?: string;
};

export type AlertsPayload = {
  alerts: string[];
  securityAlerts: SecurityAlert[];
  stats: Record<string, number>;
};
