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

export type PacketStatistics = {
  totalPackets: number;
  highRiskPackets: number;
  mediumRiskPackets: number;
  lowRiskPackets: number;
  protocolCounts: Record<string, number>;
  averageRiskScore: number;
};

export type EnhancedPacket = {
  timestamp: string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  size: number;
  details: string;
  riskScore: number;
  securityFlags: string[];
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
};

export type AlertsPayload = {
  alerts: string[];
  securityAlerts: SecurityAlert[];
  stats: Record<string, number>;
};
