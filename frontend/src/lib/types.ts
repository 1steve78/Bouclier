export type RiskLevel = "low_risk" | "suspicious" | "high_risk" | "confirmed_malicious";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface InvestigationRequest {
  input: string;
  options?: { ai?: boolean };
}

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  explanation: string;
}

export interface SecurityFinding {
  id: string;
  title: string;
  severity: Severity;
  evidence: string;
  explanation: string;
  impact: string;
  recommendation: string;
  source: "rule" | "feed" | "probe" | "ai";
}

export interface TLSCertificateInfo {
  https: boolean;
  valid: boolean;
  expiresAt: string;
  issuer: string;
  subjectAlternativeNames: string[];
}

export interface DomainInformation {
  domain: string;
  registeredDomain: string;
  subdomain: string;
  tld: string;
  ipAddress: string;
  registration: string;
  reputation: string;
}

export interface RedirectInformation {
  url: string;
  statusCode: number;
  locationHost: string;
}

export interface ThreatIntelligenceMatch {
  source: string;
  status: "match" | "clear" | "unavailable";
  detail: string;
}

export interface InvestigationResult {
  id: string;
  submittedUrl: string;
  scannedAt: string;
  durationMs: number;
  risk: RiskAssessment;
  domain: DomainInformation;
  tls: TLSCertificateInfo;
  redirects: RedirectInformation[];
  findings: SecurityFinding[];
  intelligence: ThreatIntelligenceMatch[];
  checksCompleted: number;
  checksUnavailable: number;
  aiExplanation: string;
  isDemo: true;
}

export interface MessageAnalysisRequest {
  message: string;
}

export interface MessageAnalysisResult {
  risk: RiskAssessment;
  indicators: { title: string; detail: string; severity: Severity }[];
  urls: string[];
  emails: string[];
  phones: string[];
  explanation: string;
  safetyMeasures: string[];
  isDemo: true;
}

export interface BlockchainVerificationResult {
  status: "verified" | "not_found" | "unavailable";
  reportId: string;
  reportHash: string;
  transactionHash: string;
  contractAddress: string;
  network: string;
  blockNumber: number | null;
  timestamp: string | null;
  isDemo: true;
}

export interface ThreatRecord {
  id: string;
  indicator: string;
  category: string;
  reported: string;
  source: string;
  status: string;
  severity: Severity;
}
