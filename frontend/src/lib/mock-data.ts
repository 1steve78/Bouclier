import type { InvestigationResult, ThreatRecord } from "./types";

export const demoInvestigation: InvestigationResult = {
  id: "demo-8F2A91",
  submittedUrl: "https://accounts-micros0ft.example",
  scannedAt: "2026-11-08T08:30:00Z",
  durationMs: 1842,
  risk: {
    level: "high_risk",
    score: 82,
    explanation: "Multiple indicators warrant caution. This demonstration report is not a live scan.",
  },
  domain: {
    domain: "accounts-micros0ft.example",
    registeredDomain: "accounts-micros0ft.example",
    subdomain: "—",
    tld: ".example",
    ipAddress: "203.0.113.42",
    registration: "Unavailable in demonstration",
    reputation: "No live reputation lookup",
  },
  tls: {
    https: true,
    valid: true,
    expiresAt: "2027-02-14",
    issuer: "Example Trust Services",
    subjectAlternativeNames: ["accounts-micros0ft.example"],
  },
  redirects: [
    { url: "https://accounts-micros0ft.example/", statusCode: 200, locationHost: "accounts-micros0ft.example" },
  ],
  findings: [
    {
      id: "f-1",
      title: "Brand-like spelling in registered domain",
      severity: "high",
      evidence: "The domain contains a zero in place of the letter “o”.",
      explanation: "Visual substitutions can be used to make a domain resemble a familiar brand.",
      impact: "A visitor may mistake this domain for an official account page.",
      recommendation: "Navigate to the service using a saved bookmark or its official website.",
      source: "rule",
    },
    {
      id: "f-2",
      title: "No independent threat-feed result",
      severity: "info",
      evidence: "Threat feeds were not queried for this demonstration report.",
      explanation: "A missing lookup is not evidence that a domain is safe.",
      impact: "Current reputation is unknown.",
      recommendation: "Check authoritative sources before interacting with the site.",
      source: "probe",
    },
  ],
  intelligence: [
    { source: "Google Safe Browsing", status: "unavailable", detail: "Not queried in this demo" },
    { source: "URLhaus", status: "unavailable", detail: "Not queried in this demo" },
    { source: "PhishTank", status: "unavailable", detail: "Not queried in this demo" },
  ],
  checksCompleted: 8,
  checksUnavailable: 3,
  aiExplanation: "This sample domain uses a character substitution that could be mistaken for a familiar brand. The result is a demonstration only: the domain, evidence, and checks have not been independently queried.",
  isDemo: true,
};

export const threatRecords: ThreatRecord[] = [
  { id: "TI-2048", indicator: "secure-payments-check.example", category: "Credential harvesting", reported: "12 min ago", source: "Community report", status: "Under review", severity: "high" },
  { id: "TI-2047", indicator: "parcel-tracking-update.example", category: "Delivery impersonation", reported: "48 min ago", source: "Demonstration feed", status: "Confirmed · demo", severity: "critical" },
  { id: "TI-2046", indicator: "invoice-portal.example", category: "Business email compromise", reported: "2 hours ago", source: "Community report", status: "Under review", severity: "medium" },
  { id: "TI-2045", indicator: "wallet-verify.example", category: "Cryptocurrency scam", reported: "5 hours ago", source: "Demonstration feed", status: "Confirmed · demo", severity: "high" },
  { id: "TI-2044", indicator: "account-alert.example", category: "Brand impersonation", reported: "Yesterday", source: "Community report", status: "Under review", severity: "medium" },
];
