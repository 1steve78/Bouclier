import { demoInvestigation } from "@/lib/mock-data";
import type {
  BlockchainVerificationResult,
  InvestigationRequest,
  InvestigationResult,
  MessageAnalysisRequest,
  MessageAnalysisResult,
  ThreatRecord,
} from "@/lib/types";
import { threatRecords } from "@/lib/mock-data";

const delay = (duration = 850) =>
  new Promise<void>((resolve) => window.setTimeout(resolve, duration));

export async function investigateURL(
  request: InvestigationRequest,
): Promise<InvestigationResult> {
  if (!request.input.trim()) throw new Error("Enter a URL or domain to investigate.");
  await delay(1050);
  return {
    ...demoInvestigation,
    id: `demo-${Math.random().toString(16).slice(2, 8).toUpperCase()}`,
    submittedUrl: request.input.trim(),
    scannedAt: new Date().toISOString(),
  };
}

export async function analyzeMessage(
  request: MessageAnalysisRequest,
): Promise<MessageAnalysisResult> {
  if (!request.message.trim()) throw new Error("Enter a message to analyze.");
  await delay(950);
  const urls = request.message.match(/https?:\/\/[^\s<>"']+/gi) ?? [];
  const emails = request.message.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g) ?? [];
  const phones = request.message.match(/(?:\+\d[\d\s().-]{7,}\d)/g) ?? [];
  return {
    risk: {
      level: /urgent|immediately|verify|payment/i.test(request.message) ? "suspicious" : "low_risk",
      score: /urgent|immediately|verify|payment/i.test(request.message) ? 58 : 18,
      explanation: "Language indicators are observations, not proof of fraud.",
    },
    indicators: /urgent|immediately|verify|payment/i.test(request.message)
      ? [{ title: "Urgency or account-action language", detail: "The message contains terms that may pressure a recipient to act quickly.", severity: "medium" }]
      : [{ title: "No common pressure language detected", detail: "This heuristic cannot establish sender legitimacy.", severity: "info" }],
    urls: [...new Set(urls)],
    emails: [...new Set(emails)],
    phones: [...new Set(phones)],
    explanation: "This is a heuristic demonstration analysis. The language and extracted indicators have not been verified against a sender, domain, or threat feed.",
    safetyMeasures: [
      "Verify the sender using a separate, trusted contact method.",
      "Do not open links or attachments until their destination is independently checked.",
      "Never share passwords, one-time codes, payment details, or recovery phrases.",
    ],
    isDemo: true,
  };
}

export async function assessWebsiteSecurity(input: string): Promise<InvestigationResult> {
  return investigateURL({ input });
}

export async function getThreatIntelligence(): Promise<ThreatRecord[]> {
  await delay(450);
  return threatRecords;
}

export async function verifyThreatReport(
  identifier: string,
): Promise<BlockchainVerificationResult> {
  if (!identifier.trim()) throw new Error("Enter a report ID, SHA-256 hash, or transaction hash.");
  await delay(750);
  return {
    status: "unavailable",
    reportId: identifier.trim(),
    reportHash: "Not queried",
    transactionHash: "Not queried",
    contractAddress: "Not configured",
    network: "Not configured",
    blockNumber: null,
    timestamp: null,
    isDemo: true,
  };
}
