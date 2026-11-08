import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const fixturesDir = path.join(rootDir, 'testdata', 'fixtures');
const expectedPath = path.join(fixturesDir, 'expected_hashes.json');
const expected = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));

const fixtureNames = [
  'report_low_risk.json',
  'report_suspicious.json',
  'report_high_risk.json',
  'report_confirmed_malicious.json',
  'report_message.json',
  'report_edge_cases.json',
];

function compareUTF8(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function quoteString(value) {
  let encoded = '"';
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) {
      throw new Error('Canonical string contains an unpaired UTF-16 surrogate');
    }
    switch (point) {
      case 0x22:
        encoded += '\\"';
        break;
      case 0x5c:
        encoded += '\\\\';
        break;
      case 0x08:
        encoded += '\\b';
        break;
      case 0x0c:
        encoded += '\\f';
        break;
      case 0x0a:
        encoded += '\\n';
        break;
      case 0x0d:
        encoded += '\\r';
        break;
      case 0x09:
        encoded += '\\t';
        break;
      default:
        if (point < 0x20) {
          encoded += `\\u00${point.toString(16).padStart(2, '0')}`;
        } else {
          encoded += character;
        }
    }
  }
  return encoded + '"';
}

function canonicalizeValue(value) {
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalizeValue(item)).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort(compareUTF8);
    return '{' + keys.map((key) => `${quoteString(key)}:${canonicalizeValue(value[key])}`).join(',') + '}';
  }
  if (typeof value === 'string') {
    return quoteString(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`Canonical numbers must be safe integers other than -0: ${value}`);
    }
    return String(value);
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  throw new Error(`Unsupported canonical value: ${typeof value}`);
}

function validateJSONNumberTokens(source) {
  let inString = false;
  for (let i = 0; i < source.length; i += 1) {
    const character = source[i];
    if (inString) {
      if (character === '\\') {
        i += 1;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === '-' || (character >= '0' && character <= '9')) {
      const match = source.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
      if (!match) continue;
      const token = match[0];
      if (token.includes('.') || /[eE]/.test(token) || token === '-0') {
        throw new Error(`Non-canonical number token: ${token}`);
      }
      i += token.length - 1;
    }
  }
}

function canonicalizeEvidence(entries = []) {
  return [...entries].sort((a, b) => compareUTF8(a.key, b.key)).map((item) => ({
    key: item.key,
    value: item.value,
  }));
}

function canonicalizeFinding(finding) {
  return {
    id: finding.id,
    module: finding.module,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    source: finding.source,
    evidence: canonicalizeEvidence(finding.evidence),
    impact: finding.impact,
    recommendation: finding.recommendation,
    limitations: finding.limitations,
  };
}

function canonicalizeReport(report) {
  const target = { input: report.target.input };
  if (report.target.message_sha256) target.message_sha256 = report.target.message_sha256;
  if (report.target.normalized_url) target.normalized_url = report.target.normalized_url;
  if (report.target.host) target.host = report.target.host;
  if (report.target.registrable_domain) target.registrable_domain = report.target.registrable_domain;

  const findings = [...report.findings]
    .map(canonicalizeFinding)
    .sort((a, b) => {
      const byID = compareUTF8(a.id, b.id);
      return byID || Buffer.compare(
        Buffer.from(canonicalizeValue(a), 'utf8'),
        Buffer.from(canonicalizeValue(b), 'utf8'),
      );
    });

  const indicators = [...report.indicators]
    .map((indicator) => ({ type: indicator.type, value: indicator.value }))
    .sort((a, b) => compareUTF8(a.type, b.type) || compareUTF8(a.value, b.value));

  const checks = [...report.checks]
    .map((check) => ({ module: check.module, status: check.status, detail: check.detail }))
    .sort((a, b) => compareUTF8(a.module, b.module)
      || compareUTF8(a.detail, b.detail)
      || compareUTF8(a.status, b.status));

  return canonicalizeValue({
    schema_version: report.schema_version,
    kind: report.kind,
    target,
    risk_level: report.risk_level,
    score: report.score,
    findings,
    indicators,
    checks,
    redirect_chain: report.redirect_chain,
    scanned_at: report.scanned_at,
    engine_version: report.engine_version,
  });
}

for (const fileName of fixtureNames) {
  const filePath = path.join(fixturesDir, fileName);
  const sourceBytes = fs.readFileSync(filePath);
  const source = sourceBytes.toString('utf8');
  if (!Buffer.from(source, 'utf8').equals(sourceBytes)) {
    throw new Error(`${fileName}: fixture contains invalid UTF-8`);
  }
  validateJSONNumberTokens(source);
  const report = JSON.parse(source);
  const canonical = canonicalizeReport(report);
  const hash = '0x' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  const expectedHash = expected[fileName];
  if (expectedHash === undefined) {
    throw new Error(`${fileName}: missing expected hash`);
  }
  if (hash !== expectedHash) {
    console.error(`${fileName}: expected ${expectedHash}, got ${hash}`);
    process.exitCode = 1;
    continue;
  }
  console.log(`${fileName}: ${hash}`);
}

if (process.exitCode !== 1) {
  console.log('All fixture hashes match expected_hashes.json');
}
