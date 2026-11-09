# ThreatRegistry

The deployable implementation is in [`ThreatRegistry.sol`](./ThreatRegistry.sol). The deploying
account is the permanent owner. Only the owner and owner-authorized reporters can submit report
digests; the owner can revoke reporters and correct a registered risk level. The contract stores
the reviewer-submitted risk level, reporter address, and timestamp per digest. Report contents and
target URLs are not part of the contract interface.

The ABI-compatible interface is:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ThreatRegistry {
    function owner() external view returns (address);
    function authorizedReporters(address reporter) external view returns (bool);
    function setAuthorizedReporter(address reporter, bool authorized) external;
    function submitReport(bytes32 reportHash, uint8 riskLevel) external;
    function correctReportRiskLevel(bytes32 reportHash, uint8 riskLevel) external;
    function verify(bytes32 reportHash) external view returns (bool exists, uint8 riskLevel, address reporter, uint64 timestamp);
    function reportCount() external view returns (uint256);

    event ReportSubmitted(bytes32 indexed reportHash, uint8 riskLevel, address indexed reporter, uint64 timestamp);
    event ReporterAuthorizationUpdated(address indexed reporter, bool authorized);
    event ReportRiskCorrected(bytes32 indexed reportHash, uint8 previousRiskLevel, uint8 newRiskLevel, address indexed correctedBy);

    error AlreadyReported(bytes32 reportHash);
    error InvalidRiskLevel(uint8 riskLevel);
    error UnauthorizedReporter(address reporter);
    error InvalidReporter(address reporter);
    error ReportNotFound(bytes32 reportHash);
}
```

## Risk mapping

- `1` => `suspicious`
- `2` => `high_risk`
- `3` => `confirmed_malicious`
- `0` and values above `3` pass through `InvalidRiskLevel` and revert.

Only `bytes32 reportHash` and `uint8 riskLevel` are persisted. No raw URL, message body, or report payload is stored on-chain. The owner account is fixed at deployment; securely back it up because only it can manage authorized reporters or correct a registered risk level.
