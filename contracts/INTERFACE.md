# ThreatRegistry interface

This file documents the on-chain submission contract used to store only the canonical report hash and risk level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ThreatRegistry {
    function submitReport(bytes32 reportHash, uint8 riskLevel) external;
    function verify(bytes32 reportHash) external view returns (bool exists, uint8 riskLevel, address reporter, uint64 timestamp);
    function reportCount() external view returns (uint256);

    event ReportSubmitted(bytes32 indexed reportHash, uint8 riskLevel, address indexed reporter, uint64 timestamp);

    error AlreadyReported(bytes32 reportHash);
    error InvalidRiskLevel(uint8 riskLevel);
}
```

## Risk mapping

- `1` => `suspicious`
- `2` => `high_risk`
- `3` => `confirmed_malicious`
- `0` and values above `3` pass through `InvalidRiskLevel` and revert.

No raw URL, message body, or report payload is stored on-chain. Only `bytes32 reportHash` and `uint8 riskLevel` are persisted.
