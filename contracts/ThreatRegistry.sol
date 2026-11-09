// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ThreatRegistry {
    struct Report {
        uint8 riskLevel;
        address reporter;
        uint64 timestamp;
        bool exists;
    }

    address public immutable owner;
    mapping(address reporter => bool authorized) public authorizedReporters;
    mapping(bytes32 reportHash => Report report) private reports;
    uint256 public reportCount;

    event ReportSubmitted(
        bytes32 indexed reportHash,
        uint8 riskLevel,
        address indexed reporter,
        uint64 timestamp
    );
    event ReporterAuthorizationUpdated(address indexed reporter, bool authorized);
    event ReportRiskCorrected(
        bytes32 indexed reportHash,
        uint8 previousRiskLevel,
        uint8 newRiskLevel,
        address indexed correctedBy
    );

    error AlreadyReported(bytes32 reportHash);
    error InvalidRiskLevel(uint8 riskLevel);
    error UnauthorizedReporter(address reporter);
    error InvalidReporter(address reporter);
    error ReportNotFound(bytes32 reportHash);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert UnauthorizedReporter(msg.sender);
        _;
    }

    function setAuthorizedReporter(address reporter, bool authorized) external onlyOwner {
        if (reporter == address(0)) revert InvalidReporter(reporter);
        authorizedReporters[reporter] = authorized;
        emit ReporterAuthorizationUpdated(reporter, authorized);
    }

    function submitReport(bytes32 reportHash, uint8 riskLevel) external {
        if (msg.sender != owner && !authorizedReporters[msg.sender]) {
            revert UnauthorizedReporter(msg.sender);
        }
        if (riskLevel == 0 || riskLevel > 3) revert InvalidRiskLevel(riskLevel);
        if (reports[reportHash].exists) revert AlreadyReported(reportHash);

        uint64 timestamp = uint64(block.timestamp);
        reports[reportHash] = Report({
            riskLevel: riskLevel,
            reporter: msg.sender,
            timestamp: timestamp,
            exists: true
        });
        reportCount += 1;

        emit ReportSubmitted(reportHash, riskLevel, msg.sender, timestamp);
    }

    function correctReportRiskLevel(bytes32 reportHash, uint8 riskLevel) external onlyOwner {
        if (riskLevel == 0 || riskLevel > 3) revert InvalidRiskLevel(riskLevel);
        Report storage report = reports[reportHash];
        if (!report.exists) revert ReportNotFound(reportHash);

        uint8 previousRiskLevel = report.riskLevel;
        report.riskLevel = riskLevel;
        emit ReportRiskCorrected(reportHash, previousRiskLevel, riskLevel, msg.sender);
    }

    function verify(bytes32 reportHash)
        external
        view
        returns (bool exists, uint8 riskLevel, address reporter, uint64 timestamp)
    {
        Report storage report = reports[reportHash];
        return (report.exists, report.riskLevel, report.reporter, report.timestamp);
    }
}
