$ErrorActionPreference = 'Continue'
$failed = $false

$formatOutput = & gofmt -l .
if ($LASTEXITCODE -ne 0) {
    Write-Error "gofmt -l . failed with exit code $LASTEXITCODE"
    $failed = $true
}
if ($formatOutput) {
    $formatOutput
    Write-Error "Go files need formatting"
    $failed = $true
}

& go vet ./...
if ($LASTEXITCODE -ne 0) {
    Write-Error "go vet ./... failed with exit code $LASTEXITCODE"
    $failed = $true
}

& go test ./internal/model/... -race -count=1
if ($LASTEXITCODE -ne 0) {
    Write-Error "go test ./internal/model/... -race -count=1 failed with exit code $LASTEXITCODE"
    $failed = $true
}

& node scripts/verify-hash.mjs
if ($LASTEXITCODE -ne 0) {
    Write-Error "node scripts/verify-hash.mjs failed with exit code $LASTEXITCODE"
    $failed = $true
}

if ($failed) {
    exit 1
}
