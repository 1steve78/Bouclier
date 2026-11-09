# Installing Bouclier

Bouclier is distributed as a single standalone executable with no external runtime dependencies. Pre-compiled binaries are provided for Windows, Linux, and macOS.

---

## System Requirements

- **Operating System**:
  - Windows 10/11 or Windows Server 2016+ (x86_64, ARM64)
  - Linux (glibc or musl/Alpine) on x86_64, ARM64
  - macOS 12 Monterey or later (Apple Silicon ARM64, Intel x86_64)
- **Terminal**: Modern terminal with ANSI color support (e.g. Windows Terminal, PowerShell 7, iTerm2, Alacritty, GNOME Terminal).

### Archive Contents
Every release archive contains:
- `bouclier` (or `bouclier.exe`): Self-contained compiled binary.
- `README.md`: Overview and documentation guide.
- `LICENSE`: Project MIT License.
- `THIRD_PARTY_NOTICES.md`: Preserved notices and licenses for third-party libraries.

---

## 1. Installation on Windows

### Option A: Manual Download & PowerShell Setup (Recommended)

1. **Download the archive**:
   Download `bouclier_v1.0.0_windows_amd64.zip` (or `_arm64.zip` for ARM-based Surface devices) from the [GitHub Releases](https://github.com/1steve78/Bouclier/releases) page.

2. **Extract the archive using PowerShell**:
   ```powershell
   # Create a destination directory
   New-Item -ItemType Directory -Force -Path "$HOME\AppData\Local\Programs\bouclier"

   # Extract archive
   Expand-Archive -Path "bouclier_v1.0.0_windows_amd64.zip" -DestinationPath "$HOME\AppData\Local\Programs\bouclier" -Force
   ```

3. **Add to user PATH**:
   ```powershell
   [Environment]::SetEnvironmentVariable(
       "Path",
       [Environment]::GetEnvironmentVariable("Path", "User") + ";$HOME\AppData\Local\Programs\bouclier",
       "User"
   )
   ```
   *Note: Restart your terminal session after updating PATH.*

4. **Verify installation**:
   ```powershell
   bouclier version
   ```

---

## 2. Installation on Linux

### Option A: Direct Binary Install

1. **Download and extract the archive**:
   ```bash
   # For AMD64 (x86_64)
   curl -LO https://github.com/1steve78/Bouclier/releases/download/v1.0.0/bouclier_v1.0.0_linux_amd64.tar.gz
   tar -xzf bouclier_v1.0.0_linux_amd64.tar.gz

   # Or for ARM64 (e.g. Raspberry Pi, AWS Graviton)
   # curl -LO https://github.com/1steve78/Bouclier/releases/download/v1.0.0/bouclier_v1.0.0_linux_arm64.tar.gz
   # tar -xzf bouclier_v1.0.0_linux_arm64.tar.gz
   ```

2. **Move to system PATH & set executable permissions**:
   ```bash
   sudo install -m 0755 bouclier /usr/local/bin/bouclier
   ```

3. **Prepare local state directory**:
   Bouclier automatically creates its database directory on first launch, but you can explicitly initialize it:
   ```bash
   mkdir -p ~/.bouclier && chmod 0700 ~/.bouclier
   ```

4. **Verify installation**:
   ```bash
   bouclier version
   ```

---

## 3. Installation on macOS

1. **Download and extract**:
   ```bash
   # For Apple Silicon (M1/M2/M3/M4)
   curl -LO https://github.com/1steve78/Bouclier/releases/download/v1.0.0/bouclier_v1.0.0_darwin_arm64.tar.gz
   tar -xzf bouclier_v1.0.0_darwin_arm64.tar.gz

   # For Intel Macs
   # curl -LO https://github.com/1steve78/Bouclier/releases/download/v1.0.0/bouclier_v1.0.0_darwin_amd64.tar.gz
   # tar -xzf bouclier_v1.0.0_darwin_amd64.tar.gz
   ```

2. **Install to `/usr/local/bin`**:
   ```bash
   sudo install -m 0755 bouclier /usr/local/bin/bouclier
   ```

3. **Verify**:
   ```bash
   bouclier version
   ```

> [!NOTE]
> Homebrew tap distribution is planned for future releases. Package-manager distribution is not yet provided; always download verified binaries from official GitHub releases.

---

## 4. Building from Source

If you prefer building from source, ensure you have **Go 1.22+** installed:

```bash
git clone https://github.com/1steve78/Bouclier.git
cd Bouclier
go build -trimpath -o bin/bouclier .
```

To install directly to your `$GOPATH/bin`:
```bash
go install .
```

---

## 5. Verifying Release Integrity

Every official release includes a `checksums.txt` file containing SHA-256 hashes.

On Linux/macOS:
```bash
sha256sum --ignore-missing -c checksums.txt
```

On Windows (PowerShell):
```powershell
Get-FileHash bouclier_v1.0.0_windows_amd64.zip -Algorithm SHA256
```
Confirm the resulting output matches the published hash in `checksums.txt`.
