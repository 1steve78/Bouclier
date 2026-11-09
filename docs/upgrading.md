# Upgrading Bouclier

This guide explains how to safely upgrade Bouclier to a newer version while preserving local scan history, threat intelligence databases, and configuration settings.

---

## 1. Where Bouclier Stores Local State

Bouclier follows local-first data isolation principles. All persistent data is stored in your user home directory:

- **Database path**: `~/.bouclier/bouclier.db`
  - Windows: `C:\Users\<User>\.bouclier\bouclier.db`
  - Linux/macOS: `/home/<user>/.bouclier/bouclier.db`
- **What is stored**:
  - Saved scan assessments and full canonical reports.
  - Threat intelligence feed indicators (`intel_indicators`).
  - Feed sources and update timestamps (`intel_sources`, `intel_sync_runs`).
- **Configuration path** (optional):
  - Passed via `--config <path>` or located at your chosen deployment path.

---

## 2. Backup Your Local Database Before Upgrading

Before performing any version upgrade, it is best practice to back up your SQLite database file:

### On Windows (PowerShell):
```powershell
Copy-Item "$HOME\.bouclier\bouclier.db" "$HOME\.bouclier\bouclier.db.backup-$(Get-Date -Format 'yyyyMMdd')"
```

### On Linux / macOS:
```bash
cp ~/.bouclier/bouclier.db ~/.bouclier/bouclier.db.backup-$(date +%Y%m%d)
```

---

## 3. Upgrading the Executable

Because Bouclier is distributed as a single static binary, upgrading simply involves replacing the executable file.

### Windows
1. Download the new release `.zip` from GitHub Releases.
2. Terminate any running instances of `bouclier` or `bouclier serve`.
3. Extract and overwrite `bouclier.exe` in your installation folder (e.g. `$HOME\AppData\Local\Programs\bouclier\bouclier.exe`).

### Linux / macOS
1. Download the new release `.tar.gz`.
2. Extract the new binary:
   ```bash
   tar -xzf bouclier_v1.x.x_linux_amd64.tar.gz
   ```
3. Overwrite the existing executable:
   ```bash
   sudo install -m 0755 bouclier /usr/local/bin/bouclier
   ```

---

## 4. Automatic Database Migrations

Bouclier includes an embedded versioned schema migration engine (`schema_migrations` table):

- When a new binary starts and accesses `~/.bouclier/bouclier.db`, it checks the current schema version.
- Any new migrations are automatically applied within an atomic transaction before any scan or intelligence queries execute.
- Existing historical scans and indicator records remain intact and backward-compatible.
- Migrations are fully idempotent and safe across restarts.

---

## 5. Verification After Upgrade

Run the following checks to confirm a successful upgrade:

```bash
# 1. Verify new version and commit metadata
bouclier version

# 2. Verify scan history is accessible
bouclier history list

# 3. Verify threat intelligence database status
bouclier intel status
```
