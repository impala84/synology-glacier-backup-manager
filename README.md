# Synology Glacier Backup Manager

A small, allow-list based web interface for scheduled uploads from a Synology NAS to an existing AWS S3 archive. The web application runs as a Portainer stack; a deliberately small host runner executes the NAS's existing bare-metal `rclone` installation.

## Safety invariants

- Uses `rclone copy`, never `sync`.
- Always passes `--no-traverse` and `--s3-no-check-bucket`.
- Builds one throttled local baseline, then maintains a persistent SQLite change index using Linux filesystem events.
- Normal jobs read only indexed changes; a runner interruption triggers a safe reconciliation scan because events may have been missed.
- The manual TAR archive tab can package selected folders as dated `.tar` or `.tar.gz` files and upload them without modifying the originals.
- **Upload now** can explicitly queue one file or folder from an enabled source, bypassing the recent-file window while preserving all exclusions and normal remote comparison.
- Uses one transfer, one checker, no transfer buffer, lowest process priority and S3 request throttling.
- Hard-limits rclone to one CPU core by default using both Linux CPU affinity and Go's runtime limit; the allowed core count is configurable.
- Pauses local scanning at the configured temperature when exposed NAS thermal sensors are available.
- Exposes bounded scan pacing, transfer, checker, bandwidth, S3 request-rate and thermal controls in Settings.
- Leaves upload bandwidth unlimited by default; an optional MiB/s cap can be set manually.
- Starts paused after the safety upgrade; enabling the runner never starts a job by itself.
- Keeps backup jobs free of remote traversal. The separate, read-only S3 browser lists only the location the administrator explicitly opens, one level at a time.
- Runs only explicitly enabled source-to-prefix mappings.
- Source volumes are mounted read-only in the web container.
- The existing rclone configuration is read only by the host runner and is never exposed in the UI.
- Does not set an S3 storage class; the existing lifecycle policy remains responsible for Deep Archive transitions.
- Does not alter Cloud Sync.

## Components

- `app/`: dependency-free Python web application, scheduler and SQLite history store.
- `runner/`: dependency-free host service that validates queued work and invokes bare-metal rclone.
- `compose.yaml`: Portainer- and Synology Container Manager-ready project definition.
- `tests/`: safety and queue protocol tests using a fake rclone executable.

## Persistent NAS layout

```text
/volume1/docker/synology-glacier-backup-manager/
  data/
    config.json
    history.sqlite3
    jobs/{pending,running,results,cancelled}/
  logs/
  runner/
```

The initial Portainer stack mounts only the application data directory plus explicitly chosen source roots. Edit `compose.yaml` before deployment so the read-only mounts and `GBM_BROWSE_ROOTS` match the folders you want users to browse.

## Local development

```bash
python3 -m unittest discover -s tests -v
GBM_DATA_DIR=./work/data GBM_SOURCE_MOUNTS=/tmp:/tmp python3 -m app.server
```

Open <http://127.0.0.1:8787>.

## Deployment sequence

1. Copy `.env.example` to `.env`. Set `GBM_BUCKET`, review the rclone remote and config path, and choose the correct timezone.
2. Adjust the source bind mounts, `GBM_BROWSE_ROOTS` and `GBM_SOURCE_MOUNTS`; keep all source mounts read-only.
3. Deploy `compose.yaml` as either a Portainer stack or a Synology Container Manager project. This exports `runner/glacier-runner.py` into the persistent data folder.
4. Install the runner using a DSM boot-up task (instructions in `runner/README.md`). Run that task manually once. Subsequent deployments automatically restart a connected, idle runner when its code has changed.
5. Create the local administrator account and leave the backup engine paused while reviewing the installation.
6. Add one harmless test mapping and run **Dry Run**.
7. Run one real test with a uniquely named harmless file and verify it in S3.
8. Only then add production mappings.

No backup step deletes or enumerates the existing S3 dataset.

The **S3 browser** provides a read-only view of the configured bucket. It lists one explicitly opened location at a time and can pass that location to the TAR archive destination field. It does not offer delete, move or rename operations.

## One-off TAR archives

Use **TAR archive** to select up to 20 folders. Each folder is packaged separately as
`Folder name_YYYY-MM-DD.tar` (recommended) or `.tar.gz`, then uploaded beneath the
matching source hierarchy by default. For example, `/volume3/Docker/Persistent` uploads
to `Docker/Persistent/`. A custom S3 location can be selected in the browser instead.
The parent-folder option uploads the dated archive directly beside the matching source
folder: `/volume3/Docker/Persistent` becomes `Docker/Persistent_YYYY-MM-DD.tar`.
The runner checks temporary free space first, excludes Synology
metadata folders, refuses to replace a different object with the same name, and
removes the local temporary archive after a successful upload. Failed or cancelled
temporary archives remain in `data/archive-work` for diagnosis.

Successful TAR jobs are recorded locally. A blue dot appears beside previously archived
folders in both folder browsers; hovering over it shows the most recent archive date.

## Bucket versioning (recommended)

`rclone copy` replaces an object when the local file changed. To keep a last-resort copy of the
previous version at almost no extra cost, enable **S3 Bucket Versioning** and add a lifecycle rule
that permanently deletes noncurrent versions after about 200 days (Deep Archive bills a 180-day
minimum on replaced objects anyway). Also abort incomplete multipart uploads after 7 days. Keep your
existing Deep Archive transition rule. Versioning adds no ingress charge; egress only occurs on restore.

## Storage & cost card (Overview)

The Overview page shows how much is stored in S3, an estimated monthly storage cost, and (optionally) the real AWS bill.

- **Stored size** is measured by the runner with a read-only `rclone size` (a cheap LIST, no downloads). Between measurements the card adds the bytes this app has uploaded since, and it re-measures weekly when idle (switchable). *Recalculate size* does it on demand.
- **Estimated cost** = size × the editable price per GB-month (default `$0.00099`, S3 Glacier Deep Archive in us-east-1/us-west-2; check the pricing link for your region). It covers storage only, not requests or early-deletion charges.
- **Actual AWS bill** uses Cost Explorer and is off until you add credentials:
  1. Enable Cost Explorer in the AWS Billing console (data lags about a day).
  2. Create an IAM user with only this policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ce:GetCostAndUsage","Resource":"*"}]}`
  3. On the NAS save `{"access_key_id": "...", "secret_access_key": "..."}` as `/volume1/@rclone/aws-billing.json`, owned by the runner user, `chmod 600` (the runner refuses looser permissions). Use `--billing-credentials` to choose another path.
  4. Restart the runner so it advertises the new capability.

  Each refresh costs about $0.01 and runs at most once a day (plus the manual *Refresh bill* button). The figure is the whole account's S3 + Glacier spend, not only this bucket. The secret key never leaves the NAS; requests are signed locally.

## Updates

The application checks its public version marker every six hours and shows an **Update
available** notice when a newer release exists. It never receives access to Docker and
cannot replace its own container. Update the repository, then redeploy the stack/project in
Portainer or Synology Container Manager; the image is built locally from the repository. Set `GBM_UPDATE_CHECK=false` to disable the
outbound version check.

## Security and support

Read [SECURITY.md](SECURITY.md) before deployment. This is independent software provided without warranty; it is not affiliated with or endorsed by AWS or Synology. The code is available under the [MIT License](LICENSE), while third-party names and marks remain the property of their owners as described in [TRADEMARKS.md](TRADEMARKS.md).
