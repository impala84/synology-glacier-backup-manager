# Bare-metal runner

The runner is the only component that invokes rclone. It must run as a NAS user that can read the selected source folders and `/volume1/@rclone/rclone.conf`, and write the manager's `data` and `logs` directories.

It accepts no shell commands from the web app. Queue items contain only a run mode and mapping IDs; the runner reloads and independently validates the fixed remote, bucket, source paths, S3 prefixes and mandatory flags.

The runner performs one deliberately paced baseline walk, stores its directory and change journal in `data/change-index.sqlite3`, and then uses Linux filesystem events to record changes continuously. Normal jobs query that persistent index rather than walking the tree again. The first job after a runner restart performs a controlled reconciliation because filesystem events may have been missed while it was stopped. Excluded directories are pruned before entry, thermal sensors are checked where available, and only the indexed recent-file list is passed to rclone with `--files-from0 --no-traverse`.

## DSM Task Scheduler installation

1. Redeploy the Portainer stack. It exports this file automatically to `/volume1/docker/synology-glacier-backup-manager/data/runner/glacier-runner.py`.
2. In **Control Panel → Task Scheduler**, create a **Triggered Task → User-defined script**.
3. Name it `Glacier Backup Manager Runner`, run it as the dedicated backup user, and trigger it at boot-up.
4. Use this command:

```sh
/usr/bin/python3 /volume1/docker/synology-glacier-backup-manager/data/runner/glacier-runner.py \
  --data-dir /volume1/docker/synology-glacier-backup-manager/data \
  --log-dir /volume1/docker/synology-glacier-backup-manager/logs \
  --remote aws-archive \
  --bucket YOUR-BUCKET-NAME \
  --rclone-config /volume1/@rclone/rclone.conf
```

`--remote`, `--bucket` and `--rclone-config` **pin the destination outside `config.json`**, which the web container can write. The runner refuses to start if `config.json` disagrees, so a compromised container cannot redirect uploads to another bucket. Without them the runner still starts but logs a warning.

If bare-metal rclone is not on the Task Scheduler PATH, append `--rclone /exact/path/to/rclone`.

Do not start the runner until the Portainer stack has created `config.json` and the test mapping has been reviewed.

The DSM task must be started manually once on the first installation because no runner process exists yet. After that, deploying a changed runner automatically asks the existing process to reload itself as soon as it is idle. Deploying an identical version does not restart it, and an active job is never interrupted.

## Change index and catch-up

The runner watches folders for changes and keeps an index of what still needs uploading. Watching only works while the runner is running. When it starts again after being away (a restart, an update, a reboot), it does not re-walk every folder. It lists the folders and reads files only inside folders whose modification time moved since the runner was last seen, which takes minutes instead of hours. Moved, copied and newly created files are caught this way.

Limits: a file edited in place while the runner was away leaves its folder's time unchanged, so that edit is not noticed until the file changes again. If the runner was away for more than 30 days, the index is rebuilt with a full walk. The decision is written to the runner log ("Keeping the change index" or "Change index will be rebuilt").
