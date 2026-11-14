import importlib.util
import json
import os
import sqlite3
import tempfile
import tarfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.core import DEFAULT_CONFIG, init_db, load_config, queue_archive_job, queue_job, queue_upload_now, save_config, upsert_result, validate_config, validate_prefix, validate_source

SPEC = importlib.util.spec_from_file_location("runner", Path(__file__).parents[1] / "runner/glacier-runner.py")
runner = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)


class SafetyTests(unittest.TestCase):
    def test_command_has_permanent_safety_flags(self):
        cfg=json.loads(json.dumps(DEFAULT_CONFIG)); mapping={"source":"/volume3/Photo/New Archive","destination":"Photo/New Archive"}
        command=runner.build_command(mapping,cfg,False,"/tmp/filter","/usr/bin/rclone")
        self.assertEqual(command[1],"copy");self.assertNotIn("sync",command);self.assertIn("--no-traverse",command);self.assertIn("--s3-no-check-bucket",command)
        self.assertNotIn("--fast-list",command);self.assertNotIn("--delete-excluded",command)
        self.assertEqual(command[command.index("--transfers") + 1], "1")
        self.assertEqual(command[command.index("--checkers") + 1], "1")
        self.assertEqual(command[command.index("--buffer-size") + 1], "0")
        self.assertNotIn("--bwlimit",command)

    def test_dry_run_only_adds_dry_run(self):
        cfg=json.loads(json.dumps(DEFAULT_CONFIG)); mapping={"source":"/volume3/Photo/Test","destination":"Photo/Test"}
        self.assertIn("--dry-run",runner.build_command(mapping,cfg,True,"/tmp/f","rclone"))

    def test_rejects_volume_root_and_parent_prefix(self):
        with self.assertRaises(ValueError):validate_source("/volume3")
        with self.assertRaises(ValueError):validate_prefix("Photo/../Elsewhere")

    def test_queue_contains_ids_not_commands(self):
        with tempfile.TemporaryDirectory() as td:
            data=Path(td);cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["safety"]["paused"]=False;cfg["mappings"]=[{"id":"m1","source":"/volume3/Photo/Test","destination":"Photo/Test","enabled":True}];save_config(data,cfg)
            job=queue_job(data,"dry-run");raw=(data/"jobs/pending"/f"{job['id']}.json").read_text()
            self.assertIn('"m1"',raw);self.assertNotIn("rclone",raw);self.assertNotIn("/volume3",raw)

    def test_upload_now_is_scoped_to_an_enabled_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            data=Path(td);cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["safety"]["paused"]=False
            cfg["mappings"]=[{"id":"m1","source":"/volume3/Photo","destination":"Photo","enabled":True}];save_config(data,cfg)
            job=queue_upload_now(data,"/volume3/Photo/Old/file.raw")
            self.assertEqual(job["mode"],"upload-now");self.assertEqual(job["mapping_ids"],["m1"])
            self.assertEqual(job["selected_path"],"Old/file.raw")
            with self.assertRaises(ValueError):queue_upload_now(data,"/volume3/Other/file.raw")
            with self.assertRaises(ValueError):queue_upload_now(data,"/volume3/Photo/@eaDir/file.raw")

    def test_upload_now_file_list_keeps_exclusions(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"Photo";root.mkdir();(root/"old.raw").write_bytes(b"old")
            (root/"@eaDir").mkdir();(root/"@eaDir"/"metadata").write_text("skip")
            mapping={"source":str(root),"destination":"Photo","exclusions":[]}
            cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            with patch.object(runner,"validate_source",return_value=str(root)):
                filename,count=runner.explicit_file_list(mapping,cfg,"")
            try:
                values=Path(filename).read_bytes().split(b"\0")
                self.assertEqual(count,1);self.assertIn(b"old.raw",values)
                self.assertFalse(any(b"@eaDir" in value for value in values))
            finally:Path(filename).unlink(missing_ok=True)

    def test_archive_job_has_validated_sources_and_format(self):
        with tempfile.TemporaryDirectory() as td:
            data=Path(td);cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["safety"]["paused"]=False;save_config(data,cfg)
            job=queue_archive_job(data,[{"source":"/volume3/Photo/New Archive","exclusions":["Old"]}],"Folder Archives","tar","custom")
            queued=json.loads((data/"jobs/pending"/f"{job['id']}.json").read_text())
            self.assertEqual(queued["mode"],"archive")
            self.assertEqual(queued["archive_format"],"tar")
            self.assertEqual(queued["destination_mode"],"custom")
            self.assertEqual(queued["sources"][0]["exclusions"],["Old"])
            with self.assertRaises(ValueError):queue_archive_job(data,[{"source":"/volume3"}],"Folder Archives","tar")
            with self.assertRaises(ValueError):queue_archive_job(data,[{"source":"/volume3/Photo"}],"Folder Archives","zip")

    def test_run_history_persists_human_summary(self):
        with tempfile.TemporaryDirectory() as td:
            db=init_db(Path(td));summary='[{"outcome":"uploaded_new","path":"file.txt"}]'
            upsert_result(db,{"id":"job","mode":"backup","trigger":"manual","started_at":"now",
                "finished_at":"now","status":"success","files":1,"candidates":1,"bytes":4,
                "duration":1,"error":"","log":"diagnostic","summary":summary})
            self.assertEqual(db.execute("SELECT summary FROM runs WHERE id='job'").fetchone()[0],summary)

    def test_archive_name_uses_folder_name_and_today(self):
        name=runner.archive_name("/volume3/Photo/New Archive","tar.gz")
        self.assertRegex(name,r"^New Archive_\d{4}-\d{2}-\d{2}\.tar\.gz$")

    def test_archive_destination_can_match_source_hierarchy(self):
        self.assertEqual(runner.archive_destination({"destination_mode":"source"}, "/volume3/Docker/Persistent"), "Docker/Persistent")
        self.assertEqual(runner.archive_destination({"destination_mode":"parent"}, "/volume3/Docker/Persistent"), "Docker")
        self.assertEqual(runner.archive_destination({"destination_mode":"parent"}, "/volume3/Persistent"), "")
        self.assertEqual(runner.archive_destination({"destination_mode":"custom","destination":"Manual"}, "/volume3/Docker/Persistent"), "Manual")

    def test_archive_job_accepts_parent_destination(self):
        with tempfile.TemporaryDirectory() as td:
            data=Path(td);cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["safety"]["paused"]=False;save_config(data,cfg)
            job=queue_archive_job(data,[{"source":"/volume3/Work/_WEBSITES/folder_1"}],"","tar","parent")
            self.assertEqual(job["destination_mode"],"parent")
            self.assertEqual(job["destination"],"")

    def test_archive_contains_original_folder_and_omits_synology_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"Project";root.mkdir();(root/"document.txt").write_text("hello")
            for special in ("@eaDir", ".snapshot", "#snapshot", "#recycle", "@Recycle"):
                (root/special).mkdir();(root/special/"metadata").write_text("skip")
            (root/"Excluded").mkdir();(root/"Excluded"/"private.txt").write_text("skip")
            target=Path(td)/"result.tar";cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            runner.RUNNER_PROGRESS.clear()
            with patch.object(runner,"validate_source",return_value=str(root)), patch.object(runner,"wait_for_safe_temperature"):
                entries,total=runner.archive_source(str(root),target,"tar",cfg,lambda:False,["Excluded"])
            with tarfile.open(target) as archive:names=archive.getnames()
            self.assertEqual(entries,1);self.assertEqual(total,5)
            self.assertIn("Project/document.txt",names)
            self.assertFalse(any(any(special in name for special in ("@eaDir", ".snapshot", "#snapshot", "#recycle", "@Recycle", "Excluded")) for name in names))

    def test_upgrade_forces_existing_installation_paused(self):
        with tempfile.TemporaryDirectory() as td:
            data=Path(td);cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["version"]=1;cfg.pop("safety");cfg["schedule"]["enabled"]=True
            (data/"config.json").write_text(json.dumps(cfg))
            migrated=load_config(data)
            self.assertTrue(migrated["safety"]["paused"])
            self.assertFalse(migrated["schedule"]["enabled"])
            self.assertEqual(migrated["performance"]["scan_batch_entries"],100)
            self.assertEqual(migrated["performance"]["bandwidth_mib"],0)
            self.assertEqual(migrated["performance"]["rclone_cpu_cores"],1)

    def test_performance_limits_are_bounded(self):
        cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["performance"]["transfers"]=5
        with self.assertRaises(ValueError):validate_config(cfg)
        cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["performance"]["temperature_resume_c"]=65
        with self.assertRaises(ValueError):validate_config(cfg)
        cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["performance"]["temperature_pause_c"]=70;cfg["performance"]["temperature_resume_c"]=64;cfg["performance"]["bandwidth_mib"]=12
        command=runner.build_command({"source":"/volume3/Test","destination":"Test"},cfg,False,"/tmp/list","rclone")
        self.assertEqual(command[command.index("--bwlimit")+1],"12M")
        cfg["performance"]["s3_requests_per_second"]=0
        command=runner.build_command({"source":"/volume3/Test","destination":"Test"},cfg,False,"/tmp/list","rclone")
        self.assertNotIn("--tpslimit",command)

    def test_rclone_process_is_pinned_to_configured_cores(self):
        with patch.object(runner.os,"nice") as nice, patch.object(runner.os,"sched_getaffinity",return_value={2,3,4,5},create=True), patch.object(runner.os,"sched_setaffinity",create=True) as affinity:
            runner.constrain_rclone_process(1)
        nice.assert_called_once_with(19);affinity.assert_called_once_with(0,{2})

    def test_rclone_result_counts_explicit_copy_events_not_ambiguous_stats(self):
        log = "\n".join([
            json.dumps({"level":"info","msg":"Copied (new)","object":"one.jpg","size":12}),
            json.dumps({"level":"info","msg":"Transferred: 1 / 1","stats":{"transfers":5,"bytes":0}}),
        ])
        self.assertEqual(runner.parse_output(log), (1, 12))

    def test_live_rclone_stats_update_dashboard_progress(self):
        runner.RUNNER_PROGRESS.clear()
        runner.update_live_transfer_stats(json.dumps({"stats":{"bytes":500,"totalBytes":1000,"transfers":2,"totalTransfers":4,"speed":125,"eta":4}}))
        self.assertEqual(runner.RUNNER_PROGRESS["percentage"], 50.0)
        self.assertEqual(runner.RUNNER_PROGRESS["speed_bps"], 125.0)
        self.assertEqual(runner.RUNNER_PROGRESS["files_transferred"], 2)

    def test_interrupted_job_is_closed_on_runner_restart(self):
        with tempfile.TemporaryDirectory() as td:
            data=Path(td);running=data/"jobs/running";running.mkdir(parents=True)
            (running/"job.json").write_text(json.dumps({"id":"job","mode":"backup","trigger":"manual","created_at":"2026-01-01T00:00:00+00:00"}))
            runner.recover_interrupted_jobs(data)
            result=json.loads((data/"jobs/results/job.json").read_text())
            self.assertEqual(result["status"],"interrupted");self.assertFalse((running/"job.json").exists())

    def test_local_scan_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"file.txt").write_text("data")
            mapping={"source":str(root),"destination":"Test","exclusions":[]};cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            with patch.object(runner,"validate_source",return_value=str(root)), patch.object(runner,"wait_for_safe_temperature"):
                with self.assertRaises(runner.JobCancelled):runner.recent_file_list(mapping,cfg,cancel_check=lambda:True)

    def test_mapping_exclusions_are_relative_and_normalized(self):
        cfg=json.loads(json.dumps(DEFAULT_CONFIG));cfg["mappings"]=[{"id":"m1","source":"/volume3/Music","destination":"Music","enabled":True,"exclusions":["/Lossy/","_import"]}]
        validate_config(cfg)
        self.assertEqual(cfg["mappings"][0]["exclusions"],["Lossy","_import"])
        cfg["mappings"][0]["exclusions"]=["../escape"]
        with self.assertRaises(ValueError):validate_config(cfg)

    def test_throttled_scan_lists_only_recent_allowed_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"keep").mkdir();(root/"skip").mkdir()
            for special in ("@eaDir", ".snapshot", "#snapshot", "#recycle", "@Recycle"):
                (root/special).mkdir();(root/special/"metadata").write_text("ignored")
            (root/"keep"/"new.txt").write_text("new")
            old=root/"keep"/"old.txt";old.write_text("old");os.utime(old,(time.time()-72*3600,)*2)
            (root/"skip"/"excluded.txt").write_text("ignored")
            mapping={"source":str(root),"destination":"Test","exclusions":["skip"]}
            cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            directories=[];changed=[]
            with patch.object(runner,"validate_source",return_value=str(root)), patch.object(runner,"wait_for_safe_temperature"):
                filename,count=runner.recent_file_list(mapping,cfg,lambda path,relative:directories.append((path,relative)),lambda relative,mtime,size,observed_at:changed.append(relative))
            try:
                values=Path(filename).read_bytes().split(b"\0")
                self.assertEqual(count,2);self.assertIn(b"keep/new.txt",values)
                self.assertIn(b"keep/old.txt",values);self.assertNotIn(b"skip/excluded.txt",values)
                self.assertFalse(any(any(special.encode() in value for special in ("@eaDir", ".snapshot", "#snapshot", "#recycle", "@Recycle")) for value in values))
                self.assertIn("keep/new.txt",changed);self.assertTrue(any(relative=="keep" for _,relative in directories))
            finally:
                os.unlink(filename)

    def test_recent_arrival_is_candidate_even_when_file_mtime_is_old(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); target=root/"moved-in.bin"; target.write_bytes(b"data")
            old=time.time()-60*86400; os.utime(target,(old,old))
            index=object.__new__(runner.ChangeIndex);index.lock=runner.threading.RLock()
            index.db=sqlite3.connect(":memory:")
            index.db.execute("CREATE TABLE changes (mapping_id TEXT, relative TEXT, mtime REAL, size INTEGER, observed_at REAL, PRIMARY KEY(mapping_id,relative))")
            index.db.execute("INSERT INTO changes VALUES(?,?,?,?,?)",("m1","moved-in.bin",old,4,time.time()));index.db.commit()
            mapping={"id":"m1","source":str(root),"exclusions":[]};cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            filename,count=index.candidates(mapping,cfg)
            try:
                self.assertEqual(count,1);self.assertIn(b"moved-in.bin",Path(filename).read_bytes())
                index.complete("m1",filename)
                self.assertEqual(index.db.execute("SELECT COUNT(*) FROM changes").fetchone()[0],0)
            finally: os.unlink(filename)

    def test_reconciliation_preserves_recorded_arrival_events(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); listed=root/"empty-list";listed.write_bytes(b"")
            index=object.__new__(runner.ChangeIndex);index.lock=runner.threading.RLock();index.watch_directory=lambda *args:None
            index.db=sqlite3.connect(":memory:")
            index.db.execute("CREATE TABLE mappings (id TEXT PRIMARY KEY, signature TEXT, initialized INTEGER, reconciled_at REAL)")
            index.db.execute("CREATE TABLE directories (mapping_id TEXT, path TEXT, relative TEXT, PRIMARY KEY(mapping_id,path))")
            index.db.execute("CREATE TABLE changes (mapping_id TEXT, relative TEXT, mtime REAL, size INTEGER, observed_at REAL, PRIMARY KEY(mapping_id,relative))")
            index.db.execute("INSERT INTO changes VALUES(?,?,?,?,?)",("m1","arrived.bin",1,4,time.time()));index.db.commit()
            mapping={"id":"m1","source":str(root),"exclusions":[]};cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            with patch.object(runner,"recent_file_list",return_value=(str(listed),0)):
                index.baseline(mapping,cfg,"signature")
            self.assertEqual(index.db.execute("SELECT COUNT(*) FROM changes WHERE relative='arrived.bin'").fetchone()[0],1)

    def test_old_manifest_does_not_trigger_periodic_full_scan(self):
        index=object.__new__(runner.ChangeIndex);index.lock=runner.threading.RLock();index.unwatched=set()
        index.db=sqlite3.connect(":memory:")
        index.db.execute("CREATE TABLE mappings (id TEXT PRIMARY KEY, signature TEXT, initialized INTEGER, reconciled_at REAL)")
        mapping={"id":"m1","source":"/volume3/Test","exclusions":[]};cfg=json.loads(json.dumps(DEFAULT_CONFIG))
        signature=index.signature(mapping,cfg)
        index.db.execute("INSERT INTO mappings VALUES(?,?,?,?)",("m1",signature,1,time.time()-90*86400));index.db.commit()
        with patch.object(index,"candidates",return_value=("indexed-list",0)) as candidates, patch.object(index,"baseline") as baseline:
            self.assertEqual(index.ensure_mapping(mapping,cfg),("indexed-list",0))
        candidates.assert_called_once();baseline.assert_not_called()

    def test_parent_directory_timestamp_detects_moved_file_with_old_mtime(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);target=root/"old-backup.wpress";target.write_bytes(b"data")
            old=time.time()-60*86400;os.utime(target,(old,old))
            mapping={"source":str(root),"destination":"Test","exclusions":[]};cfg=json.loads(json.dumps(DEFAULT_CONFIG))
            with patch.object(runner,"validate_source",return_value=str(root)), patch.object(runner,"wait_for_safe_temperature"):
                filename,count=runner.recent_file_list(mapping,cfg)
            try:
                self.assertEqual(count,1);self.assertIn(b"old-backup.wpress",Path(filename).read_bytes())
            finally: os.unlink(filename)

    def test_combined_report_accounts_for_every_candidate(self):
        outcomes=runner.parse_combined_report("= already.bin\n+ new.bin\n* changed.bin\n! broken.bin\n")
        self.assertEqual(outcomes["already.bin"],"=")
        self.assertEqual(outcomes["new.bin"],"+")
        report=runner.readable_outcome_report({"already.bin":4,"unknown.bin":8},outcomes)
        self.assertIn("already present and identical",report)
        self.assertIn("UNACCOUNTED FOR; retained for retry",report)

    def test_rclone_status_exposes_only_safe_fields(self):
        output = """[aws-archive]\n type = s3\nprovider = AWS\naccess_key_id = XXX\nsecret_access_key = XXX\nregion = us-west-2\n"""
        with patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)):
            status = runner.inspect_rclone_remote("rclone")
        self.assertTrue(status["configured"])
        self.assertEqual(status["region"], "us-west-2")
        self.assertNotIn("access_key_id", status)
        self.assertNotIn("secret_access_key", status)

    def test_runner_status_includes_current_temperature(self):
        with tempfile.TemporaryDirectory() as td, patch.object(runner, "temperatures_c", return_value=[48.2, 53.74]):
            data = Path(td)
            runner.write_status(data, "rclone", "idle")
            status = json.loads((data / "runner-status.json").read_text())
        self.assertEqual(status["temperature_c"], 53.7)
        self.assertEqual(status["state"], "idle")

    def test_runner_restart_request_is_acknowledged(self):
        with tempfile.TemporaryDirectory() as td:
            data = Path(td); pending = data / "control/pending"; pending.mkdir(parents=True)
            request = {"id":"restart-test","action":"restart-runner","expires_at":time.time()+60}
            (pending / "restart-test.json").write_text(json.dumps(request))
            runner.RESTART = False
            runner.process_control_requests(data, "rclone")
            result = json.loads((data / "control/results/restart-test.json").read_text())
            self.assertEqual(result["status"], "success")
            self.assertTrue(runner.RESTART)
            runner.RESTART = False

    def test_s3_browser_lists_only_one_requested_level(self):
        listing = json.dumps([
            {"Name": "Photos", "IsDir": True, "Size": 0, "ModTime": "2026-09-28T00:00:00Z"},
            {"Name": "archive.tar", "IsDir": False, "Size": 123, "ModTime": "2026-09-28T01:00:00Z"},
        ])
        completed = SimpleNamespace(returncode=0, stdout=listing)
        with patch.object(runner.subprocess, "run", return_value=completed) as run:
            result = runner.browse_s3({"prefix": "/Folder Archives/"}, "rclone")
        self.assertEqual(result["prefix"], "Folder Archives")
        self.assertEqual([item["name"] for item in result["entries"]], ["Photos", "archive.tar"])
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["rclone", "lsjson", f"{runner.REMOTE}:{runner.BUCKET}/Folder Archives"])
        self.assertIn("--max-depth", command)

    def test_s3_browser_rejects_parent_traversal(self):
        with self.assertRaises(ValueError):
            runner.browse_s3({"prefix": "safe/../other"}, "rclone")

    def test_rclone_configuration_obscures_secret_via_stdin_and_preserves_other_remotes(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / "rclone.conf"
            config.write_text("[other]\ntype = local\n\n[aws-archive]\ntype = s3\nregion = old\n")
            completed = SimpleNamespace(returncode=0, stdout="obscured-value\n", stderr="")
            request = {"auth_mode": "keys", "access_key_id": "ABCDEFGHIJKLMNOP",
                       "secret_access_key": "a-very-long-secret-key-value"}
            with patch.object(runner, "RCLONE_CONFIG", str(config)), patch.object(runner.subprocess, "run", return_value=completed) as run:
                runner.configure_rclone_remote(request, "rclone")
            command = run.call_args.args[0]
            self.assertEqual(command, ["rclone", "obscure", "-"])
            self.assertEqual(run.call_args.kwargs["input"], request["secret_access_key"])
            self.assertNotIn(request["secret_access_key"], " ".join(command))
            written = config.read_text()
            self.assertIn("[other]\ntype = local", written)
            self.assertIn("secret_access_key = obscured-value", written)
            self.assertNotIn(request["secret_access_key"], written)
            self.assertIn("storage_class =\n", written)


if __name__=="__main__":unittest.main()
