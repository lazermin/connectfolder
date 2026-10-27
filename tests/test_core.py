#!/usr/bin/env python3
"""Тесты ядра и помощника connectfolder. Запуск: make test"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOP = os.path.dirname(HERE)
sys.path.insert(0, TOP)
sys.path.insert(0, HERE)

import connectfolder_core as core  # noqa: E402
import demo_seed  # noqa: E402

HELPER = os.path.join(TOP, "connectfolder-helper")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class TestNetworkPath(unittest.TestCase):
    def test_forms(self):
        for text in ("fileserver/docs", "//fileserver/docs", "\\\\fileserver\\docs",
                     "smb://fileserver/docs/", " fileserver//docs "):
            self.assertEqual(core.parse_network_path(text), ("fileserver", "docs"), text)
        self.assertEqual(core.parse_network_path("10.0.0.5/a/b c"), ("10.0.0.5", "a/b c"))

    def test_bad(self):
        for text in ("", "server", "srv;rm -rf/x", "srv/a\"b", "srv/a/../b",
                     "srv/a\nb", "-srv/x"):
            with self.assertRaises(core.ValidationError, msg=text):
                core.parse_network_path(text)

    def test_suggest_key(self):
        self.assertEqual(core.suggest_key("docs/Отдел продаж"), "Отдел_продаж")
        self.assertEqual(core.suggest_key("c$"), "c")


class TestMapLine(unittest.TestCase):
    def roundtrip(self, share):
        line = core.build_map_line(share)
        back = core.parse_map_line(line)
        self.assertIsNotNone(back, line)
        self.assertEqual(back.to_dict(), share.to_dict(), line)
        return line

    def test_password_owner(self):
        line = self.roundtrip(core.Share("docs", "fs", "docs"))
        self.assertEqual(
            line, "docs\t-fstype=cifs,rw,credentials=/etc/connectfolder/credentials/docs,"
                  "uid=$UID,gid=$GID,file_mode=0600,dir_mode=0700\t://fs/docs")
        line = self.roundtrip(core.Share("d", "fs", "d", extra=["file_mode=0640"]))
        self.assertIn("dir_mode=0700,file_mode=0640", line)
        self.assertNotIn("file_mode=0600", line)

    def test_variants(self):
        self.roundtrip(core.Share("a", "fs", "s/sub", smb_version="3.0",
                                  access=core.ACCESS_SHARED, read_only=True,
                                  extra=["iocharset=utf8", "nobrl"]))
        self.roundtrip(core.Share("k", "dc1.corp.local", "otdel", auth=core.AUTH_KERBEROS,
                                  access=core.ACCESS_NONE))
        self.roundtrip(core.Share("n", "fs", "x", access=core.ACCESS_NONE,
                                  extra=["uid=1000"]))

    def test_special_chars_escaped(self):
        line = self.roundtrip(core.Share("h", "fs", "users$/Мои документы & co"))
        self.assertIn('"://fs/users\\$/Мои документы \\& co"', line)

    def test_old_format(self):
        sh = core.parse_map_line(
            "archive  -fstype=cifs,vers=1.0,rw,noperm,credentials=/root/.auth_smb/archive"
            "  ://nas01/archive/2020")
        self.assertEqual((sh.key, sh.server, sh.share_path, sh.smb_version, sh.access),
                         ("archive", "nas01", "archive/2020", "1.0", core.ACCESS_SHARED))
        self.assertEqual(sh.credentials_path, "/root/.auth_smb/archive")
        self.assertEqual(sh.extra, [])
        k = core.parse_map_line("o -fstype=cifs,multiuser,cruid=$UID,sec=krb5,"
                                "domain=corp.local ://dc1/otdel")
        self.assertEqual(k.auth, core.AUTH_KERBEROS)
        self.assertEqual(k.extra, [])

    def test_format_0_2_5(self):
        """Строки версии 0.2.5 (RED SOFT)."""
        pw = core.parse_map_line(
            "docs  -fstype=cifs,vers=1.0,file_mode=0600,dir_mode=0700,noperm,"
            "credentials=/root/.auth_smb/docs  ://srv/docs")
        self.assertEqual((pw.access, pw.smb_version), (core.ACCESS_SHARED, "1.0"))
        self.assertEqual(pw.extra, ["file_mode=0600", "dir_mode=0700"])
        krb = core.parse_map_line(
            "otd  -fstype=cifs,multiuser,cruid=$UID,sec=krb5,iocharset=utf8,"
            "file_mode=0600,dir_mode=0700,domain=corp.local  ://dc1/otd")
        self.assertEqual(krb.auth, core.AUTH_KERBEROS)
        self.assertEqual(krb.extra, ["iocharset=utf8", "file_mode=0600", "dir_mode=0700"])
        core.validate_share(pw)
        core.validate_share(krb)

    def test_not_ours(self):
        for line in ("", "# comment", "+auto.samba", "cd -fstype=iso9660,ro :/dev/sr0",
                     "g -fstype=cifs,guest ://srv/pub", "x  ://srv/y"):
            self.assertIsNone(core.parse_map_line(line), line)

    def test_validation(self):
        bad = [core.Share("bad key", "fs", "x"), core.Share("a", "fs", "x", extra=["rw"]),
               core.Share("a", "fs", "x", extra=["password=1"]),
               core.Share("a", "fs", "x", extra=["uid=0"]),
               core.Share("a", "fs", "x", extra=["a,b"]),
               core.Share("a", "fs", "x", smb_version="3;id")]
        for sh in bad:
            with self.assertRaises(core.ValidationError, msg=sh):
                core.validate_share(sh)


class TestMapFile(unittest.TestCase):
    TEXT = ("# мой комментарий\n"
            "\n"
            "cd -fstype=iso9660,ro :/dev/sr0\n"
            "docs\t-fstype=cifs,rw,noperm,credentials=/x/docs\t://fs/docs\n"
            "multi -fstype=nfs \\\n"
            "    srv:/export\n"
            "media -fstype=cifs,rw,noperm,credentials=/x/media ://fs/media\n")

    def test_preserves_foreign_lines(self):
        mf = core.MapFile.parse(self.TEXT)
        self.assertEqual(mf.render(), self.TEXT)
        self.assertEqual([s.key for s in mf.shares], ["docs", "media"])

    def test_remove_by_key_not_index(self):
        mf = core.MapFile.parse(self.TEXT)
        mf.remove("media")
        out = mf.render()
        self.assertIn("# мой комментарий", out)
        self.assertIn("cd -fstype=iso9660", out)
        self.assertIn("docs\t", out)
        self.assertNotIn("media", out)

    def test_has_key_sees_foreign(self):
        mf = core.MapFile.parse(self.TEXT)
        self.assertTrue(mf.has_key("cd"))
        self.assertTrue(mf.has_key("multi"))
        self.assertFalse(mf.has_key("nope"))


class TestCredentials(unittest.TestCase):
    def test_old_and_new(self):
        old = core.parse_credentials("[smb]\nusername = guest\npassword = Pa%ss 1\ndomain = W\n")
        self.assertEqual(old, {"username": "guest", "password": "Pa%ss 1", "domain": "W"})
        txt = core.format_credentials("u", "p=%x", "D")
        self.assertEqual(txt, "username=u\npassword=p=%x\ndomain=D\n")
        self.assertEqual(core.parse_credentials(txt)["password"], "p=%x")

    def test_reject_newline(self):
        with self.assertRaises(core.ValidationError):
            core.format_credentials("u", "a\nusername=root")


class TestMountinfo(unittest.TestCase):
    def test_is_mounted(self):
        mi = ("30 25 0:40 / /media/share rw - autofs systemd-1 rw\n"
              "31 30 0:41 / /media/share/docs rw - cifs //fs/docs rw\n"
              "32 30 0:42 / /media/share/my\\040dir rw - cifs //fs/x rw\n")
        self.assertTrue(core.is_mounted("/media/share/docs", mi))
        self.assertTrue(core.is_mounted("/media/share/my dir", mi))
        self.assertFalse(core.is_mounted("/media/share", mi))
        self.assertFalse(core.is_mounted("/media/share/other", mi))


class RootCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        demo_seed.seed(self.root) if self.seed_old else self._fresh()
        self.paths = core.Paths(self.root)
        self.sys = core.System(self.paths, run_commands=False)

    seed_old = False

    def _fresh(self):
        demo_seed.seed(self.root)
        os.remove(os.path.join(self.root, "etc/auto.samba"))
        os.remove(os.path.join(self.root, "root/.auth_smb/docs"))
        os.remove(os.path.join(self.root, "root/.auth_smb/archive"))
        os.rmdir(os.path.join(self.root, "root/.auth_smb"))
        with open(os.path.join(self.root, "etc/auto.master"), "w") as f:
            f.write("/misc\t/etc/auto.misc\n+auto.master\n")

    def tearDown(self):
        self.tmp.cleanup()

    def op(self, fn, *a):
        self.sys.begin()
        try:
            r = fn(self.sys, *a)
        except Exception:
            self.sys.rollback()
            raise
        self.sys.commit()
        return r


class TestOperations(RootCase):
    def test_add_creates_everything(self):
        sh = core.Share("docs", "fs", "docs")
        self.op(core.save_share, sh, {"username": "u", "password": "p%1", "domain": ""}, None)
        master = read(self.paths.master_file)
        self.assertIn("+dir:/etc/auto.master.d", master)
        self.assertEqual(read(self.paths.master_d_file), core.master_d_content())
        self.assertIn(core.build_map_line(sh), read(self.paths.map_file))
        cf = self.paths.cred_file("docs")
        self.assertEqual(read(cf), "username=u\npassword=p%1\n")
        self.assertEqual(mode(cf), 0o600)
        self.assertEqual(mode(self.paths.cred_dir), 0o700)
        self.assertTrue(any("systemctl reload autofs" in e.cmd for e in self.sys.log))

    def test_duplicate_and_rollback(self):
        sh = core.Share("docs", "fs", "docs")
        self.op(core.save_share, sh, {"username": "u", "password": "p"}, None)
        map_before = read(self.paths.map_file)
        with self.assertRaises(core.OperationError):
            self.op(core.save_share, sh, {"username": "x", "password": "y"}, None)
        self.assertEqual(read(self.paths.map_file), map_before)
        self.assertEqual(read(self.paths.cred_file("docs")), "username=u\npassword=p\n")

    def test_edit_keep_password_and_rename(self):
        self.op(core.save_share, core.Share("docs", "fs", "docs"),
                {"username": "u", "password": "secret"}, None)
        new = core.Share("docs2", "fs", "docs/sub", smb_version="3.0")
        self.op(core.save_share, new, {"username": "u2", "password": None, "domain": "D"}, "docs")
        self.assertFalse(os.path.exists(self.paths.cred_file("docs")))
        self.assertEqual(read(self.paths.cred_file("docs2")),
                         "username=u2\npassword=secret\ndomain=D\n")
        mf = core.MapFile.load(self.paths.map_file)
        self.assertEqual([s.key for s in mf.shares], ["docs2"])
        self.assertEqual(core.get_credentials(self.paths, "docs2"),
                         {"username": "u2", "domain": "D", "has_password": True})

    def test_switch_to_kerberos_removes_creds(self):
        self.op(core.save_share, core.Share("docs", "fs", "docs"),
                {"username": "u", "password": "p"}, None)
        self.op(core.save_share, core.Share("docs", "fs", "docs", auth=core.AUTH_KERBEROS),
                None, "docs")
        self.assertFalse(os.path.exists(self.paths.cred_file("docs")))
        self.assertIn("sec=krb5", read(self.paths.map_file))

    def test_new_without_password_fails(self):
        with self.assertRaises(core.OperationError):
            self.op(core.save_share, core.Share("a", "fs", "a"), {"username": "u"}, None)
        self.assertFalse(os.path.exists(self.paths.map_file))
        self.assertFalse(os.path.exists(self.paths.master_d_file))

    def test_remove(self):
        with open(self.paths.map_file, "w") as f:
            f.write("# keep\ncd -fstype=iso9660 :/dev/sr0\n")
        self.op(core.save_share, core.Share("docs", "fs", "docs"),
                {"username": "u", "password": "p"}, None)
        self.op(core.remove_share, "docs")
        self.assertEqual(read(self.paths.map_file), "# keep\ncd -fstype=iso9660 :/dev/sr0\n")
        self.assertFalse(os.path.exists(self.paths.cred_file("docs")))

    def test_conflict_in_master(self):
        with open(self.paths.master_file, "a") as f:
            f.write("/media/share /etc/auto.other\n")
        with self.assertRaises(core.OperationError) as cm:
            self.op(core.save_share, core.Share("a", "fs", "a"),
                    {"username": "u", "password": "p"}, None)
        self.assertIn("/etc/auto.other", str(cm.exception))

    def test_state(self):
        st = core.read_state(self.paths, demo=True)
        self.assertFalse(st.master_configured)
        self.assertFalse(st.old_config)
        self.op(core.save_share, core.Share("docs", "fs", "docs"),
                {"username": "u", "password": "p"}, None)
        st = core.read_state(self.paths, demo=True)
        self.assertTrue(st.master_configured)
        self.assertEqual([s.key for s in st.shares], ["docs"])


class TestMigration(RootCase):
    seed_old = True

    def test_state_sees_old(self):
        st = core.read_state(self.paths, demo=True)
        self.assertTrue(st.old_config)
        self.assertEqual(st.old_shares, 3)
        self.assertEqual(st.conflicts, [])

    def test_migrate(self):
        rep = self.op(core.migrate_old_config)
        self.assertEqual(rep.migrated, ["docs", "archive", "otdel"])
        mf = core.MapFile.load(self.paths.map_file)
        byk = {s.key: s for s in mf.shares}
        self.assertEqual(byk["docs"].access, core.ACCESS_SHARED)     # поведение сохранено
        self.assertEqual(byk["archive"].smb_version, "1.0")
        self.assertEqual(byk["otdel"].auth, core.AUTH_KERBEROS)
        self.assertIn("credentials=/etc/connectfolder/credentials/docs",
                      read(self.paths.map_file))
        self.assertEqual(read(self.paths.cred_file("docs")),
                         "username=ivanov\npassword=Pa%ss 1\ndomain=CORP\n")
        self.assertEqual(mode(self.paths.cred_file("docs")), 0o600)

        master = read(self.paths.master_file)
        self.assertNotIn("\n/media/share    /etc/auto.samba", master)
        self.assertIn("# /media/share    /etc/auto.samba    --ghost", master)
        self.assertEqual(core.master_conflicts(master, ignore_old=False), [])
        self.assertTrue(os.path.exists(self.paths.master_file + core.BACKUP_SUFFIX))

        self.assertFalse(os.path.exists(self.paths.old_map_file))
        self.assertTrue(os.path.exists(self.paths.old_map_file + core.MIGRATED_SUFFIX))
        arch = self.paths.old_cred_dir + core.MIGRATED_SUFFIX
        self.assertEqual(mode(arch), 0o700)
        self.assertEqual(mode(os.path.join(arch, "docs")), 0o600)

        st = core.read_state(self.paths, demo=True)
        self.assertFalse(st.old_config)
        self.assertTrue(st.master_configured)

        again = self.op(core.migrate_old_config)
        self.assertTrue(again.nothing_to_do)

    def test_migrate_keeps_unknown_and_skips_dupes(self):
        with open(self.paths.old_map_file, "a") as f:
            f.write("# старый комментарий\ncd -fstype=iso9660,ro :/dev/sr0\n")
        with open(self.paths.map_file, "w") as f:
            f.write("docs -fstype=cifs,rw,credentials=/x ://other/docs\n")
        os.remove(os.path.join(self.paths.old_cred_dir, "archive"))
        rep = self.op(core.migrate_old_config)
        self.assertEqual(rep.skipped, ["docs"])
        self.assertIn("archive", rep.migrated)
        self.assertTrue(any("archive" in w for w in rep.warnings))
        self.assertIn("cd -fstype=iso9660,ro :/dev/sr0", read(self.paths.map_file))

    def test_migrate_rollback(self):
        before_master = read(self.paths.master_file)
        before_map = read(self.paths.old_map_file)
        orig_rename = self.sys.rename

        def boom(src, dst):
            if src == self.paths.old_cred_dir:
                raise OSError("сбой")
            orig_rename(src, dst)
        self.sys.rename = boom
        with self.assertRaises(OSError):
            self.op(core.migrate_old_config)
        self.assertEqual(read(self.paths.master_file), before_master)
        self.assertEqual(read(self.paths.old_map_file), before_map)
        self.assertFalse(os.path.exists(self.paths.map_file))
        self.assertFalse(os.path.exists(self.paths.cred_dir))


class TestHelper(RootCase):
    seed_old = True

    def start(self):
        env = dict(os.environ, CONNECTFOLDER_ROOT=self.root)
        return subprocess.Popen([sys.executable, "-I", HELPER], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, universal_newlines=True, env=env)

    def call(self, p, action, **params):
        p.stdin.write(json.dumps({"id": 1, "action": action, "params": params}) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    def test_protocol(self):
        p = self.start()
        try:
            r = self.call(p, "hello")
            self.assertTrue(r["ok"] and r["result"]["demo"])
            r = self.call(p, "run", cmd="id")
            self.assertFalse(r["ok"])
            r = self.call(p, "migrate")
            self.assertTrue(r["ok"], r)
            self.assertEqual(len(r["result"]["migrated"]), 3)
            r = self.call(p, "get_credentials", key="docs")
            self.assertEqual(r["result"]["username"], "ivanov")
            self.assertNotIn("password", r["result"])
            r = self.call(p, "get_credentials", key="../../etc/shadow")
            self.assertFalse(r["ok"])
            share = core.Share("new", "fs", "new").to_dict()
            r = self.call(p, "save", share=share,
                          credentials={"username": "u", "password": "p"})
            self.assertTrue(r["ok"], r)
            self.assertTrue(any("reload" in x["cmd"] for x in r["log"]))
            r = self.call(p, "save", share=dict(share, key="bad key"),
                          credentials={"username": "u", "password": "p"})
            self.assertFalse(r["ok"])
            r = self.call(p, "remove", key="new")
            self.assertTrue(r["ok"], r)
        finally:
            p.stdin.close()
            p.wait(5)

    def test_cli_migrate(self):
        env = dict(os.environ, CONNECTFOLDER_ROOT=self.root)
        out = subprocess.run([sys.executable, "-I", HELPER, "--migrate"], env=env,
                             stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("Перенесено каталогов: 3", out.stdout)
        out = subprocess.run([sys.executable, "-I", HELPER, "--migrate", "--quiet"], env=env,
                             stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(out.stdout, "")

    def test_client(self):
        c = core.HelperClient(demo_root=self.root, helper=HELPER)
        try:
            res, _ = c.call("hello")
            self.assertTrue(res["demo"])
            with self.assertRaises(core.HelperError):
                c.call("remove", key="nope")
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
