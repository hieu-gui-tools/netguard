import json

import pytest

from conftest import mkconn
from netguard.guard import GuardError
from netguard.storage import Storage


def names(env):
    return env.fw.list_rules()


def test_block_unblock_and_journal(env):
    bid = env.guard.block_ip("185.220.101.9", "test")
    assert "NetGuard-IP-185.220.101.9" in names(env)
    assert env.guard.is_blocked(mkconn(remote_ip="185.220.101.9"))
    env.guard.unblock(bid)
    assert not names(env) and not env.guard.is_blocked(mkconn(remote_ip="185.220.101.9"))
    actions = [r["action"] for r in env.storage.list_journal()]
    assert actions[:2] == ["unblock", "block_ip"]


def test_block_is_idempotent(env):
    a = env.guard.block_ip("185.220.101.9")
    b = env.guard.block_ip("185.220.101.9")
    assert a == b and len(env.storage.list_blocks()) == 1


def test_undo_block_and_undo_unblock(env):
    bid = env.guard.block_ip("185.220.101.9")
    block_entry = env.storage.list_journal()[0]
    env.guard.undo(block_entry["id"])
    assert not names(env)
    with pytest.raises(GuardError):
        env.guard.undo(block_entry["id"])  # không hoàn tác hai lần
    env.guard.unblock(env.storage.list_blocks(False)[0]["id"]) if names(env) else None
    # bỏ chặn rồi hoàn tác việc bỏ chặn → chặn trở lại
    env.guard.block_ip("91.121.50.1")
    b = env.storage.get_block_by_name("NetGuard-IP-91.121.50.1")
    env.guard.unblock(b["id"])
    unblock_entry = env.storage.list_journal()[0]
    env.guard.undo(unblock_entry["id"])
    assert "NetGuard-IP-91.121.50.1" in names(env)


def test_undo_settings_and_allowlist(env):
    env.guard.set_settings({"block_threshold": 90})
    assert env.guard.setting("block_threshold") == 90
    env.guard.undo(env.storage.list_journal()[0]["id"])
    assert env.guard.setting("block_threshold") == 70
    env.guard.allow_add("process", "foo.exe", "ok")
    assert len(env.storage.list_allow()) == 1
    env.guard.undo(env.storage.list_journal()[0]["id"])
    assert len(env.storage.list_allow()) == 0


def test_refuse_loopback_private_auto_and_protected(env):
    with pytest.raises(GuardError):
        env.guard.block_ip("127.0.0.1")
    with pytest.raises(GuardError):
        env.guard.block_ip("not-an-ip")
    with pytest.raises(GuardError):
        env.guard.block_ip("192.168.1.10", source="auto")
    with pytest.raises(GuardError):
        env.guard.block_ip("8.8.8.8", source="auto")
    env.guard.block_ip("192.168.1.10")  # thủ công thì cho phép
    with pytest.raises(GuardError):
        env.guard.block_program(r"C:\Windows\System32\svchost.exe", source="auto")


def test_auto_block_prefers_ip_then_program(env):
    c = mkconn(remote_ip="185.220.101.9", ip_score=90, score=90)
    assert "Đã chặn IP" in env.guard.auto_block(c)
    c2 = mkconn(process="a.pdf.exe", exe=r"C:\Users\x\Documents\a.pdf.exe", ip_score=0, proc_score=80,
                score=80, tags={"userdir", "doubleext"})
    assert "Đã chặn chương trình" in env.guard.auto_block(c2)
    c3 = mkconn(ip_score=0, proc_score=80, score=80)  # không có bằng chứng IP, không ở thư mục người dùng
    assert env.guard.auto_block(c3) is None


def test_auto_block_disabled_and_circuit_breaker(env):
    env.guard.set_settings({"auto_block": False})
    assert env.guard.auto_block(mkconn(remote_ip="185.220.101.9", ip_score=90)) is None
    env.guard.set_settings({"auto_block": True, "max_auto_blocks_per_min": 3})
    results = [env.guard.auto_block(mkconn(remote_ip=f"185.220.101.{i}", ip_score=90)) for i in range(1, 7)]
    assert sum(1 for r in results if r) == 3
    assert env.guard.breaker_until > 0
    assert any(r["action"] == "breaker" for r in env.storage.list_journal())


def test_reconcile_heals_missing_rule(env):
    env.guard.block_ip("185.220.101.9")
    env.fw.delete_rule("NetGuard-IP-185.220.101.9")  # ai đó xóa rule thủ công
    env.fw.add_block_ip("NetGuard-IP-9.9.9.200", "9.9.9.200")  # rule mồ côi
    rep = env.guard.reconcile(fix=True)
    assert rep["missing"] == ["NetGuard-IP-185.220.101.9"] and rep["orphans"] == ["NetGuard-IP-9.9.9.200"]
    assert "NetGuard-IP-185.220.101.9" in names(env)
    assert "NetGuard-IP-9.9.9.200" in names(env)  # mặc định không xóa rule lạ
    env.guard.reconcile(fix=True, remove_orphans=True)
    assert "NetGuard-IP-9.9.9.200" not in names(env)


def test_snapshot_restore_roundtrip(env):
    env.guard.block_ip("185.220.101.1", "a")
    env.guard.block_ip("185.220.101.2", "b")
    env.guard.allow_add("process", "keep.exe")
    snap = env.guard.snapshot_now("mốc an toàn")
    # "sự cố": thêm bậy, gỡ mất, đổi cài đặt, xóa allowlist
    env.guard.block_ip("185.220.101.3", "bậy")
    env.guard.unblock(env.storage.get_block_by_name("NetGuard-IP-185.220.101.1")["id"])
    env.guard.set_settings({"block_threshold": 55})
    env.guard.allow_remove(env.storage.list_allow()[0]["id"])
    res = env.guard.restore_snapshot(snap)
    assert not res["errors"]
    assert names(env) == {"NetGuard-IP-185.220.101.1", "NetGuard-IP-185.220.101.2"}
    assert {r["target"] for r in env.storage.list_blocks()} == {"185.220.101.1", "185.220.101.2"}
    assert env.guard.setting("block_threshold") == 70
    assert [r["value"] for r in env.storage.list_allow()] == ["keep.exe"]
    assert any(i["kind"] == "pre-restore" for i in env.guard.snapshots.list())  # luôn có đường lui


def test_restore_rejects_bad_snapshot(env):
    bad = env.tmp / "bad.json"
    bad.write_text("{not json")
    from netguard.snapshots import SnapshotError
    with pytest.raises(SnapshotError):
        env.guard.restore_snapshot(bad)
    bad.write_text(json.dumps({"format": 99}))
    with pytest.raises(SnapshotError):
        env.guard.restore_snapshot(bad)


def test_emergency_clear(env):
    env.guard.block_ip("185.220.101.1")
    env.guard.block_program(r"C:\Users\x\Documents\bad.exe")
    n = env.guard.emergency_clear()
    assert n == 2 and not names(env) and not env.storage.list_blocks()
    assert env.guard.setting("auto_block") is False
    # và vẫn khôi phục được bằng bản sao lưu pre-restore
    pre = [i for i in env.guard.snapshots.list() if i["kind"] == "pre-restore"][0]
    env.guard.restore_snapshot(pre["path"])
    assert len(names(env)) == 2


def test_snapshot_prune_keeps_manual(env):
    env.guard.snapshot_now("thủ công", "manual")
    for i in range(6):
        env.guard.snapshots.create(f"auto {i}", "auto", keep=3)
    kinds = [i["kind"] for i in env.guard.snapshots.list()]
    assert kinds.count("auto") == 3 and kinds.count("manual") == 1


def test_corrupt_database_recovers(tmp_path):
    p = tmp_path / "bad.db"
    p.write_bytes(b"this is definitely not a sqlite database" * 100)
    s = Storage(p)
    assert s.recovered
    s.add_journal("t", "x", "y", "z", None)
    assert len(s.list_journal()) == 1
    assert list(tmp_path.glob("bad.db.corrupt-*"))  # file hỏng được giữ lại để kiểm tra
