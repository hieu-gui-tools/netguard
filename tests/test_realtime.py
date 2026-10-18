import os
import sys
import textwrap
import time

from netguard.realtime import EtwSource, parse_event, swap16


def wait_for(cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def script(tmp_path, body):
    p = tmp_path / "fake_child.py"
    p.write_text(textwrap.dedent(body))
    return [sys.executable, str(p)]


def test_swap16():
    assert swap16(443) == 47873 and swap16(swap16(12345)) == 12345


def test_parse_event_string_values():
    r = parse_event(12, {"PID": "4321", "daddr": "93.184.216.34", "saddr": "192.168.1.5", "dport": "443",
                         "sport": "50123", "size": "0"})
    assert r == {"id": 12, "kind": "connect", "proto": "TCP", "pid": 4321, "lip": "192.168.1.5",
                 "lport": 50123, "rip": "93.184.216.34", "rport": 443}


def test_parse_event_tolerates_case_ints_and_v6():
    r = parse_event(31, {"pid": 7, "DADDR": "2606:4700::6810:84e5", "SADDR": "fe80::1", "DPORT": 443, "SPORT": 50000})
    assert r["rip"] == "2606:4700::6810:84e5" and r["proto"] == "TCP" and r["kind"] == "established"
    # IPv4 dạng số nguyên thô (nếu manifest không khai báo kiểu IPv4): 34.216.184.93 theo thứ tự mạng
    r = parse_event(12, {"PID": 1, "daddr": 0x5DB8D822, "saddr": 0x0501A8C0, "dport": 80, "sport": 1})
    assert r["rip"] == "34.216.184.93" and r["lip"] == "192.168.1.5"


def test_parse_event_uses_header_pid_and_rejects_bad():
    r = parse_event(42, {"EventHeader": {"ProcessId": 99}, "daddr": "9.9.9.9", "saddr": "10.0.0.2",
                         "dport": 53, "sport": 5000})
    assert r["pid"] == 99 and r["proto"] == "UDP"
    assert parse_event(12, {"PID": 1}) is None        # thiếu trường
    assert parse_event(10, {"PID": 1}) is None        # sự kiện dữ liệu từng gói: không quan tâm


def test_child_protocol_ready_events_dedupe_and_stop(tmp_path):
    cmd = script(tmp_path, """
        import json, sys
        print(json.dumps({"status": "ready", "kernel_filter": True}), flush=True)
        ev = {"id": 12, "kind": "connect", "proto": "TCP", "pid": %d, "lip": "10.0.0.2", "lport": 5000,
              "rip": "93.184.216.34", "rport": 443}
        print(json.dumps(ev), flush=True)
        print(json.dumps(dict(ev, id=15, kind="established")), flush=True)   # trùng → bị khử
        print(json.dumps({"id": 10}), flush=True)                            # sự kiện ngoài danh sách
        print("dòng rác không phải JSON", flush=True)
        sys.stdin.read()
    """ % os.getpid())
    src = EtwSource(child_cmd=cmd, platform_ok=True)
    assert src.start()
    assert wait_for(lambda: src.status == "running" and src.total >= 1)
    time.sleep(0.3)
    evs = src.drain()
    assert len(evs) == 1 and evs[0].rip == "93.184.216.34" and evs[0].name != "?"
    assert src.kernel_filter and src.counts[10] == 1
    t0 = time.time()
    src.stop()
    assert time.time() - t0 < 5 and src.status == "stopped"


def test_child_needs_admin_is_final(tmp_path):
    cmd = script(tmp_path, """
        import json, sys
        print(json.dumps({"status": "error", "code": 5, "msg": "Access is denied"}), flush=True)
        sys.exit(4)
    """)
    src = EtwSource(child_cmd=cmd, platform_ok=True)
    src.restart_delay = 0.05
    src.start()
    assert wait_for(lambda: src.status == "needs-admin")
    time.sleep(0.5)
    assert src.status == "needs-admin" and src.restarts == 0  # không thử lại vô ích
    src.stop()
    assert src.status == "needs-admin"


def test_child_missing_lib(tmp_path):
    cmd = script(tmp_path, """
        import json, sys
        print(json.dumps({"status": "error", "kind": "missing-lib", "msg": "no etw"}), flush=True)
        sys.exit(3)
    """)
    src = EtwSource(child_cmd=cmd, platform_ok=True)
    src.start()
    assert wait_for(lambda: src.status == "missing-lib")
    src.stop()


def test_child_crash_restarts_then_gives_up(tmp_path):
    cmd = script(tmp_path, "import sys; print('boom'); sys.exit(1)")
    src = EtwSource(child_cmd=cmd, platform_ok=True)
    src.restart_delay = 0.05
    src.start()
    assert wait_for(lambda: src.restarts == 3 and src.status == "error", 10)
    time.sleep(0.5)
    assert src.restarts == 3          # dừng ở 3 lần, không lặp vô hạn
    assert "boom" in src.detail
    src.stop()


def test_cpu_watchdog_kills_runaway_child(tmp_path):
    cmd = script(tmp_path, """
        import json, sys
        print(json.dumps({"status": "ready", "kernel_filter": False}), flush=True)
        while True:
            pass
    """)
    src = EtwSource(child_cmd=cmd, platform_ok=True)
    src.cpu_limit, src.watch_interval = 20.0, 0.3
    src.start()
    assert wait_for(lambda: src.status == "overload", 10)
    src.stop()
    assert src.status == "overload"


def test_unsupported_platform():
    src = EtwSource(platform_ok=False)
    assert src.start() is False and src.status == "unsupported"
