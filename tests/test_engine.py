import dataclasses
import time

from conftest import mkconn
from netguard.engine import Engine
from netguard.realtime import RtEvent, swap16


class FakeScanner:
    def __init__(self, conns=None):
        self.conns = conns or []
        self.listening = set()

    def scan(self):
        return [dataclasses.replace(c, reasons=[], tags=set()) for c in self.conns]


class FakeEtw:
    def __init__(self):
        self.pending, self.status, self.detail, self.started, self.stopped = [], "stopped", "", 0, 0

    def drain(self):
        out, self.pending = self.pending, []
        return out

    def start(self):
        self.started += 1
        self.status = "running"

    def stop(self):
        self.stopped += 1
        self.status = "stopped"


def ev(name="chrome.exe", exe=r"C:\Program Files\Google\Chrome\chrome.exe", rip="142.250.1.1", rport=443,
       lport=50000, kind="connect", pid=100, proto="TCP"):
    return RtEvent(time.time(), kind, proto, pid, "192.168.1.5", lport, rip, rport, name, exe)


def build(env):
    alerts, etw = [], FakeEtw()
    eng = Engine(env.guard, env.clf, FakeScanner(), env.storage, env.feed, etw, lambda lv, m: alerts.append((lv, m)))
    return eng, etw, alerts


def test_etw_event_blocks_malicious_program_with_no_scan_at_all(env):
    eng, etw, alerts = build(env)
    etw.pending.append(ev("telegram.pdf.exe", r"C:\Users\x\Documents\telegram.pdf.exe", "185.220.101.5"))
    assert eng.realtime_tick(time.time()) == 1       # chưa hề có lần quét nào
    assert any(n.startswith("NetGuard-APP-telegram.pdf.exe") for n in env.fw.list_rules())
    assert alerts and alerts[0][0] == "DANGEROUS"
    assert env.guard.is_blocked(mkconn(exe=r"C:\Users\x\Documents\telegram.pdf.exe"))


def test_etw_event_to_threat_feed_ip_blocks_ip_immediately(env):
    env.feed.ips.add("185.220.101.77")
    eng, etw, alerts = build(env)
    etw.pending.append(ev("evil.exe", r"D:\tools\evil.exe", "185.220.101.77"))
    eng.realtime_tick(time.time())
    assert "NetGuard-IP-185.220.101.77" in env.fw.list_rules()


def test_short_lived_connection_stays_visible_even_if_scan_missed_it(env):
    eng, etw, _ = build(env)
    t = time.time()
    etw.pending.append(ev())
    eng.realtime_tick(t)
    conns = eng.scan_tick(t + 1)                      # quét không thấy gì (kết nối đã đóng)
    assert len(conns) == 1 and conns[0].status == "ETW" and conns[0].remote_ip == "142.250.1.1"
    assert eng.scan_tick(t + 20) == []                # hết hạn sau RT_KEEP giây


def test_connection_seen_by_both_is_not_duplicated(env):
    eng, etw, _ = build(env)
    t = time.time()
    etw.pending.append(ev())
    eng.realtime_tick(t)
    eng.scanner = FakeScanner([mkconn(pid=100, remote_ip="142.250.1.1", remote_port=443, process="chrome.exe")])
    conns = eng.scan_tick(t + 1)
    assert len(conns) == 1 and conns[0].status == "ESTABLISHED"


def test_inbound_direction_uses_listening_ports(env):
    eng, etw, alerts = build(env)
    eng.scanner.listening = {3389}
    etw.pending.append(ev("svchost.exe", r"C:\Windows\System32\svchost.exe", "45.9.9.9", rport=51000, lport=3389,
                          kind="established"))
    eng.realtime_tick(time.time())
    c = list(eng._rt.values())[0][1]
    assert c.direction == "in" and c.level == "SUSPICIOUS" and c.ip_score >= 45


def test_same_event_alerts_and_logs_once(env):
    eng, etw, alerts = build(env)
    for _ in range(3):
        etw.pending.append(ev("x.exe", r"D:\tools\x.exe", "45.9.9.9", rport=4444))
        eng.realtime_tick(time.time())
    assert len(env.storage.recent_events()) == 1 and len(alerts) == 1


def test_port_byte_order_self_calibration(env):
    eng, etw, _ = build(env)
    assert not eng.swap_ports
    for i in range(1, 7):
        ip = f"93.184.216.{i}"
        etw.pending.append(ev(rip=ip, rport=swap16(443), lport=swap16(50000 + i)))   # ETW đưa cổng ngược byte
        eng.realtime_tick(time.time())
        eng.scanner = FakeScanner([mkconn(pid=100, remote_ip=ip, remote_port=443, local_port=50000 + i)])
        eng.scan_tick(time.time())
    assert eng.swap_ports
    etw.pending.append(ev(rip="93.184.216.99", rport=swap16(443), lport=swap16(55555)))
    eng.realtime_tick(time.time())
    c = [c for _, c in eng._rt.values() if c.remote_ip == "93.184.216.99"][0]
    assert c.remote_port == 443 and c.local_port == 55555


def test_correct_port_order_never_flips(env):
    eng, etw, _ = build(env)
    for i in range(1, 9):
        ip = f"93.184.216.{i}"
        etw.pending.append(ev(rip=ip, rport=443))
        eng.realtime_tick(time.time())
        eng.scanner = FakeScanner([mkconn(pid=100, remote_ip=ip, remote_port=443)])
        eng.scan_tick(time.time())
    assert not eng.swap_ports


def test_setting_controls_etw_lifecycle(env):
    eng, etw, _ = build(env)
    eng.refresh_config(time.time(), force=True)
    assert etw.started == 1 and etw.status == "running"
    env.guard.set_settings({"use_etw": False})
    eng.refresh_config(time.time(), force=True)
    assert etw.stopped == 1 and etw.status == "disabled"
    env.guard.set_settings({"use_etw": True})
    eng.refresh_config(time.time(), force=True)
    assert etw.started == 2


def test_loopback_events_ignored(env):
    eng, etw, _ = build(env)
    etw.pending.append(ev(rip="127.0.0.1"))
    assert eng.realtime_tick(time.time()) == 0
