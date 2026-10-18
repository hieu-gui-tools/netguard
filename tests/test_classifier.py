from conftest import mkconn


def test_local_connection(env):
    c = mkconn(remote_ip="192.168.1.1")
    env.clf.classify(c)
    assert c.level == "LOCAL" and c.score == 0


def test_normal_system_app_is_trusted(env):
    c = mkconn()
    env.clf.classify(c)
    assert c.level == "TRUSTED"  # nằm trong Program Files, không có bằng chứng xấu


def test_double_extension_in_documents_is_dangerous(env):
    c = mkconn(process="telegram.pdf.exe", exe=r"C:\Users\x\Documents\telegram.pdf.exe")
    env.clf.classify(c)
    assert c.level == "DANGEROUS" and "doubleext" in c.tags and "userdir" in c.tags
    assert c.ip_score == 0 and c.proc_score >= 70


def test_threat_feed_ip_is_dangerous_and_ip_scored(env):
    env.feed.ips.add("185.220.101.9")
    c = mkconn(remote_ip="185.220.101.9")
    env.clf.classify(c)
    assert c.level == "DANGEROUS" and c.ip_score >= 90


def test_feed_cidr(env):
    import ipaddress
    env.feed.nets.append(ipaddress.ip_network("91.121.50.0/24"))
    c = mkconn(remote_ip="91.121.50.77")
    env.clf.classify(c)
    assert c.ip_score >= 90


def test_bad_port_alone_is_suspicious_not_dangerous(env):
    c = mkconn(process="x.exe", exe=r"D:\tools\x.exe", remote_port=4444)
    env.clf.classify(c)
    assert c.level == "SUSPICIOUS"


def test_lolbin_outbound(env):
    c = mkconn(process="powershell.exe", exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    env.clf.classify(c)
    assert c.level == "SUSPICIOUS" and c.proc_score >= 40


def test_allowlist_overrides_everything(env):
    env.feed.ips.add("185.220.101.9")
    env.allow.load([{"kind": "ip", "value": "185.220.101.9"}])
    c = mkconn(remote_ip="185.220.101.9")
    env.clf.classify(c)
    assert c.level == "TRUSTED" and c.score == 0


def test_valid_trusted_signature_reduces_userdir_risk(env):
    path = r"C:\Users\x\AppData\Local\Temp\UniKeyNT.exe"
    c = mkconn(process="UniKeyNT.exe", exe=path)
    env.sigs.table[path] = ("Valid", "CN=PHAM KIM LONG")
    env.clf.classify(c)
    assert c.level == "NORMAL"  # Temp (+30) rồi -10 vì chữ ký hợp lệ → dưới ngưỡng 30


def test_inbound_rdp_from_internet(env):
    c = mkconn(direction="in", local_port=3389, remote_ip="45.9.9.9", remote_port=51000)
    env.clf.classify(c)
    assert c.level == "SUSPICIOUS" and c.ip_score >= 45


def test_tampered_signature(env):
    path = r"D:\apps\evil.exe"
    c = mkconn(process="evil.exe", exe=path)
    env.sigs.table[path] = ("HashMismatch", "CN=Someone")
    env.clf.classify(c)
    assert c.level == "SUSPICIOUS" and c.proc_score >= 60


def test_listening_scope(env):
    lo = mkconn(direction="listen", local_ip="127.0.0.1", local_port=8000, remote_ip="", remote_port=0,
                process="python.exe", exe=r"D:\p\python.exe")
    env.clf.classify(lo)
    assert lo.level == "LOCAL"
    anyaddr = mkconn(direction="listen", local_ip="0.0.0.0", local_port=8000, remote_ip="", remote_port=0,
                     process="python.exe", exe=r"D:\p\python.exe")
    env.clf.classify(anyaddr)
    assert anyaddr.level == "NORMAL"  # mở ra toàn mạng → phải hiện, không được ẩn như nội bộ
