from netguard.feed import ThreatFeed, parse_feed


def test_parse_feed_mixed_formats():
    text = "# comment\n1.2.3.4\n5.6.7.0/24 ; SBL123\n\nnot-an-ip\n9.9.9.9 # trailing\n"
    ips, nets = parse_feed(text)
    assert ips == {"1.2.3.4", "9.9.9.9"} and [str(n) for n in nets] == ["5.6.7.0/24"]


def test_feed_contains_and_failed_update_keeps_old(tmp_path, monkeypatch):
    f = ThreatFeed(tmp_path / "f.txt")
    (tmp_path / "f.txt").write_text("1.2.3.4\n10.0.0.0/8\n")
    f.load()
    assert f.contains("1.2.3.4") and f.contains("10.5.5.5") and not f.contains("8.8.8.8")
    res = f.update(["http://127.0.0.1:9/none"], timeout=1)  # cổng đóng → lỗi
    assert list(res.values())[0].startswith("Lỗi")
    assert f.contains("1.2.3.4")  # dữ liệu cũ còn nguyên
