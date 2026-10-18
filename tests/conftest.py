import pytest

from netguard.classifier import AllowList, Classifier
from netguard.feed import ThreatFeed
from netguard.firewall import DryRunFirewall
from netguard.guard import Guard
from netguard.models import Connection
from netguard.storage import Storage


class FakeSigs:
    def __init__(self, table=None):
        self.table = table or {}

    def lookup(self, path):
        return self.table.get(path)


@pytest.fixture
def env(tmp_path):
    storage = Storage(tmp_path / "t.db")
    fw = DryRunFirewall()
    guard = Guard(storage, fw, tmp_path / "backups")
    feed = ThreatFeed(tmp_path / "feed.txt")
    allow = AllowList()
    sigs = FakeSigs()
    clf = Classifier(allow, feed, sigs, 70)
    return type("Env", (), dict(storage=storage, fw=fw, guard=guard, feed=feed, allow=allow,
                                 sigs=sigs, clf=clf, tmp=tmp_path))


def mkconn(**kw):
    d = dict(pid=100, process="app.exe", exe=r"C:\Program Files\App\app.exe", proto="TCP",
             local_ip="192.168.1.5", local_port=50000, remote_ip="93.184.216.34", remote_port=443,
             status="ESTABLISHED", direction="out")
    d.update(kw)
    return Connection(**d)
