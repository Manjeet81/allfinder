from datetime import UTC, datetime, timedelta
from pathlib import Path

from allfinder.core.models import Finding, HttpInfo, Resolution, SourceStats, SourceStatus
from allfinder.core.store import Store


def test_add_finding_dedup_and_sources() -> None:
    with Store() as st:
        run = st.start_run(["example.com"], args={"x": 1}, version="t")
        assert st.run is run
        f1 = Finding("api.example.com", "crtsh")
        f2 = Finding("api.example.com", "otx", ips=["1.2.3.4"])
        f3 = Finding("API.example.com", "otx")  # not normalized on purpose -> distinct key
        assert st.add_finding(f1, root="example.com") is True
        assert st.add_finding(f2, root="example.com") is False
        assert st.add_finding(f2, root="example.com") is False
        assert st.add_finding(f3, root="example.com") is True
        sub = st.get("api.example.com")
        assert sub is not None
        assert sub.sources == {"crtsh", "otx"}
        assert sub.ips == ["1.2.3.4"]
        assert len(st) == 2
        assert "api.example.com" in st
        assert st.seen_this_run("api.example.com")
        assert st.hostnames() == ["API.example.com", "api.example.com"]
        assert st.counts()["total"] == 2


def test_out_of_scope_and_related() -> None:
    with Store() as st:
        st.start_run(["example.com"])
        st.add_finding(Finding("a.example.com", "x"), root="example.com")
        st.add_finding(Finding("other.net", "x"), root="example.com", in_scope=False)
        assert st.hostnames() == ["a.example.com"]
        assert st.related_domains() == ["other.net"]
        assert st.counts()["related"] == 1


def test_updates_and_persistence(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    with Store(db) as st:
        run = st.start_run(["example.com"])
        st.add_finding(Finding("a.example.com", "x"), root="example.com")
        st.add_finding(Finding("w.example.com", "x"), root="example.com")
        st.update_resolution(Resolution("a.example.com", a=["1.1.1.1"], cname=["c.example.net"]))
        st.update_resolution(Resolution("w.example.com", a=["9.9.9.9"], wildcard=True))
        st.update_http(
            "a.example.com", HttpInfo(url="https://a.example.com", status=200, title="t")
        )
        st.update_takeover("a.example.com", {"service": "github", "vulnerable": True})
        st.update_asn("a.example.com", "AS13335", "Cloudflare")
        st.update_resolution(Resolution("missing.example.com", a=["1.1.1.1"]))  # ignored
        st.save_stats(SourceStats("x", status=SourceStatus.DONE, found=2, unique=2, duration=0.5))
        st.finish_run()
        assert st.counts() == {
            "total": 2,
            "resolved": 1,
            "wildcard": 1,
            "alive": 1,
            "related": 0,
            "new_this_run": 2,
        }
        run_id = run.id

    with Store(db) as st2:
        assert st2.load(["example.com"]) == 2
        sub = st2.get("a.example.com")
        assert sub is not None
        assert sub.resolved and sub.ips == ["1.1.1.1"] and sub.cname == "c.example.net"
        assert sub.http is not None and sub.http.status == 200
        assert sub.takeover == {"service": "github", "vulnerable": True}
        assert sub.asn == "AS13335" and sub.org == "Cloudflare"
        assert sub.sources == {"x"}
        w = st2.get("w.example.com")
        assert w is not None and w.wildcard and not w.resolved
        runs = st2.runs("example.com")
        assert [r.id for r in runs] == [run_id]
        assert runs[0].finished_at is not None
        assert st2.runs("nope.com") == []
        assert st2.get_run(run_id) is not None
        stats = st2.stats(run_id)
        assert len(stats) == 1 and stats[0].source == "x" and stats[0].status is SourceStatus.DONE
        assert st2.first_seen_in_run(run_id) == ["a.example.com", "w.example.com"]


def test_keep_wildcards_flag() -> None:
    with Store() as st:
        st.start_run(["example.com"])
        st.add_finding(Finding("w.example.com", "x"), root="example.com")
        st.update_resolution(
            Resolution("w.example.com", a=["9.9.9.9"], wildcard=True), keep_wildcards=True
        )
        w = st.get("w.example.com")
        assert w is not None and w.wildcard and w.resolved


def test_new_since_and_multiple_runs(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    with Store(db) as st:
        r1 = st.start_run(["example.com"])
        st.add_finding(Finding("old.example.com", "x"), root="example.com")
        st.finish_run()
    with Store(db) as st:
        r2 = st.start_run(["example.com"])
        # make the new finding clearly later than r1.started_at
        f = Finding("new.example.com", "y", ts=datetime.now(UTC) + timedelta(seconds=1))
        assert st.add_finding(f, root="example.com") is True
        assert st.add_finding(Finding("old.example.com", "y"), root="example.com") is False
        assert st.new_since(r1.id) == ["new.example.com"]
        assert st.first_seen_in_run(r2.id) == ["new.example.com"]
        assert st.subdomains(this_run_only=True) and len(st.subdomains(this_run_only=True)) == 2
        assert st.counts()["new_this_run"] == 2
        assert st.get("old.example.com").sources == {"x", "y"}  # type: ignore[union-attr]


def test_flush_batches(tmp_path: Path) -> None:
    with Store(tmp_path / "b.db") as st:
        st.start_run(["example.com"])
        for i in range(600):
            st.add_finding(Finding(f"h{i}.example.com", "x"), root="example.com")
        st.flush()
        assert len(st.hostnames()) == 600
