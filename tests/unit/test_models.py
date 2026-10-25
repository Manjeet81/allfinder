from allfinder.core.models import (
    Finding,
    HttpInfo,
    Resolution,
    SourceKind,
    SourceStats,
    SourceStatus,
    Subdomain,
    Target,
)


def test_target_defaults_roots_and_apex() -> None:
    t = Target("example.com")
    assert t.roots == ("example.com",)
    assert t.depth == 0
    assert t.apex == "example.com"

    sub = Target("api.example.com", roots=("example.com", "example.org"), depth=1)
    assert sub.apex == "example.com"
    assert sub.parent is None


def test_finding_defaults() -> None:
    f = Finding("api.example.com", "crtsh")
    assert f.ips == []
    assert f.cname is None
    assert f.extra == {}
    assert f.ts is not None


def test_resolution_properties() -> None:
    r = Resolution("a.example.com")
    assert not r.resolved
    r.a.append("1.2.3.4")
    r.aaaa.append("::1")
    assert r.resolved
    assert r.ips == ["1.2.3.4", "::1"]
    c = Resolution("b.example.com", cname=["x.example.net"])
    assert c.resolved and c.ips == []


def test_subdomain_to_dict_and_alive() -> None:
    s = Subdomain("api.example.com", "example.com", sources={"otx", "crtsh"})
    assert not s.alive
    s.http = HttpInfo(url="https://api.example.com", status=200, title="Hi", tech=["nginx"])
    assert s.alive
    d = s.to_dict()
    assert d["hostname"] == "api.example.com"
    assert d["sources"] == ["crtsh", "otx"]
    assert d["http"]["status"] == 200
    assert d["http"]["tech"] == ["nginx"]
    assert isinstance(d["first_seen"], str)


def test_source_stats_dict() -> None:
    st = SourceStats("crtsh", status=SourceStatus.DONE, found=10, unique=3, duration=1.23456)
    d = st.to_dict()
    assert d == {
        "source": "crtsh",
        "status": "done",
        "found": 10,
        "unique": 3,
        "duration": 1.235,
        "error": None,
    }


def test_source_kind_values() -> None:
    assert SourceKind("passive") is SourceKind.PASSIVE
    assert SourceKind.ACTIVE.value == "active"
