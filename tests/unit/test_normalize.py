import pytest

from allfinder.core.normalize import (
    Scope,
    depth_below,
    extract_hostnames,
    in_scope,
    labels_below,
    normalize_hostname,
    normalize_many,
    parents,
    split_names,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # plain
        ("example.com", "example.com"),
        ("api.example.com", "api.example.com"),
        ("API.Example.COM", "api.example.com"),
        ("  api.example.com  ", "api.example.com"),
        ("﻿api.example.com", "api.example.com"),
        # dots / wildcards
        ("api.example.com.", "api.example.com"),
        (".api.example.com", "api.example.com"),
        ("*.example.com", "example.com"),
        ("*.*.example.com", "example.com"),
        ("*.api.example.com", "api.example.com"),
        ("*example.com", "example.com"),
        ("api..example.com", "api.example.com"),
        # urls
        ("https://api.example.com", "api.example.com"),
        ("http://api.example.com/", "api.example.com"),
        ("HTTPS://API.EXAMPLE.COM/path?x=1#frag", "api.example.com"),
        ("//cdn.example.com/a.js", "cdn.example.com"),
        ("api.example.com/path", "api.example.com"),
        ("api.example.com:8443", "api.example.com"),
        ("https://api.example.com:443/", "api.example.com"),
        ("https://user:pw@dev.example.com:8443/x", "dev.example.com"),
        ("ftp://files.example.com", "files.example.com"),
        ("api.example.com?x=1", "api.example.com"),
        ("api.example.com#x", "api.example.com"),
        ("api.example.com\\path", "api.example.com"),
        # escaped / encoded
        ("api\\.example\\.com", "api.example.com"),
        ("api%2Eexample%2Ecom", "api.example.com"),
        # whitespace inside (copy-paste artefacts)
        ("api .example.com", "api.example.com"),
        # underscores (real DNS names)
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("_sip._tcp.example.com", "_sip._tcp.example.com"),
        # idna
        ("bücher.example.com", "xn--bcher-kva.example.com"),
        ("xn--bcher-kva.example.com", "xn--bcher-kva.example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        # digits in labels are fine
        ("1.api.example.com", "1.api.example.com"),
        ("web01.example.com", "web01.example.com"),
        ("a-b.example.com", "a-b.example.com"),
    ],
)
def test_normalize_valid(raw: str, expected: str) -> None:
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        ".",
        "*",
        "*.",
        "..",
        "localhost",  # single label rejected by default
        "example",
        "1.2.3.4",
        "192.168.0.1",
        "::1",
        "[::1]",
        "[2001:db8::1]:443",
        "admin@example.com",
        "foo.*.example.com",
        "-api.example.com",
        "api-.example.com",
        "api.example.com-",
        "api.exam ple.com_",  # trailing underscore allowed? label 'com_' -> yes valid; keep
        "a" * 64 + ".example.com",
        ".".join(["a" * 60] * 5) + ".com",  # > 253 chars
        "api.example.c om!",
        "ex ample.com!",
        "$ub.example.com",
        "sub.example.com@",
        "example.123",
    ],
)
def test_normalize_invalid(raw: str | None) -> None:
    # a few of the items above are intentionally edge-cases; make sure the
    # ones that must be rejected are rejected.
    result = normalize_hostname(raw)
    if raw == "api.exam ple.com_":
        # whitespace stripped -> 'api.example.com_' : '_' is allowed at the end
        assert result == "api.example.com_"
        return
    assert result is None, (raw, result)


def test_single_label_opt_in() -> None:
    assert normalize_hostname("localhost") is None
    assert normalize_hostname("localhost", allow_single_label=True) == "localhost"
    assert normalize_hostname("com", allow_single_label=True) == "com"


def test_split_names_crtsh_style() -> None:
    blob = "*.example.com\nwww.example.com\napi.example.com, mail.example.com"
    assert split_names(blob) == [
        "*.example.com",
        "www.example.com",
        "api.example.com",
        "mail.example.com",
    ]
    assert split_names("") == []


def test_normalize_many_dedups_and_splits() -> None:
    out = normalize_many(
        [
            "*.example.com\nWWW.example.com",
            "www.example.com.",
            None,
            "bad name!",
            "https://api.example.com/x",
            "1.2.3.4",
        ]
    )
    assert out == {"example.com", "www.example.com", "api.example.com"}


# --------------------------------------------------------------------------- scope


def test_in_scope() -> None:
    assert in_scope("example.com", "example.com")
    assert in_scope("a.b.example.com", "example.com")
    assert not in_scope("notexample.com", "example.com")
    assert not in_scope("example.com.evil.net", "example.com")
    assert not in_scope("example.org", "example.com")


def test_scope_multi_root() -> None:
    s = Scope(["Example.com", "example.co.uk", "sub.example.com"])
    assert set(s.roots) == {"example.com", "example.co.uk", "sub.example.com"}
    assert "api.example.com" in s
    assert "api.example.co.uk" in s
    assert "example.net" not in s
    assert 42 not in s  # type: ignore[comparison-overlap]
    # longest root wins for root_for
    assert s.root_for("x.sub.example.com") == "sub.example.com"
    assert s.root_for("x.example.com") == "example.com"
    assert s.root_for("evil.net") is None
    assert s.filter(["a.example.com", "b.evil.net"]) == {"a.example.com"}
    assert len(s) == 3
    assert "Scope(" in repr(s)


def test_scope_rejects_bad_roots() -> None:
    with pytest.raises(ValueError):
        Scope(["not a domain!"])
    with pytest.raises(ValueError):
        Scope([])


def test_labels_parents_depth() -> None:
    assert labels_below("example.com", "example.com") == []
    assert labels_below("a.b.example.com", "example.com") == ["a", "b"]
    assert parents("a.b.c.example.com", "example.com") == [
        "b.c.example.com",
        "c.example.com",
        "example.com",
    ]
    assert parents("api.example.com", "example.com") == ["example.com"]
    assert parents("example.com", "example.com") == ["example.com"]
    assert depth_below("api.example.com", "example.com") == 1
    assert depth_below("v1.api.example.com", "example.com") == 2
    with pytest.raises(ValueError):
        labels_below("evil.net", "example.com")


# --------------------------------------------------------------------------- extraction


def test_extract_from_html_js_json() -> None:
    text = """
    <a href="https://www.example.com/x">x</a>
    <script src="//cdn.Example.com/app.js"></script>
    var api = "api\\.example\\.com";
    fetch("https://v2\\u002eapi.example.com/graphql")
    {"host": "internal.example.com:8080", "other": "example.org"}
    mail@user.example.com  (this is a mail address; host still extracted)
    not-example.com  notexample.com  example.com.evil.net
    http%3A%2F%2Fenc%2Eexample%2Ecom
    """
    found = extract_hostnames(text, ["example.com"])
    assert found == {
        "www.example.com",
        "cdn.example.com",
        "api.example.com",
        "v2.api.example.com",
        "internal.example.com",
        "user.example.com",
        "enc.example.com",
    }


def test_extract_multi_root_and_bare_root() -> None:
    text = "see example.com and app.example.org but not fooexample.com"
    found = extract_hostnames(text, ["example.com", "example.org"])
    assert found == {"example.com", "app.example.org"}


def test_extract_empty() -> None:
    assert extract_hostnames("", ["example.com"]) == set()
