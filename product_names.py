"""One name per product, however NVD or the CVE record spelled it.

The NVD CPE path title-cases vendor and product ("Openbsd OpenSSH", "Pcre2"), the CVE record
path keeps the CNA's spelling ("OpenBSD OpenSSH", "PCRE2"), and some CNAs include the vendor's
legal name ("Artifex Software Ghostscript") or a project suffix ("Libexpat Project Libexpat").
One product would then be grouped, routed and rule-matched as several. `canonical_product`
gives the vendor's own spelling for the known cases, and `unify_products` folds any remaining
spelling-only variants of a whole dataset onto one of them.

Scanner markup inside a product cell ("***PRIVILEGE CANNOT BE NONE...***") is dropped.
"""
from __future__ import annotations

import re
from functools import lru_cache

_JUNK = re.compile(r"\*{2,}.*?\*{2,}|<[^>]+>")
_SPACES = re.compile(r"\s+")

# (pattern over the cleaned, casefolded name; canonical name). Canonical names are the
# project's own spelling; fullmatch, so "Apache Tomcat" never matches "Apache".
PRODUCT_ALIASES: list[tuple[str, str]] = [
    (r"(artifex(\s+software)?\s+)?ghostscript", "Artifex Ghostscript"),
    (r"(the\s+)?gnu\s+c\s+library(\s+glibc)?|glibc", "glibc"),
    (r"(rsyncproject|samba)\s+rsync|rsync", "rsync"),
    (r"(libexpat\s+project\s+)?libexpat|expat", "libexpat"),
    (r"isc\s+bind(\s+9)?", "ISC BIND"),
    (r"(openbsd\s+)?openssh", "OpenBSD OpenSSH"),
    (r"(php\s+)?pcre2", "PCRE2"),
    (r"mariadb(\s+server)?", "MariaDB"),
    (r"ibm\s+(websphere\s+)?mq", "IBM MQ"),
    (r"zlib", "zlib"),
    (r"git(-scm\s+git)?", "Git"),
    (r"git[- ]for[- ]windows(\s+git)?|gitforwindows\s+git", "Git for Windows"),
    (r"fasterxml\s+jackson-databind", "FasterXML jackson-databind"),
    (r"nodejs\s+node(\.js)?|node\.js", "Node.js"),
    (r"erlang\s*/?\s*otp", "Erlang/OTP"),
    (r"7-zip", "7-Zip"),
    (r"apache\s+mina\s+sshd", "Apache MINA SSHD"),
    (r"oracle\s+database(\s+server)?", "Oracle Database Server"),
    (r"haxx\s+(lib)?curl|curl", "curl"),
    (r"(python\s+software\s+foundation\s+)?cpython|python", "Python"),
    (r"linux\s+kernel", "Linux Kernel"),
    (r"xmlsoft\s+libxml2|libxml2", "libxml2"),
    (r"xmlsoft\s+libxslt|libxslt", "libxslt"),
    (r"nlnetlabs\s+unbound|unbound", "Unbound"),
    (r"littlecms\s+little\s+cms|little\s+cms|lcms2", "Little CMS"),
    (r"gnu\s+tar", "GNU tar"),
    (r"gnu\s+gzip", "GNU gzip"),
    (r"gnu\s+patch", "GNU patch"),
    (r"gnu\s+emacs", "GNU Emacs"),
    (r"gnome\s+gconf|gconf", "GConf"),
    (r"freetype(2)?", "FreeType"),
    (r"openssl", "OpenSSL"),
    (r"sqlite", "SQLite"),
    (r"smuellerdd\s+libkcapi|libkcapi", "libkcapi"),
    (r"e2fsprogs(\s+project\s+e2fsprogs)?", "e2fsprogs"),
    (r"giflib(\s+project\s+giflib)?", "giflib"),
    (r"(the\s+tcpdump\s+group\s+)?libpcap", "libpcap"),
    (r"fossies\s+gawk|gnu\s+gawk|gawk", "GNU gawk"),
    (r"x\.org\s+x\s+server|xorg\s+x\s+server", "X.Org X Server"),
]
_ALIASES = [(re.compile(pattern, re.I), name) for pattern, name in PRODUCT_ALIASES]


def clean_product_name(name) -> str:
    """The product cell without scanner markup or stray escapes."""
    text = _JUNK.sub(" ", str(name or ""))
    text = text.replace("\\/", "/").rstrip("\\/ ")
    return _SPACES.sub(" ", text).strip()


def canonical_product(name) -> str:
    """The one spelling for this product (unchanged when it is not a known case)."""
    return _canonical(str(name or ""))


@lru_cache(maxsize=8192)
def _canonical(name: str) -> str:
    # A file repeats a few hundred product names over thousands of rows.
    text = clean_product_name(name)
    folded = text.casefold()
    for pattern, canonical in _ALIASES:
        if pattern.fullmatch(folded):
            return canonical
    return text


def _spelling_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def unify_products(names) -> dict[str, str]:
    """name -> canonical name for a whole dataset: known cases via canonical_product, then
    names that differ only in case or punctuation ("Zlib"/"zlib") fold onto the spelling
    with the most capitals (the one a CNA wrote, not the title-cased CPE)."""
    mapping = {name: canonical_product(name) for name in dict.fromkeys(names)}
    by_key: dict[str, list[str]] = {}
    for canonical in dict.fromkeys(mapping.values()):
        by_key.setdefault(_spelling_key(canonical), []).append(canonical)
    best = {key: max(variants, key=lambda v: (sum(c.isupper() for c in v), v))
            for key, variants in by_key.items()}
    return {name: best[_spelling_key(canonical)] for name, canonical in mapping.items()}
