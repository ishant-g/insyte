"""Public-suffix resolution for deriving the registrable domain (eTLD+1).

Scope and honesty about it: this is a curated subset of the Mozilla Public
Suffix List, not the whole thing. It carries the multi-label ICANN suffixes
that appear in practice plus the private suffixes that matter for exposure
work (cloud and PaaS hostnames, where treating `foo.s3.amazonaws.com` as a
subdomain of `amazonaws.com` would badly mis-scope a scan).

Anything not listed falls back to "the last label is the suffix", which is
correct for every single-label TLD. The consequence of a miss on an unlisted
two-label ccTLD is a registrable domain that is one label too short; it never
crashes and never silently widens scope, because scope checks elsewhere use
whole-label comparisons against the target, not the registrable domain.

Rule syntax follows the PSL:
    "co.uk"      exact suffix
    "*.ck"       any single label under .ck is a suffix
    "!www.ck"    exception: www.ck is registrable, not a suffix
"""

from __future__ import annotations

from functools import lru_cache

_ICANN_SUFFIXES: frozenset[str] = frozenset(
    ["ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk", "police.uk", "sch.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au", "csiro.au", "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "gen.nz", "kiwi.nz", "maori.nz", "school.nz", "co.za", "net.za", "org.za", "web.za", "gov.za", "ac.za", "edu.za", "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br", "eco.br", "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar", "int.ar", "mil.ar", "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx", "com.co", "net.co", "org.co", "gov.co", "edu.co", "nom.co", "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe", "nom.pe", "com.ve", "net.ve", "org.ve", "web.ve", "gob.ve", "edu.ve", "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk", "fam.pk", "biz.pk", "web.pk", "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd", "com.lk", "net.lk", "org.lk", "gov.lk", "edu.lk", "sch.lk", "ac.lk", "com.np", "net.np", "org.np", "gov.np", "edu.np", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn", "ah.cn", "bj.cn", "sh.cn", "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk", "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw", "game.tw", "ebiz.tw", "club.tw", "co.jp", "ne.jp", "or.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp", "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr", "ac.kr", "hs.kr", "ms.kr", "es.kr", "sc.kr", "kg.kr", "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg", "com.my", "net.my", "org.my", "gov.my", "edu.my", "mil.my", "name.my", "co.th", "in.th", "ac.th", "go.th", "mi.th", "net.th", "or.th", "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph", "ngo.ph", "mil.ph", "i.ph", "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn", "ac.vn", "biz.vn", "info.vn", "name.vn", "pro.vn", "co.id", "net.id", "or.id", "web.id", "sch.id", "ac.id", "go.id", "mil.id", "my.id", "biz.id", "desa.id", "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr", "pol.tr", "mil.tr", "k12.tr", "av.tr", "dr.tr", "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "sch.sa", "med.sa", "pub.sa", "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg", "sci.eg", "mil.eg", "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng", "sch.ng", "com.gh", "com.ke", "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke", "sc.ke", "me.ke", "mobi.ke", "info.ke", "co.tz", "ac.tz", "go.tz", "ne.tz", "or.tz", "hotel.tz", "co.ug", "ac.ug", "sc.ug", "go.ug", "ne.ug", "or.ug", "com.et", "net.et", "org.et", "gov.et", "edu.et", "biz.et", "name.et", "info.et", "co.il", "net.il", "org.il", "ac.il", "gov.il", "k12.il", "muni.il", "idf.il", "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "edu.ru", "gov.ru", "int.ru", "mil.ru", "ac.ru", "com.ua", "net.ua", "org.ua", "in.ua", "edu.ua", "gov.ua", "kiev.ua", "co.ua", "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "biz.pl", "info.pl", "waw.pl", "gda.pl", "krakow.pl", "co.hu", "info.hu", "org.hu", "priv.hu", "sport.hu", "tm.hu", "com.ro", "org.ro", "tm.ro", "nt.ro", "nom.ro", "info.ro", "rec.ro", "arts.ro", "firm.ro", "store.ro", "www.ro", "com.hr", "from.hr", "iz.hr", "name.hr", "com.gr", "net.gr", "org.gr", "edu.gr", "gov.gr", "com.cy", "net.cy", "org.cy", "gov.cy", "ac.cy", "com.pt", "org.pt", "edu.pt", "gov.pt", "int.pt", "nome.pt", "publ.pt", "com.es", "org.es", "nom.es", "gob.es", "edu.es", "com.it", "edu.it", "gov.it", "co.at", "or.at", "ac.at", "gv.at", "priv.at", "co.ch", "com.ch", "net.ch", "org.ch", "com.de", "com.se", "org.se", "pp.se", "tm.se", "press.se", "com.no", "priv.no", "vgs.no", "fhs.no", "folkebibl.no", "co.dk", "com.ee", "pri.ee", "fie.ee", "med.ee", "aip.ee", "org.ee", "com.lv", "net.lv", "org.lv", "edu.lv", "gov.lv", "asn.lv", "id.lv", "conf.lv", "com.lt", "net.lt", "org.lt", "gov.lt", "com.by", "net.by", "of.by", "com.ge", "net.ge", "org.ge", "pvt.ge", "edu.ge", "gov.ge", "com.kz", "net.kz", "org.kz", "edu.kz", "gov.kz", "mil.kz", "com.uz", "net.uz", "org.uz", "co.uz", "com.af", "net.af", "org.af", "gov.af", "edu.af", "com.iq", "net.iq", "org.iq", "gov.iq", "edu.iq", "com.jo", "net.jo", "org.jo", "gov.jo", "edu.jo", "sch.jo", "mil.jo", "com.kw", "net.kw", "org.kw", "gov.kw", "edu.kw", "com.lb", "net.lb", "org.lb", "gov.lb", "edu.lb", "com.om", "net.om", "org.om", "gov.om", "ac.om", "med.om", "pro.om", "com.qa", "net.qa", "org.qa", "gov.qa", "edu.qa", "sch.qa", "mil.qa", "com.bh", "net.bh", "org.bh", "gov.bh", "edu.bh", "com.ec", "net.ec", "org.ec", "gob.ec", "fin.ec", "med.ec", "pro.ec", "edu.ec", "info.ec", "com.uy", "net.uy", "org.uy", "gub.uy", "edu.uy", "mil.uy", "com.py", "net.py", "org.py", "gov.py", "edu.py", "com.bo", "net.bo", "org.bo", "gob.bo", "tv.bo", "mil.bo", "int.bo", "com.gt", "net.gt", "org.gt", "gob.gt", "ind.gt", "edu.gt", "mil.gt", "com.sv", "org.sv", "gob.sv", "edu.sv", "red.sv", "com.ni", "net.ni", "org.ni", "gob.ni", "co.ni", "edu.ni", "com.cr", "co.cr", "ac.cr", "ed.cr", "fi.cr", "go.cr", "or.cr", "sa.cr", "com.pa", "net.pa", "org.pa", "sld.pa", "edu.pa", "gob.pa", "ac.pa", "com.do", "net.do", "org.do", "gob.do", "web.do", "art.do", "sld.do", "edu.do", "com.cu", "net.cu", "org.cu", "inf.cu", "com.jm", "net.jm", "org.jm", "gov.jm", "edu.jm", "com.tt", "co.tt", "net.tt", "org.tt", "gov.tt", "edu.tt", "com.bs", "net.bs", "org.bs", "com.bz", "net.bz", "org.bz", "edu.bz", "gov.bz", "com.ci", "co.ci", "ed.ci", "org.ci", "int.ci", "com.sn", "art.sn", "univ.sn", "gouv.sn", "org.sn", "perso.sn", "com.cm", "co.cm", "net.cm", "gov.cm", "com.zm", "ac.zm", "co.zm", "org.zm", "sch.zm", "gov.zm", "com.zw", "co.zw", "org.zw", "gov.zw", "ac.zw", "com.mt", "net.mt", "org.mt", "edu.mt", "gov.mt", "com.is", "net.is", "org.is", "edu.is", "gov.is", "int.is", "com.mk", "net.mk", "org.mk", "gov.mk", "edu.mk", "inf.mk", "com.al", "net.al", "org.al", "edu.al", "gov.al", "mil.al", "com.ba", "net.ba", "org.ba", "gov.ba", "edu.ba", "unsa.ba", "com.rs", "co.rs", "org.rs", "edu.rs", "ac.rs", "gov.rs", "in.rs", "com.si", "eu.com", "us.com", "uk.com", "de.com", "gb.com", "br.com", "cn.com", "jpn.com", "ru.com", "sa.com", "za.com", "com.ki", "gov.ki"]
)

#: Private (non-ICANN) suffixes. Present so `bucket.s3.amazonaws.com` and
#: `app.vercel.app` are not mistaken for subdomains of one shared parent.
_PRIVATE_SUFFIXES: frozenset[str] = frozenset(
    ["s3.amazonaws.com", "s3-website.amazonaws.com", "elb.amazonaws.com", "compute.amazonaws.com", "compute-1.amazonaws.com", "execute-api.amazonaws.com", "cloudfront.net", "amplifyapp.com", "awsapprunner.com", "elasticbeanstalk.com", "blob.core.windows.net", "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net", "trafficmanager.net", "azureedge.net", "azurefd.net", "azurestaticapps.net", "azure-api.net", "database.windows.net", "appspot.com", "cloudfunctions.net", "run.app", "web.app", "firebaseapp.com", "storage.googleapis.com", "googleapis.com", "googleusercontent.com", "pages.dev", "workers.dev", "r2.dev", "cdn.cloudflare.net", "vercel.app", "now.sh", "netlify.app", "netlify.com", "onrender.com", "railway.app", "up.railway.app", "fly.dev", "herokuapp.com", "herokudns.com", "github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io", "pythonanywhere.com", "repl.co", "replit.dev", "glitch.me", "digitaloceanspaces.com", "ondigitalocean.app", "zone.id", "fastly.net", "fastlylb.net", "akamaized.net", "akamaiedge.net", "edgekey.net", "edgesuite.net", "akadns.net", "myshopify.com", "wordpress.com", "wpengine.com", "squarespace.com", "webflow.io", "zendesk.com", "freshdesk.com", "atlassian.net", "statuspage.io", "sharepoint.com", "onmicrosoft.com", "readthedocs.io", "surge.sh", "render.com", "koyeb.app", "deno.dev"]
)

#: Wildcard rules - any single label beneath these forms a suffix.
_WILDCARD_SUFFIXES: frozenset[str] = frozenset(
    ["ck", "jm", "kh", "mm", "bd", "np", "om", "er", "zw", "pg", "fk", "gu", "bn", "kw", "sch.uk", "compute.amazonaws.com", "compute-1.amazonaws.com", "s3.dualstack.amazonaws.com"]
)

#: Exception rules - these are registrable despite matching a wildcard.
_EXCEPTIONS: frozenset[str] = frozenset({"www.ck", "city.kobe.jp"})

_ALL_SUFFIXES: frozenset[str] = _ICANN_SUFFIXES | _PRIVATE_SUFFIXES


@lru_cache(maxsize=4096)
def public_suffix(domain: str) -> str | None:
    """Return the public suffix of an already-punycoded, lowercased domain.

    Longest match wins, exactly as the PSL algorithm specifies.
    """
    if not domain:
        return None
    name = domain.strip(".").lower()
    if not name:
        return None
    labels = name.split(".")

    # Exception rules take precedence over everything else.
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in _EXCEPTIONS:
            # The exception's own suffix is one label shorter.
            return ".".join(labels[index + 1 :]) or None

    # Longest explicit match.
    best: str | None = None
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in _ALL_SUFFIXES:
            best = candidate
            break  # first (longest) match wins

    # Wildcard rules: "*.ck" means "<anything>.ck" is itself a suffix.
    for index in range(1, len(labels)):
        parent = ".".join(labels[index:])
        if parent in _WILDCARD_SUFFIXES:
            candidate = ".".join(labels[index - 1 :])
            if best is None or len(candidate.split(".")) > len(best.split(".")):
                best = candidate
            break

    if best is not None:
        return best

    # Default rule: the rightmost label is the suffix.
    return labels[-1] if len(labels) >= 1 else None


@lru_cache(maxsize=4096)
def registrable_domain(domain: str) -> str | None:
    """Return the eTLD+1 ("registrable domain") of a punycoded domain.

    Returns None when the input *is* a public suffix and therefore has no
    registrable form (e.g. "co.uk").
    """
    if not domain:
        return None
    name = domain.strip(".").lower()
    suffix = public_suffix(name)
    if suffix is None:
        return None
    if name == suffix:
        return None
    suffix_labels = suffix.split(".")
    labels = name.split(".")
    if len(labels) <= len(suffix_labels):
        return None
    return ".".join(labels[-(len(suffix_labels) + 1) :])


def same_registrable(left: str, right: str) -> bool:
    """True when two hostnames share a registrable domain."""
    a = registrable_domain(left)
    b = registrable_domain(right)
    return bool(a and b and a == b)
