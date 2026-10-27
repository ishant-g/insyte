"""CPE 2.3 derivation for detected technologies.

NVD's CVE search is far more precise against a CPE string
(`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`) than against a keyword,
because it matches the *configuration* NVD records against each CVE rather
than free-text searching descriptions. Not every detected technology maps
cleanly to a CPE vendor:product pair - this module holds the mapping table
Insyte actually knows about and returns `None` for anything it does not,
so the correlator falls back to keyword search (weaker evidence, and it is
scored accordingly) rather than fabricating a CPE that would silently
return wrong results.
"""

from __future__ import annotations

#: normalized technology name -> (vendor, product)
_CPE_MAP: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache http server": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla\\!"),
    "php": ("php", "php"),
    "django": ("djangoproject", "django"),
    "express": ("expressjs", "express"),
    "laravel": ("laravel", "laravel"),
    "jquery": ("jquery", "jquery"),
    "jquery ui": ("jqueryui", "jquery_ui"),
    "react": ("facebook", "react"),
    "vue.js": ("vuejs", "vue.js"),
    "angularjs": ("angularjs", "angular.js"),
    "angular": ("angular", "angular"),
    "next.js": ("vercel", "next.js"),
    "nuxt.js": ("nuxtjs", "nuxt.js"),
    "lodash": ("lodash", "lodash"),
    "moment.js": ("momentjs", "moment.js"),
    "openssl": ("openssl", "openssl"),
    "log4j": ("apache", "log4j"),
    "spring framework": ("vmware", "spring_framework"),
    "tomcat": ("apache", "tomcat"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "redis": ("redis", "redis"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "kibana": ("elastic", "kibana"),
    "varnish": ("varnish-cache", "varnish"),
    "haproxy": ("haproxy", "haproxy"),
    "openresty": ("openresty", "openresty"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "magento": ("magento", "magento"),
    "prestashop": ("prestashop", "prestashop"),
    "typo3": ("typo3", "typo3"),
    "ghost": ("ghost", "ghost"),
    "strapi": ("strapi", "strapi"),
    "graphql": ("graphql", "graphql"),
    "webmin": ("webmin", "webmin"),
    "moodle": ("moodle", "moodle"),
    "vbulletin": ("vbulletin", "vbulletin"),
    "openssh": ("openbsd", "openssh"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
    "bind": ("isc", "bind"),
    "vault": ("hashicorp", "vault"),
    "consul": ("hashicorp", "consul"),
    "kubernetes": ("kubernetes", "kubernetes"),
    "docker": ("docker", "docker"),
    "traefik": ("traefik", "traefik"),
}


def to_cpe(normalized_name: str, version: str | None) -> str | None:
    """Build a CPE 2.3 formatted string, or None if unmapped or unversioned.

    A CPE without a version matches *every* version of the product in
    NVD's search, which is indistinguishable from a keyword search but
    slower - so this returns None when there is no version to pin, and the
    caller falls back to keyword search deliberately.
    """
    mapping = _CPE_MAP.get(normalized_name.strip().lower())
    if mapping is None or not version:
        return None
    vendor, product = mapping
    safe_version = version.strip().replace(":", "\\:")
    return f"cpe:2.3:a:{vendor}:{product}:{safe_version}:*:*:*:*:*:*:*"


def is_known_product(normalized_name: str) -> bool:
    return normalized_name.strip().lower() in _CPE_MAP


def vendor_product(normalized_name: str) -> tuple[str, str] | None:
    """The (vendor, product) pair for a known technology, or None."""
    return _CPE_MAP.get(normalized_name.strip().lower())
