#!/usr/bin/env python3
"""Anonymize server logs for test fixtures – consistently, so patterns survive.

    python3 -I tests/anonymize.py [--server-ip IP] [--hostname NAME]
                                  [--own-domains FILE] [--learn FILE... --]
                                  [--out-dir DIR] FILE...

Without --out-dir the anonymized FILEs are printed one after the other; with it,
each goes to DIR/<its path as given> – so pass relative paths. --learn reads more files only to learn names (all
logs of the server, say), so a customer name is replaced in a short excerpt even
if its domain doesn't appear there. One mapping is shared by all files, so the
same domain, mailbox or IP gets the same replacement everywhere:

  - domains          -> d1.example, d2.example … (subdomains keep their prefix
                        shape: mail.d3.example); well-known providers and the
                        blocklists the script looks for are kept
  - mailbox names    -> user1, user2 … (generic ones like info, admin, postmaster
                        are kept); bare login names that match a mapped mailbox
                        are replaced too
  - IPv4 addresses   -> 198.18.0.0/15 (RFC 2544, never routed); the server's IP
                        -> 203.0.113.10; private, loopback and documentation
                        ranges are kept
  - IPv6 addresses   -> 2001:db8::/32 (documentation); ::1 and fe80:: are kept
  - the server's host name -> host.example.com, its short name -> host
  - for the server's own domains (--own-domains: one per line – the hosted
    domains), their distinctive words (a company or family name) and their
    mailbox names are replaced wherever they appear – in paths, file names,
    folder names, bare logins
  - SSH key fingerprints, long hex or base64 tokens -> fixed placeholders
  - the script's own reports: Plesk system users ("uid 10020  name") -> sysuser,
    bare login names in count lists ("      30  jane") like mailbox names

Nothing is sent anywhere; the script only reads the files and prints. Read the
result before you publish it: anonymizing is best effort, a human (or a second
check) has the last word.
"""
import ipaddress
import re
import sys

KEEP_DOMAINS = {
    # mail providers the report groups deliveries by, and their MX hosts
    "google.com", "googlemail.com", "gmail.com", "outlook.com", "hotmail.com",
    "live.com", "microsoft.com", "office365.com", "gmx.net", "gmx.de", "web.de",
    "t-online.de", "icloud.com", "me.com", "apple.com", "yahoo.com", "aol.com",
    "ionos.de", "1und1.de", "kundenserver.de", "strato.de", "hornetsecurity.com",
    "amazonses.com", "sendgrid.net", "mailjet.com", "datev.de",
    # blocklists and services the script queries or reads
    "spamhaus.org", "spamcop.net", "barracudacentral.org", "surriel.com",
    "uribl.com", "surbl.org", "letsencrypt.org", "db-ip.com", "plesk.com",
    "wordpress.org", "w.org", "github.com", "shellcheck.net",
}
KEEP_LOCALS = {
    "info", "admin", "administrator", "postmaster", "root", "abuse", "webmaster",
    "noreply", "no-reply", "mailer-daemon", "bounce", "bounces", "office",
    "kontakt", "contact", "mail", "test", "support", "sales", "service", "hr",
    "billing", "rechnungen", "invoice", "invoices", "newsletter", "news",
    "www-data", "popuser", "psaadm", "nobody", "user", "users", "x",
}
STOPWORDS = {
    "mail", "email", "server", "login", "admin", "online", "service", "services", "shop",
    "store", "info", "web", "host", "hosting", "cloud", "group", "world", "media", "design",
    "digital", "office", "news", "consulting", "accounting", "support", "system", "systems",
}
TLDS = ("de|com|net|org|eu|info|ch|at|io|biz|shop|online|uk|nl|fr|es|it|pl|ru|cn|"
        "br|us|co|me|tv|cc|site|xyz|top|club|app|dev|cloud|email|store|tech|"
        "space|pro|mobi|name|ws|ua|kr|jp|in|tr|se|dk|no|fi|be|lu|cz|hu|ro|pt|gr|"
        "ar|mx|ca|au|nz|za|sk|si|hr|lt|lv|ee|bg|rs|by|kz|vn|id|th|my|sg|hk|tw|"
        "ir|il|ae|sa|eg|ng|ke|cl|pe|ve|uy|ec|bo|py|gt|cr|pa|do|hn|ni|sv|cu|"
        "website|agency|digital|media|news|live|world|today|link|click|win|bid|"
        "work|life|art|blog|fun|icu|buzz|rest|bar|cyou|sbs|ltd|gmbh|immo|bayern|"
        "berlin|hamburg|koeln|ruhr|nrw|saarland|swiss|wien|tirol")
DOMAIN_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s))(?![\w-])" % TLDS, re.I)
VERP_RE = re.compile(r"(?<![\w.+=-])(bounces?|prvs|msprvs\d*|srs\d|bo|bnc)([+=.-])[^@\s<>,;]*@", re.I)
EMAIL_RE = re.compile(r"(?<![\w.+-])([a-z0-9][a-z0-9._+-]*)@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")   # an IP may end a sentence: "from 192.0.2.1."
IPV6_RE = re.compile(r"(?<![\w:])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4})(?![\w:])", re.I)
FPR_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{20,}")
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{28,}={0,2}")
LOGIN_RE = re.compile(r"((?:\busername=|/mailnames/[^/\s]+/|\buser=<?|sasl_username=|with login '|\buser '|[Ii]nvalid user |Failed (?:password|publickey|none) for (?:invalid user )?|Accepted \w+ for |session (?:opened|closed) for user |Disconnected from (?:invalid |authenticating )?user |Connection closed by (?:invalid |authenticating )?user |logname=\S* ruser=\S* rhost=\S* +user=))([A-Za-z][A-Za-z0-9._-]*)(?=[\s,'>;)(/]|$)")
SYSUSER_RE = re.compile(r"(?<![\w-])[a-z0-9][a-z0-9.-]*_[a-z0-9]{6,12}(?![\w-])")
REQ_RE = re.compile(r'("(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|PROPFIND) )(\S+)')
REF_RE = re.compile(r'("https?://[^/"\s]+)(/[^"\s]*)?(")')
KEEP_SEG_RE = re.compile(r"(wp-[a-z0-9-]+|[A-Za-z0-9_.-]+\.(php\d?|txt|xml|js|css|ico|env|git|sql|zip|gz|tar|bak|old|ini|json|html?|log|yml|yaml|cgi|asp|aspx|jsp)|"
                         r"\.[A-Za-z0-9_-]+|admin|plugins|themes|uploads|includes|api|v\d+|feed|login|cgi-bin|vendor|"
                         r"phpmyadmin|pma|xmlrpc|wordpress|wp|blog|backup|backups|old|new|test|config|"
                         r"\d{4}|\d{1,2}|robots\.txt|sitemap.*|well-known|acme-challenge|autodiscover)", re.I)
# a "+" address (Gmail forwarding, subaddress) may carry another address after the "+"
PLUS_RE = re.compile(r"(?<![\w.+=-])([a-z0-9][a-z0-9._-]*)\+[^@\s<>,;]*@", re.I)
# the script's own reports: Plesk system users ("uid 10020  name  /var/www/vhosts/…") and
# bare login names in count lists ("      30  jane")
UIDUSER_RE = re.compile(r"(\buid \d+\s+)([a-z][\w.-]*)(?=\s+/)")
KEEP_SYSUSERS = {"root", "popuser", "www-data", "apache", "nginx", "psaadm", "mailman", "postfix", "nobody"}
COUNTLOGIN_RE = re.compile(r"^([ \t]+\d+[ \t]+)([A-Za-z][\w.-]*)(?=[ \t]*$)", re.M)
HEX_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{24,}(?![0-9a-f])", re.I)


class Anon:
    def __init__(self, server_ip, hostname):
        self.dom, self.loc, self.v4, self.v6, self.words = {}, {}, {}, {}, {}
        self.server_ip, self.hostname = server_ip, (hostname or "").lower()
        self._loc_re = self._word_re = None
        self.own = set()

    @staticmethod
    def registrable(d):
        p = d.lower().split(".")
        if len(p) >= 3 and p[-2] in ("co", "com", "org", "net", "ac", "gov") and len(p[-1]) == 2:
            return ".".join(p[-3:])
        return ".".join(p[-2:])

    def domain(self, d):
        dl = d.lower().rstrip(".")
        if dl.endswith((".example", ".invalid", ".test", ".localhost")) or dl in ("localhost", "localdomain"):
            return d
        if self.hostname and dl == self.hostname:
            return "host.example.com"
        reg = self.registrable(dl)
        if reg in KEEP_DOMAINS or reg.startswith("example."):
            return d
        if reg not in self.dom:
            n = len(self.dom) + 1
            self.dom[reg] = "d%d.example" % n
            if reg in self.own:
                for w in re.split(r"[.-]", reg.rsplit(".", 1)[0]):
                    if len(w) >= 5 and not w.isdigit() and w.lower() not in STOPWORDS:
                        self.words.setdefault(w.lower(), "name%d" % (len(self.words) + 1))
                # the whole name too, where its parts are short ("my-big-shop")
                lab = reg.rsplit(".", 1)[0].lower()
                if "-" in lab and len(lab) >= 5:
                    self.words.setdefault(lab, "name%d" % (len(self.words) + 1))
        sub = dl[: -len(reg)].rstrip(".")
        sub = ".".join(("www" if s == "www" else "mail" if s in ("mail", "mx", "smtp") else "sub") for s in sub.split(".")) if sub else ""
        return (sub + "." if sub else "") + self.dom[reg]

    def local(self, l, dom=None):
        ll = l.lower()
        if ll in KEEP_LOCALS:
            return l
        # VERP and SRS addresses carry the original address inside: keep only the prefix
        m = re.match(r"(bounces?|prvs|msprvs\d*|srs\d|bo|bnc)([=+.-])", ll)
        if m:
            return l[: m.end()] + "X"
        if ll not in self.loc:
            self.loc[ll] = "user%d" % (len(self.loc) + 1)
        return self.loc[ll]

    @staticmethod
    def web_path(p):
        """A requested path: keep what tells attacks and WordPress apart, replace the rest
        (page and author slugs, uploads – they can carry names); query values become x."""
        path, _, q = p.partition("?")
        segs = []
        for sg in path.split("/"):
            if sg == "" or KEEP_SEG_RE.fullmatch(sg):
                segs.append(sg)
            else:
                segs.append("page")
        q = re.sub(r"=[^&]*", "=x", q)
        return "/".join(segs) + ("?" + q if q else "")

    def ipv4(self, s):
        try:
            ip = ipaddress.IPv4Address(s)
        except ValueError:
            return s
        if s == self.server_ip:
            return "203.0.113.10"
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast \
                or any(ip in ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")) \
                or s.startswith("127."):
            return s
        if s not in self.v4:
            n = len(self.v4) + 1
            self.v4[s] = str(ipaddress.IPv4Address("198.18.0.0") + n)
        return self.v4[s]

    def ipv6(self, s):
        try:
            ip = ipaddress.IPv6Address(s)
        except ValueError:
            return s
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or s.lower().startswith("2001:db8") or ip.ipv4_mapped:
            return s
        if s not in self.v6:
            self.v6[s] = "2001:db8::%x" % (len(self.v6) + 1)
        return self.v6[s]

    def line(self, t):
        t = FPR_RE.sub("SHA256:" + "A" * 43, t)
        t = VERP_RE.sub(lambda m: m.group(1) + m.group(2) + "X@", t)
        t = PLUS_RE.sub(lambda m: self.local(m.group(1)) + "+X@", t)
        t = EMAIL_RE.sub(lambda m: self.local(m.group(1)) + "@" + self.domain(m.group(2)), t)
        t = DOMAIN_RE.sub(lambda m: self.domain(m.group(1)), t)
        t = IPV4_RE.sub(lambda m: self.ipv4(m.group(1)), t)
        t = IPV6_RE.sub(lambda m: self.ipv6(m.group(1)), t)
        if self.hostname:
            short = self.hostname.split(".")[0]
            t = re.sub(r"(?<![\w.-])%s(?![\w-])" % re.escape(short), "host", t, flags=re.I)
        # login names without domain, where logs name them ("user=jane", "Invalid user
        # jane", "with login 'jane'", "for jane from"), and Plesk system users
        # ("example.com_a1b2c3d4")
        t = LOGIN_RE.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).lower() in KEEP_LOCALS
                                                  or m.group(2).startswith(("user", "d")) and m.group(2)[1:].isdigit()
                                                  else self.local(m.group(2))), t)
        t = SYSUSER_RE.sub("sysuser", t)
        t = UIDUSER_RE.sub(lambda m: m.group(1) + (m.group(2) if m.group(2) in KEEP_SYSUSERS else "sysuser"), t)
        t = COUNTLOGIN_RE.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).lower() in KEEP_LOCALS
                                                      or re.fullmatch(r"(user|sysuser|name)\d*", m.group(2))
                                                      else self.local(m.group(2))), t)
        t = REQ_RE.sub(lambda m: m.group(1) + self.web_path(m.group(2)), t)
        t = REF_RE.sub(lambda m: m.group(1) + (self.web_path(m.group(2)) if m.group(2) else "/") + m.group(3), t)   # the referrer path matters too (login_up.php)
        if self._word_re is None:
            words = sorted(self.words, key=len, reverse=True)
            self._word_re = re.compile("|".join(map(re.escape, words)), re.I) if words else False
        # the distinctive words of the server's own domains, wherever they appear
        if self._word_re:
            t = self._word_re.sub(lambda m: self.words[m.group(0).lower()], t)
        t = HEX_RE.sub("0" * 24, t)
        t = TOKEN_RE.sub("TOKEN", t)
        return t


def main(argv):
    import os
    server_ip, hostname, out_dir, own_file, learn, files = None, None, None, None, [], []
    it = iter(argv)
    target = files
    for a in it:
        if a == "--server-ip":
            server_ip = next(it)
        elif a == "--hostname":
            hostname = next(it)
        elif a == "--own-domains":
            own_file = next(it)
        elif a == "--out-dir":
            out_dir = next(it)
        elif a == "--learn":
            target = learn
        elif a == "--":
            target = files
        else:
            target.append(a)
    an = Anon(server_ip, hostname)
    if own_file:
        with open(own_file) as fh:
            an.own = {an.registrable(x.strip().lower()) for x in fh if x.strip()}
    # first pass: learn every domain and mailbox, so bare words are replaced from line one
    for f in learn + files:
        with open(f, errors="replace") as fh:
            for l in fh:
                for m in EMAIL_RE.finditer(l):
                    an.local(m.group(1), m.group(2)); an.domain(m.group(2))
                for m in DOMAIN_RE.finditer(l):
                    an.domain(m.group(1))
    for f in files:
        out = sys.stdout
        if out_dir:
            path = os.path.join(out_dir, an.line(f.lstrip("./")).strip())
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            out = open(path, "w")
        with open(f, errors="replace") as fh:
            for l in fh:
                out.write(an.line(l))
        if out_dir:
            out.close()


if __name__ == "__main__":
    main(sys.argv[1:])
