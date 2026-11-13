#!/usr/bin/env python3
"""Checks the static site in site/ before it is published, offline.

Every local href and src must name a file in site/ (a directory link needs
its index.html), and every #fragment must name an id on the target page.
Absolute paths are resolved under the project site's /lockssh/ base, as on
GitHub Pages. Each page needs lang, a viewport, a title, a description and a
canonical URL: its own address under the site's URL (the home page's for
404.html). sitemap.xml must list every page but 404.html, and nothing else.
External links are not fetched.

    python3 scripts/check-site.py [site]
"""

import html.parser
import re
import pathlib
import sys
import urllib.parse

BASE = "/lockssh/"
URL = "https://davidgodefroid.github.io" + BASE


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.ids, self.meta = [], set(), {}
        self.lang = self.title = False
        self.canonical = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "html" and a.get("lang"):
            self.lang = True
        if tag == "title":
            self._in_title = True
        if tag == "meta" and "name" in a:
            self.meta[a["name"]] = a.get("content", "")
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical = a.get("href")
        for attr in ("href", "src", "srcset"):
            if attr in a:
                self.links.append((tag, a[attr]))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and data.strip():
            self.title = True


def parse(path):
    p = Page()
    p.feed(path.read_text(encoding="utf-8"))
    return p


def target(root, page, ref):
    """The file a local reference points at, or None for an external one."""
    u = urllib.parse.urlsplit(ref)
    if u.scheme or u.netloc:
        return None, None
    path = urllib.parse.unquote(u.path)
    if path.startswith("/"):
        if not path.startswith(BASE):
            return root / "__outside_base__", u.fragment
        f = root / path[len(BASE):]
    elif path:
        f = page.parent / path
    else:
        f = page
    if path.endswith("/") or f.is_dir():
        f = f / "index.html"
    return f.resolve(), u.fragment


def page_path(rel):
    """A page's path under the site's URL: a directory for index.html, the home page for 404.html."""
    if rel.name == "404.html":
        return ""
    if rel.name == "index.html":
        return "" if rel.parent == pathlib.Path(".") else rel.parent.as_posix() + "/"
    return rel.as_posix()


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "site").resolve()
    pages = {p.resolve(): parse(p) for p in root.rglob("*.html")}
    errors = []
    if (root / "CNAME").exists():
        errors.append("site/CNAME: the site uses the default GitHub Pages URL")
    for page, p in sorted(pages.items()):
        rel = page.relative_to(root)
        if not p.lang:
            errors.append(f"{rel}: <html> has no lang")
        if not p.title:
            errors.append(f"{rel}: no <title>")
        if "viewport" not in p.meta:
            errors.append(f"{rel}: no viewport meta")
        if not p.meta.get("description"):
            errors.append(f"{rel}: no description meta")
        want = URL + page_path(rel)
        if p.canonical != want:
            errors.append(f"{rel}: canonical is {p.canonical!r}, want {want!r}")
        for tag, ref in p.links:
            if tag == "source":  # srcset holds a single URL here
                ref = ref.split()[0]
            f, frag = target(root, page, ref)
            if f is None:
                continue
            if not f.is_file():
                errors.append(f"{rel}: {ref}: no such file")
                continue
            if frag and f.suffix == ".html" and frag not in pages[f].ids:
                errors.append(f"{rel}: {ref}: no id {frag!r}")
    sitemap = root / "sitemap.xml"
    listed = set(re.findall(r"<loc>([^<]*)</loc>", sitemap.read_text(encoding="utf-8"))) if sitemap.is_file() else set()
    wanted = {URL + page_path(page.relative_to(root)) for page in pages if page.name != "404.html"}
    for u in sorted(wanted - listed):
        errors.append(f"sitemap.xml: {u} missing")
    for u in sorted(listed - wanted):
        errors.append(f"sitemap.xml: {u} is no page")
    for e in errors:
        print(e, file=sys.stderr)
    print(f"{len(pages)} pages checked, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
