"""Exercise each additional public collector once without persisting evidence."""

from app.osint.registry import CollectorRegistry


CASES = {
    "domain_certspotter": {"domain": "example.com"},
    "domain_commoncrawl": {"domain": "example.com"},
    "url_commoncrawl": {"url": "https://example.com/"},
    "ip_shodan_internetdb": {"ip": "8.8.8.8"},
    "username_bluesky": {"username": "jay.bsky.team"},
    "username_hackernews": {"username": "pg"},
    "username_github_repositories": {"username": "octocat"},
    "username_npm_maintainer": {"username": "sindresorhus"},
    "keyword_gdelt_news": {"keyword": "open source intelligence"},
    "keyword_crossref": {"keyword": "open source intelligence"},
    "keyword_openlibrary": {"keyword": "open source intelligence"},
    "keyword_stackexchange": {"keyword": "open source intelligence"},
    "keyword_europepmc": {"keyword": "open source intelligence"},
    "keyword_google_books": {"keyword": "open source intelligence"},
    "keyword_hackernews": {"keyword": "open source intelligence"},
}


def main() -> int:
    registry = CollectorRegistry()
    failures: list[str] = []
    for name, query in CASES.items():
        try:
            items = registry.get(name).collect(query)
        except Exception as exc:  # provider/network diagnostics belong in stdout
            failures.append(name)
            print(f"FAIL {name}: {type(exc).__name__}: {str(exc)[:180]}")
        else:
            print(f"OK   {name}: {len(items)} normalized item(s)")

    print(f"\nSummary: {len(CASES) - len(failures)}/{len(CASES)} providers reachable")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
