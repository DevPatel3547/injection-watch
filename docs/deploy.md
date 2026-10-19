# Deploying InjectionWatch at zero cost

There are two independent ways to deploy. Most users only need the first.

## A. Static feed on GitHub Pages (recommended, $0)

`injectionwatch publish` writes a self-contained static site:

| path | what |
|---|---|
| `index.html`, `app.js`, `style.css` | dashboard: stats, breakdowns, searchable table, client-side URL check |
| `feed.json`, `feed.csv`, `stix.json` | the full feed (CC BY 4.0) |
| `meta.json` | generation time, versions, aggregate stats, recent scan statistics |
| `lookup/<xx>.json` | per-host shards; `xx = sha256(lowercase host)[:2]` |
| `schema/feed-entry.schema.json` | JSON Schema of an entry |

**Client-side `/check` for agents and tools without the API.** Normalise the URL the same way as
`injectionwatch.db.normalize_url` (`app.js` has a reference `normalizeUrl`). Hash the host and fetch
`lookup/<first two hex chars>.json`, then look for the exact `url_norm` inside
`hosts[<host>]`. A missing shard or host means *not listed*, which never means "safe".

### Monthly automated publish (template, not active)

`deploy/github-actions/monthly-publish.yml` runs once a month and:

1. resolves the latest Common Crawl crawl id from `https://index.commoncrawl.org/collinfo.json`;
2. downloads `https://data.commoncrawl.org/crawl-data/<id>/warc.paths.gz` and picks `warc_count`
   files (a deterministic sample seeded by the crawl id);
3. merges the currently published `feed.json` into a fresh DB (`injectionwatch merge-feed`), so
   `first_seen`, `seen_count` and status history carry forward;
4. streams each WARC through `injectionwatch scan-warc`, deleting it before the next download so disk
   use stays at about one file (~1 GB);
5. runs `injectionwatch publish` + `report` and deploys with `actions/deploy-pages`.

To activate it:

1. Fill in the `CONTACT` placeholder in `injectionwatch/config.py` (`PROJECT_URL` already points to
   https://github.com/DevPatel3547/injection-watch).
2. Under Settings -> Pages, set Source to **GitHub Actions**.
3. `cp deploy/github-actions/monthly-publish.yml .github/workflows/`, then commit and push.
4. Trigger it once with `warc_count=1` and check the run time and the site before relying on the
   schedule.

Notes:

* A free runner has 4 vCPUs and a 6 h job limit. At the throughput measured in the README, 3 to 5 WARC
  files per month fit comfortably. Each file is a random ~0.0001 sample of a crawl, so treat the feed as
  a *sample*, not a census.
* `data.commoncrawl.org` is free and needs no account. Heavy users are asked to read from S3 in
  `us-east-1`, so keep `warc_count` modest.
* The repository URLs and the Common Crawl path layout above come from the Common Crawl documentation as
  of 2026. If a download step fails, re-check them at https://commoncrawl.org/get-started.

## B. The HTTP API (optional)

The API serves the same data with per-URL lookups, pagination, ETags and rate limits.

```
docker build -t injectionwatch .
docker run -p 8000:8000 -v $PWD/data:/data injectionwatch     # DB at /data/injectionwatch.db
curl 'http://127.0.0.1:8000/v1/check?url=https://example.com/'
open http://127.0.0.1:8000/docs                              # OpenAPI UI
```

Environment variables (`injectionwatch/api.py::Settings.from_env`):

| variable | default | meaning |
|---|---|---|
| `INJECTIONWATCH_DB` | `injectionwatch.db` | SQLite feed DB |
| `INJECTIONWATCH_CORS_ORIGINS` | `*` | comma-separated allowed origins (reads are public; no credentials are ever allowed) |
| `INJECTIONWATCH_RATE_LIMIT` | `60` | requests/minute/client on read routes |
| `INJECTIONWATCH_SUBMIT_RATE_LIMIT` | `10` | POST /v1/submit per minute per client |
| `INJECTIONWATCH_RATE_BACKEND` | `memory` | `memory` (one process) or `sqlite` (several workers, one host) |
| `INJECTIONWATCH_TRUST_PROXY` | `0` | key rate limits on `X-Forwarded-For` (only behind a proxy you control) |
| `INJECTIONWATCH_LOG_SALT` | random | salt for hashed client keys in logs and the rate limiter |

Free hosting options for the API come and go, so none are endorsed here. The static site needs nothing
beyond GitHub Pages. For many workers on many hosts, implement `ratelimit.RateLimitBackend` on Redis or
enforce limits at the CDN.
