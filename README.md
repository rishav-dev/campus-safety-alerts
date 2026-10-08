# Campus Safety Alerts Across 10 Universities

A Python data-collection project comparing how ten U.S. universities publish campus crime and safety alerts.

I built university-specific scrapers to collect and normalize 519 documents from HTML pages and PDFs into a common dataset. Every record includes the source URL, archive URL, scrape timestamp, and a content hash, so any row can be traced back to where it came from.

## The problem

Universities are required to publish crime information, but each one does it differently: some post individual alerts in a feed, some only publish annual security reports or crime logs, and some block ordinary scripted requests. A single generic crawler does not work, so each university gets its own scraper and all of them write to one schema.

## Data

`university_incident_reports.csv` has 519 rows, 506 from HTML pages and 13 from PDFs.

| Column | Meaning |
|---|---|
| `university` | Source institution |
| `record_family` | `alert_notice`, `alert_feed`, `annual_report`, or `crime_log` |
| `archive_url`, `source_url` | Where the document was found and where its text came from |
| `source_type` | `html` or `pdf` |
| `link_text`, `title`, `date` | Listing text, page title, and extracted date when available |
| `incident_type`, `location` | Filled where the source states them |
| `content`, `content_length` | Full normalized text and its length |
| `content_hash` | MD5 of the text, used to remove duplicates |
| `scrape_timestamp_utc` | When the row was collected |

Not every university keeps a public archive of alerts. Where none exists (UC Berkeley and ASU, for example), the scraper collects annual security reports or crime logs instead. Use `record_family` to separate those sources in any analysis.

## How it works

- One scraper function per university and source, plus shared helpers for fetching, cleaning text, and extracting dates.
- Requests are throttled and retried on transient failures. `cloudscraper` is used as an option for sites that return 403 to ordinary requests.
- PDFs are converted to text with `pdfminer.six`.
- Records are de-duplicated by content hash before the CSV is written.
- `scraper_log.txt` is the log from the run that produced the included dataset.

## Run it

```bash
pip install requests beautifulsoup4 pdfminer.six cloudscraper
python scraper.py
```

This writes `university_incident_reports.csv` to the current directory. Pages change over time, so a new run will not match the included file exactly.

## Files

```
scraper.py                       scrapers and helpers
university_incident_reports.csv  the dataset
scraper_log.txt                  log from the collection run
```

Built for DACSS 758 at UMass Amherst.
