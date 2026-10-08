"""
scraper.py
----------------

This script collects campus crime alerts and timely warning notices from ten major universities.  Each
institution has its own way of publishing safety notices, so a single generic crawler is not reliable.
Instead, this file implements a dedicated scraper function per university along with a small set of
utility routines.  The functions are combined at the end of the file to produce a unified CSV dataset.

For every university we explicitly specify which URLs we are scraping from and whether the records come
from a post feed (alert_notice, alert_feed) or from official annual security reports or crime logs
(annual_report, crime_log).  See the ``record_family`` field on each record.  During development the
links for each university were verified manually; citations for the contents of those pages can be
found in the final report submitted with this assignment.

The script requires Python 3.8+ and a few libraries: ``requests``, ``beautifulsoup4``,
``pdfminer.six`` and optionally ``cloudscraper``.  It throttles requests between pages to reduce
load on the remote servers and employs retry logic on transient HTTP failures.  Some campuses
respond with 403 Forbidden to typical requests; when available the optional ``cloudscraper``
library is used to work around those blocks.

Usage
-----
Run the script directly to write a CSV file named ``university_incident_reports.csv`` in the
current directory:

    python scraper.py

The resulting file contains one row per distinct document scraped with fields documenting the
university, the source type (html or pdf), the family of record, the URLs, the extracted date and
title (if available), the body content, and various metadata useful for downstream processing.

Note
----
Not all universities maintain a public historical archive of crime alerts.  Where a comparable
archive does not exist (e.g. UC Berkeley and ASU), the scraper falls back to collecting
officially-published annual security and fire safety reports or crime logs instead.  The ``record_family``
field makes it easy to separate these sources later in analysis.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from bs4 import BeautifulSoup
from pdfminer.high_level import extract_text as pdf_extract_text
from requests.adapters import HTTPAdapter
from urllib.parse import urljoin, urlparse, urlunparse

try:
    # cloudscraper can bypass some 403 pages used by Cloudflare protection on UNC's Alert Carolina
    # site.  It is optional.  If unavailable, the UNC scraper will degrade gracefully and may
    # return fewer records.
    import cloudscraper  # type: ignore
    HAS_CLOUDSCRAPER = True
except ImportError:
    cloudscraper = None  # type: ignore
    HAS_CLOUDSCRAPER = False


# -----------------------------------------------------------------------------
# Configuration constants
# -----------------------------------------------------------------------------

# Target output CSV path.  You can change this if desired.
OUTPUT_FILE = "university_incident_reports.csv"

# Logging configuration
LOG_FILE = "scraper_log.txt"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


# Generic request configuration
REQUEST_DELAY = 1.0  # seconds between requests
REQUEST_TIMEOUT = 20  # seconds per request
MAX_PAGES = 30        # safeguard on paginated feeds
MIN_CONTENT_CHARS = 80  # discard scraped content shorter than this many characters

# HTTP headers to present a realistic browser profile
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

def log(msg: str) -> None:
    """Print to console and write to log file."""
    print(msg)
    logging.info(msg)


def build_session() -> requests.Session:
    """Create a requests session with retry behaviour and default headers."""
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    retry = requests.adapters.Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=1.0,
        status_forcelist=[403, 429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


SESSION = build_session()
CS_SCRAPER = (cloudscraper.create_scraper(
    browser={"browser": "chrome", "platform": "windows", "mobile": False}
) if HAS_CLOUDSCRAPER else None)


def polite_get(url: str, use_cloud: bool = False) -> Optional[requests.Response]:
    """Get a URL with polite delay and optional Cloudflare bypass via cloudscraper."""
    time.sleep(REQUEST_DELAY)
    try:
        if use_cloud and CS_SCRAPER is not None:
            resp = CS_SCRAPER.get(url, timeout=REQUEST_TIMEOUT)
        else:
            resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp
    except Exception as exc:
        log(f"[ERROR] GET failed: {url} | {exc}")
        return None


def get_html(url: str, use_cloud: bool = False) -> Tuple[Optional[BeautifulSoup], Optional[requests.Response]]:
    """Return BeautifulSoup for the URL's HTML or (None, response) if not HTML."""
    resp = polite_get(url, use_cloud=use_cloud)
    if not resp:
        return None, None
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "html" not in ctype:
        return None, resp
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup, resp
    except Exception as exc:
        log(f"[ERROR] HTML parse failed: {url} | {exc}")
        return None, resp


def canonicalize_url(url: str) -> str:
    """Normalize URL by removing fragments.  Querystring is preserved."""
    parsed = urlparse(url)
    parsed = parsed._replace(fragment="")
    return urlunparse(parsed)


def normalize_text(text: str) -> str:
    """Normalize whitespace in single-line text."""
    return re.sub(r"\s+", " ", text or "").strip()


def normalize_multiline(text: str) -> str:
    """Normalize whitespace in multi-line text preserving newlines."""
    lines = [normalize_text(line) for line in text.splitlines()]
    lines = [line for line in lines if line]
    return "\n".join(lines)


def md5_text(text: str) -> str:
    """Return an MD5 hash of the given text (UTF-8)."""
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def remove_noise(soup: BeautifulSoup) -> BeautifulSoup:
    """Remove non-content elements from a BeautifulSoup document."""
    for bad in soup.select("script, style, nav, footer, header, aside, form, noscript"):
        bad.decompose()
    return soup


def extract_title(soup: BeautifulSoup) -> str:
    """Extract a plausible title from a BeautifulSoup document."""
    selectors = [
        "h1", "article h1", ".entry-title", ".post-title", ".page-title", "title", "h2"
    ]
    for sel in selectors:
        node = soup.select_one(sel)
        if node:
            text = normalize_text(node.get_text(" ", strip=True))
            if text:
                return text
    return ""


DATE_PATTERNS: List[Tuple[str, str]] = [
    ("%B %d, %Y", r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}"),
    ("%b %d, %Y", r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2},\s+\d{4}"),
    ("%B %d %Y", r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s+\d{4}"),
    ("%Y-%m-%d", r"\b\d{4}-\d{2}-\d{2}\b"),
    ("%m/%d/%Y", r"\b\d{1,2}/\d{1,2}/\d{4}\b"),
    ("%m/%d/%y", r"\b\d{1,2}/\d{1,2}/\d{2}\b"),
]


def parse_date_string(raw: str, fmt: str) -> str:
    """Attempt to parse a date string into ISO (YYYY-MM-DD) using a given format."""
    raw = raw.strip()
    raw = raw.replace("Sept.", "Sep.").replace("Sept ", "Sep ")
    raw = re.sub(r"(?<=\b[A-Za-z]{3})\. ", " ", raw)  # remove periods after month abbreviations
    try:
        return datetime.strptime(raw, fmt).strftime("%Y-%m-%d")
    except Exception:
        return ""


def extract_date_from_text(text: str) -> str:
    """Extract a date from arbitrary text using known patterns."""
    if not text:
        return ""
    for fmt, pattern in DATE_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            parsed = parse_date_string(match.group(0), fmt)
            if parsed:
                return parsed
    return ""


def extract_date_from_soup(soup: BeautifulSoup) -> str:
    """Extract a date from HTML document using <time> or common date containers."""
    if soup is None:
        return ""
    for t in soup.find_all("time"):
        dt = t.get("datetime")
        if dt:
            if len(dt) >= 10:
                chunk = dt[:10]
                try:
                    return datetime.strptime(chunk, "%Y-%m-%d").strftime("%Y-%m-%d")
                except Exception:
                    pass
            parsed = extract_date_from_text(dt)
            if parsed:
                return parsed
        parsed = extract_date_from_text(t.get_text(" ", strip=True))
        if parsed:
            return parsed
    # fallback selectors
    for selector in [".date", ".posted-on", ".entry-date", ".post-date", ".article-date", ".node__submitted", ".meta"]:
        node = soup.select_one(selector)
        if node:
            parsed = extract_date_from_text(node.get_text(" ", strip=True))
            if parsed:
                return parsed
    return extract_date_from_text(soup.get_text(" ", strip=True))


def extract_main_text(soup: BeautifulSoup) -> str:
    """Extract the main content from a BeautifulSoup document."""
    if soup is None:
        return ""
    soup = remove_noise(soup)
    selectors = [
        "article",
        "main",
        ".entry-content",
        ".post-content",
        ".article-content",
        ".field--name-body",
        ".node__content",
        ".content",
        "#content",
        ".region-content",
    ]
    for sel in selectors:
        node = soup.select_one(sel)
        if node:
            pieces = []
            for item in node.find_all(["p", "li"]):
                txt = normalize_text(item.get_text(" ", strip=True))
                if txt:
                    pieces.append(txt)
            joined = "\n".join(pieces).strip()
            if len(joined) >= MIN_CONTENT_CHARS:
                return joined
    # fallback: all paragraphs
    pieces = []
    for p in soup.find_all("p"):
        txt = normalize_text(p.get_text(" ", strip=True))
        if txt:
            pieces.append(txt)
    joined = "\n".join(pieces).strip()
    if len(joined) >= MIN_CONTENT_CHARS:
        return joined
    return normalize_text(soup.get_text(" ", strip=True))


def extract_pdf_text_from_response(resp: requests.Response) -> str:
    """Extract plain text from a PDF response using pdfminer."""
    tmp_path: Optional[str] = None
    try:
        with NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(resp.content)
            tmp_path = tmp.name
        text = pdf_extract_text(tmp_path) or ""
        return normalize_multiline(text)
    except Exception as exc:
        log(f"[ERROR] PDF extraction failed: {exc}")
        return ""
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


def make_record(
    university: str,
    record_family: str,
    archive_url: str,
    source_url: str,
    source_type: str,
    title: str,
    date: str,
    content: str,
    link_text: str = "",
    incident_type: str = "",
    location: str = "",
) -> Dict[str, str]:
    """Construct a record dict with standard fields."""
    content = content.strip()
    return {
        "university": university,
        "record_family": record_family,
        "archive_url": archive_url,
        "source_url": source_url,
        "source_type": source_type,
        "link_text": link_text.strip(),
        "title": title.strip(),
        "date": date.strip(),
        "incident_type": incident_type.strip(),
        "location": location.strip(),
        "content": content,
        "content_length": str(len(content)),
        "content_hash": md5_text(content) if content else "",
        "scrape_timestamp_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def dedupe_records(records: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove duplicate records based on (university, record_family, content_hash)."""
    seen = set()
    clean: List[Dict[str, str]] = []
    for rec in records:
        key = (rec["university"], rec["record_family"], rec["content_hash"])
        if not rec["content"] or len(rec["content"]) < MIN_CONTENT_CHARS:
            continue
        if key in seen:
            continue
        seen.add(key)
        clean.append(rec)
    return clean


# -----------------------------------------------------------------------------
# Generic page parser: used by many of the scrapers when following a detail link.
# -----------------------------------------------------------------------------

def parse_detail_page(
    university: str,
    record_family: str,
    archive_url: str,
    detail_url: str,
    link_text: str = "",
    use_cloud: bool = False,
) -> Optional[Dict[str, str]]:
    """Parse a detail (notice) page or PDF into a record."""
    resp = polite_get(detail_url, use_cloud=use_cloud)
    if not resp:
        return None
    # Check for PDF
    if detail_url.lower().endswith(".pdf") or "application/pdf" in (resp.headers.get("Content-Type") or "").lower():
        text = extract_pdf_text_from_response(resp)
        if len(text) < MIN_CONTENT_CHARS:
            return None
        title = text.splitlines()[0][:300] if text.splitlines() else link_text
        date = extract_date_from_text(text)
        return make_record(
            university=university,
            record_family=record_family,
            archive_url=archive_url,
            source_url=detail_url,
            source_type="pdf",
            title=title,
            date=date,
            content=text,
            link_text=link_text,
        )
    # HTML case
    soup = BeautifulSoup(resp.text, "html.parser")
    title = extract_title(soup) or link_text
    date = extract_date_from_soup(soup)
    content = extract_main_text(soup)
    if len(content) < MIN_CONTENT_CHARS:
        return None
    return make_record(
        university=university,
        record_family=record_family,
        archive_url=archive_url,
        source_url=detail_url,
        source_type="html",
        title=title,
        date=date,
        content=content,
        link_text=link_text,
    )


# -----------------------------------------------------------------------------
# Pagination helper used by some scrapers
# -----------------------------------------------------------------------------

def collect_paginated_pages(
    start_url: str,
    next_selectors: Optional[List[str]] = None,
    max_pages: int = MAX_PAGES,
    use_cloud: bool = False,
) -> List[str]:
    """Collect a list of paginated URLs starting from start_url."""
    if next_selectors is None:
        next_selectors = [
            "a[rel='next']",
            "a.next",
            ".pager__item--next a",
            ".nav-links a",
            ".pagination a",
        ]
    pages = []
    seen = set()
    current = canonicalize_url(start_url)
    while current and current not in seen and len(pages) < max_pages:
        seen.add(current)
        pages.append(current)
        soup, _ = get_html(current, use_cloud=use_cloud)
        if soup is None:
            break
        next_url: Optional[str] = None
        for selector in next_selectors:
            for a in soup.select(selector):
                href = a.get("href")
                if not href:
                    continue
                text = normalize_text(a.get_text(" ", strip=True)).lower()
                rel = " ".join(a.get("rel", [])).lower()
                candidate = canonicalize_url(urljoin(current, href))
                if "next" in text or rel == "next" or "page/" in candidate or "page=" in candidate:
                    if candidate != current:
                        next_url = candidate
                        break
            if next_url:
                break
        current = next_url
    return pages


# -----------------------------------------------------------------------------
# Scraper functions per university
# -----------------------------------------------------------------------------

def scrape_umass_alerts() -> List[Dict[str, str]]:
    """Scrape recent UMass Amherst UMPD alerts from the Alerts & Advisories page.

    The page contains sections titled "UMPD Public Safety Advisory".  Each section is self-contained and
    includes a heading line, a date line, and a paragraph or two of narrative.  The script extracts
    these sections and constructs records of type 'alert_feed'.
    """
    university = "UMass Amherst"
    archive_url = "https://www.umass.edu/police/alerts-advisories"
    records: List[Dict[str, str]] = []
    soup, _ = get_html(archive_url)
    if soup is None:
        return records
    text = normalize_multiline(soup.get_text("\n", strip=True))
    # Split on visible marker; there may only be a few advisories but we capture each one
    chunks = re.split(r"(?=UMPD Public Safety Advisory)", text)
    for chunk in chunks:
        chunk = chunk.strip()
        if "UMPD Public Safety Advisory" not in chunk:
            continue
        lines = [line.strip() for line in chunk.splitlines() if line.strip()]
        if not lines:
            continue
        # Typically the title is the second line after the heading
        if len(lines) > 1:
            title = lines[1][:250]
        else:
            title = "UMPD Public Safety Advisory"
        date = extract_date_from_text(chunk)
        content = "\n".join(lines[:25])
        if len(content) >= MIN_CONTENT_CHARS:
            records.append(
                make_record(
                    university=university,
                    record_family="alert_feed",
                    archive_url=archive_url,
                    source_url=archive_url,
                    source_type="html",
                    title=title,
                    date=date,
                    content=content,
                    link_text=title,
                )
            )
    return records


def scrape_umass_reports() -> List[Dict[str, str]]:
    """Scrape UMass Amherst annual security reports (ASR) from the Clery compliance page."""
    university = "UMass Amherst"
    page_url = "https://www.umass.edu/police/clery"
    records: List[Dict[str, str]] = []
    links = collect_pdf_links(page_url, pdf_include_pattern=r"(annual security|clery|report)", use_cloud=False)
    for pdf_url, link_text in links:
        rec = parse_detail_page(
            university=university,
            record_family="annual_report",
            archive_url=page_url,
            detail_url=pdf_url,
            link_text=link_text,
        )
        if rec:
            records.append(rec)
    return records

# -----------------------------------------------------------------------------
# Additional scrapers for UMass monthly crime logs, Washington RSS feed,
# Ohio State numeric pagination, UF extra categories and annual summaries,
# UNC RSS feed, and ASU Clery timely warning posts.  These functions
# complement the existing alert and report scrapers to increase coverage for
# universities that publish limited numbers of notices.
# -----------------------------------------------------------------------------

def scrape_umass_crime_logs() -> List[Dict[str, str]]:
    """Scrape UMass monthly crime logs from the UMPD Documents listing.

    UMass posts its monthly Clery logs in the Documents section rather than on
    the older "clery-crime-logs" page.  Each document entry labelled with a
    ``CLERY`` tag corresponds to a monthly log.  The listing is paginated.
    For each page of the listing we extract entries whose tags include
    ``CLERY``.  We then follow the entry link to a detail page and collect
    any PDF links from the page (often found in the "Download" section).
    Each PDF is parsed as a crime log record.
    """
    university = "UMass Amherst"
    base_url = "https://www.umass.edu/police/documents"
    records: List[Dict[str, str]] = []
    # Gather all paginated listing pages
    page_urls = collect_paginated_pages(base_url)
    # Ensure the base URL itself is included even if collect_paginated_pages returns empty
    if base_url not in page_urls:
        page_urls.insert(0, base_url)
    seen_month_links: set = set()
    for page_url in page_urls:
        soup, _ = get_html(page_url)
        if soup is None:
            continue
        # Each document entry is wrapped in a div.teaser-item.document
        for doc_div in soup.find_all("div", class_=lambda x: x and "teaser-item" in x and "document" in x):
            # Check if the document has a CLERY tag
            tag_div = doc_div.find("div", class_="tag")
            if not tag_div:
                continue
            tag_text = normalize_text(tag_div.get_text())
            if "clery" not in tag_text.lower():
                continue
            # Find the anchor to the month detail page
            a_tag = doc_div.find("a", href=True)
            if not a_tag:
                continue
            month_url = urljoin(page_url, a_tag["href"])
            # Avoid processing the same month URL multiple times
            if month_url in seen_month_links:
                continue
            seen_month_links.add(month_url)
            # Collect all PDF links on the month page.  Use both the helper and fallback extraction.
            pdfs: List[Tuple[str, str]] = collect_pdf_links(month_url, pdf_include_pattern=None, use_cloud=False)
            # If no PDFs found via helper, parse the page and extract any anchor ending with .pdf
            if not pdfs:
                month_soup, _ = get_html(month_url)
                if month_soup is not None:
                    for link in month_soup.find_all("a", href=True):
                        href = link.get("href")
                        if not href:
                            continue
                        if href.lower().endswith(".pdf"):
                            pdf_url = urljoin(month_url, href)
                            link_text = normalize_text(link.get_text(" ", strip=True)) or a_tag.get_text(" ", strip=True)
                            pdfs.append((pdf_url, link_text))
            # Create a record for each PDF found
            for pdf_url, link_text in pdfs:
                rec = parse_detail_page(
                    university=university,
                    record_family="crime_log",
                    archive_url=base_url,
                    detail_url=pdf_url,
                    link_text=link_text,
                )
                if rec:
                    records.append(rec)
    return records


def scrape_washington_feed() -> List[Dict[str, str]]:
    """Scrape University of Washington crime notifications via the RSS feed.

    The RSS feed contains many posts from multiple categories.  We filter for
    items whose category contains "Crime Notifications" (case-insensitive) and
    parse each linked post.  Using the feed greatly increases coverage
    compared to scraping the HTML listing alone.
    """
    university = "University of Washington"
    feed_url = "https://police.uw.edu/feed/"
    records: List[Dict[str, str]] = []
    resp = polite_get(feed_url)
    if not resp:
        return records
    # Parse the RSS feed.  Try the default XML parser first.  If unavailable, fall back to lxml-xml or html.
    soup = None
    for parser in ["xml", "lxml-xml", "html.parser"]:
        try:
            soup = BeautifulSoup(resp.content, parser)  # type: ignore[arg-type]
            break
        except Exception:
            soup = None
    if soup is None:
        log("[ERROR] Failed to parse UW RSS feed: no suitable XML parser found")
        return records
    for item in soup.find_all("item"):
        title_tag = item.find("title")
        link_tag = item.find("link")
        if not title_tag or not link_tag:
            continue
        title = normalize_text(title_tag.get_text())
        detail_url = link_tag.get_text().strip()
        # Check categories
        categories = [normalize_text(cat.get_text()) for cat in item.find_all("category")]
        if not any("crime" in cat.lower() and "notification" in cat.lower() for cat in categories):
            continue
        # Use pubDate for date if available
        date = ""
        pubdate_tag = item.find("pubDate")
        if pubdate_tag:
            date = extract_date_from_text(pubdate_tag.get_text())
        rec = parse_detail_page(
            university=university,
            record_family="alert_notice",
            archive_url=feed_url,
            detail_url=detail_url,
            link_text=title,
        )
        if rec:
            # If feed provided a date, override the extracted date
            if date and not rec["date"]:
                rec["date"] = date
            records.append(rec)
    return records


def scrape_osu_alerts_enhanced() -> List[Dict[str, str]]:
    """Scrape Ohio State University public safety notices including paginated pages.

    In addition to using collect_paginated_pages on the base PSN page, this
    function explicitly enumerates numeric page parameters (?page=N) to ensure
    earlier posts are collected.  Posts are filtered to those under the /psn/
    path.
    """
    university = "Ohio State University"
    base_url = "https://dps.osu.edu/psn"
    records: List[Dict[str, str]] = []
    seen: set = set()
    # Include the base page and explicit numeric pages up to 9
    page_urls = [base_url] + [f"{base_url}?page={i}" for i in range(1, 10)]
    for page_url in page_urls:
        soup, _ = get_html(page_url)
        if soup is None:
            continue
        for a in soup.select("h2 a, h3 a, a"):
            href = a.get("href")
            if not href:
                continue
            detail_url = urljoin(page_url, href)
            # Skip anchor that resolves to the same page
            if detail_url.rstrip("/") == base_url.rstrip("/"):
                continue
            if detail_url in seen:
                continue
            # Accept only pages under the /psn/ path
            if "/psn/" not in detail_url:
                continue
            seen.add(detail_url)
            link_text = normalize_text(a.get_text(" ", strip=True))
            rec = parse_detail_page(
                university=university,
                record_family="alert_notice",
                archive_url=base_url,
                detail_url=detail_url,
                link_text=link_text,
            )
            if rec:
                records.append(rec)
    return records


def scrape_uf_alerts_extended() -> List[Dict[str, str]]:
    """Scrape University of Florida alerts from multiple campus pages.

    The UF Alert site hosts separate feeds for Gainesville, Systemwide, Jacksonville,
    Lake Nona, Shands, and UF Scripps.  This function iterates over all known
    alert feeds and uses the existing feed parsing logic.  It returns one
    record per alert segment.
    """
    university = "University of Florida"
    feed_pages = [
        "https://ufalert.ufl.edu/gainesville/",
        "https://ufalert.ufl.edu/systemwide/",
        "https://ufalert.ufl.edu/jacksonville/",
        "https://ufalert.ufl.edu/lake-nona/",
        "https://ufalert.ufl.edu/shands/",
        "https://ufalert.ufl.edu/uf-scripps/",
    ]
    records: List[Dict[str, str]] = []
    for archive_url in feed_pages:
        soup, _ = get_html(archive_url)
        if soup is None:
            continue
        page_text = normalize_multiline(soup.get_text("\n", strip=True))
        # Use the same splitting logic as the original UF scraper
        chunks = re.split(r"(?=(UF Alert|Campus Safety Message|Emergency Notification|Advisory))", page_text)
        rebuilt: List[str] = []
        i = 1
        while i < len(chunks):
            head = chunks[i].strip()
            body = chunks[i + 1] if i + 1 < len(chunks) else ""
            rebuilt.append((head + "\n" + body).strip())
            i += 2
        for chunk in rebuilt:
            lines = [line.strip() for line in chunk.splitlines() if line.strip()]
            if len(lines) < 2:
                continue
            title = lines[0][:250]
            date = extract_date_from_text(chunk)
            content = "\n".join(lines[:15])
            if len(content) >= MIN_CONTENT_CHARS:
                records.append(
                    make_record(
                        university=university,
                        record_family="alert_feed",
                        archive_url=archive_url,
                        source_url=archive_url,
                        source_type="html",
                        title=title,
                        date=date,
                        content=content,
                        link_text=title,
                    )
                )
    return records


def scrape_uf_summaries() -> List[Dict[str, str]]:
    """Scrape UF Alert annual summary PDF files from the annual summaries page."""
    university = "University of Florida"
    summary_page = "https://ufalert.ufl.edu/annual-summaries/"
    records: List[Dict[str, str]] = []
    links = collect_pdf_links(summary_page, pdf_include_pattern=r"UF Alert Summary", use_cloud=False)
    for pdf_url, link_text in links:
        rec = parse_detail_page(
            university=university,
            record_family="annual_report",
            archive_url=summary_page,
            detail_url=pdf_url,
            link_text=link_text,
        )
        if rec:
            records.append(rec)
    return records


def scrape_unc_feed() -> List[Dict[str, str]]:
    """Scrape UNC Chapel Hill alerts via the Alert Carolina RSS feed."""
    university = "UNC Chapel Hill"
    feed_url = "https://alertcarolina.unc.edu/feed/"
    records: List[Dict[str, str]] = []
    resp = polite_get(feed_url, use_cloud=True)
    if not resp:
        return records
    # Parse the RSS feed.  Try the default XML parser first.  If unavailable, fall back to lxml-xml or html.
    soup = None
    for parser in ["xml", "lxml-xml", "html.parser"]:
        try:
            soup = BeautifulSoup(resp.content, parser)  # type: ignore[arg-type]
            break
        except Exception:
            soup = None
    if soup is None:
        log("[ERROR] Failed to parse UNC RSS feed: no suitable XML parser found")
        return records
    for item in soup.find_all("item"):
        title_tag = item.find("title")
        link_tag = item.find("link")
        if not title_tag or not link_tag:
            continue
        title = normalize_text(title_tag.get_text())
        detail_url = link_tag.get_text().strip()
        # All categories are included; filter can be applied here if desired
        rec = parse_detail_page(
            university=university,
            record_family="alert_notice",
            archive_url=feed_url,
            detail_url=detail_url,
            link_text=title,
            use_cloud=True,
        )
        if rec:
            records.append(rec)
    return records


def scrape_asu_clery_notices() -> List[Dict[str, str]]:
    """Scrape ASU Clery Timely Warning notices by scanning the warning list page.

    The page sometimes contains links to individual timely warning posts with paths
    containing '/ctw-'.  We extract these links and parse each as an alert notice.
    If the page does not expose such links due to client-side rendering, this
    scraper may yield no results, but the fallback annual reports and logs
    continue to provide coverage.
    """
    university = "Arizona State University"
    list_url = "https://cfo.asu.edu/clery-timely-warning"
    records: List[Dict[str, str]] = []
    soup, _ = get_html(list_url)
    if soup is None:
        return records
    seen_links: set = set()
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href:
            continue
        detail_url = urljoin(list_url, href)
        if "/ctw-" not in detail_url:
            continue
        if detail_url in seen_links:
            continue
        seen_links.add(detail_url)
        title = normalize_text(a.get_text(" ", strip=True))
        rec = parse_detail_page(
            university=university,
            record_family="alert_notice",
            archive_url=list_url,
            detail_url=detail_url,
            link_text=title,
        )
        if rec:
            records.append(rec)
    return records


def scrape_berkeley_reports() -> List[Dict[str, str]]:
    """Scrape UC Berkeley annual security and fire safety reports from the chancellor's Clery pages.

    Berkeley does not maintain a publicly accessible archive of individual crime alerts similar to other
    universities.  We therefore collect the official annual security/fire safety reports from the
    Clery compliance resources pages.
    """
    university = "UC Berkeley"
    pages = [
        "https://chancellor.berkeley.edu/topics/clery-compliance",
        "https://chancellor.berkeley.edu/clery-act-compliance/clery-resources",
    ]
    records: List[Dict[str, str]] = []
    seen: set = set()
    for page_url in pages:
        links = collect_pdf_links(page_url, pdf_include_pattern=r"(annual security|fire safety|asfsr|clery|report)", use_cloud=False)
        for pdf_url, link_text in links:
            if pdf_url in seen:
                continue
            seen.add(pdf_url)
            rec = parse_detail_page(
                university=university,
                record_family="annual_report",
                archive_url=page_url,
                detail_url=pdf_url,
                link_text=link_text,
            )
            if rec:
                records.append(rec)
    return records


def scrape_washington_alerts() -> List[Dict[str, str]]:
    """Scrape University of Washington crime notifications from the police site."""
    university = "University of Washington"
    archive_url = "https://police.uw.edu/crime-notifications/"
    records: List[Dict[str, str]] = []
    seen: set = set()
    for page_url in collect_paginated_pages(archive_url):
        soup, _ = get_html(page_url)
        if soup is None:
            continue
        for h2 in soup.select("h2"):
            a = h2.find("a", href=True)
            if not a:
                continue
            detail_url = urljoin(page_url, a["href"])
            if detail_url in seen:
                continue
            seen.add(detail_url)
            link_text = normalize_text(a.get_text(" ", strip=True))
            rec = parse_detail_page(
                university=university,
                record_family="alert_notice",
                archive_url=archive_url,
                detail_url=detail_url,
                link_text=link_text,
            )
            if rec:
                records.append(rec)
    return records


def scrape_osu_alerts() -> List[Dict[str, str]]:
    """Scrape Ohio State University public safety notices from the DPS PSN page."""
    university = "Ohio State University"
    archive_url = "https://dps.osu.edu/psn"
    records: List[Dict[str, str]] = []
    seen: set = set()
    for page_url in collect_paginated_pages(archive_url):
        soup, _ = get_html(page_url)
        if soup is None:
            continue
        for a in soup.select("h2 a, h3 a, a"):
            href = a.get("href")
            if not href:
                continue
            detail_url = urljoin(page_url, href)
            if detail_url.rstrip("/") == archive_url.rstrip("/"):
                continue
            if detail_url in seen:
                continue
            # Accept only PSN article pages
            if "/psn/" not in detail_url:
                continue
            seen.add(detail_url)
            link_text = normalize_text(a.get_text(" ", strip=True))
            rec = parse_detail_page(
                university=university,
                record_family="alert_notice",
                archive_url=archive_url,
                detail_url=detail_url,
                link_text=link_text,
            )
            if rec:
                records.append(rec)
    return records


def scrape_uf_alerts() -> List[Dict[str, str]]:
    """Scrape University of Florida timely alerts from Gainesville/Systemwide alert feeds."""
    university = "University of Florida"
    feed_pages = [
        "https://ufalert.ufl.edu/gainesville/",
        "https://ufalert.ufl.edu/systemwide/",
    ]
    records: List[Dict[str, str]] = []
    for archive_url in feed_pages:
        soup, _ = get_html(archive_url)
        if soup is None:
            continue
        page_text = normalize_multiline(soup.get_text("\n", strip=True))
        # Split on distinct alert labels (UF Alert, Campus Safety Message, etc.) and rebuild segments
        chunks = re.split(r"(?=(UF Alert|Campus Safety Message|Emergency Notification|Advisory))", page_text)
        rebuilt: List[str] = []
        i = 1
        while i < len(chunks):
            head = chunks[i].strip()
            body = chunks[i + 1] if i + 1 < len(chunks) else ""
            rebuilt.append((head + "\n" + body).strip())
            i += 2
        for chunk in rebuilt:
            lines = [line.strip() for line in chunk.splitlines() if line.strip()]
            if len(lines) < 2:
                continue
            title = lines[0][:250]
            date = extract_date_from_text(chunk)
            content = "\n".join(lines[:15])
            if len(content) >= MIN_CONTENT_CHARS:
                records.append(
                    make_record(
                        university=university,
                        record_family="alert_feed",
                        archive_url=archive_url,
                        source_url=archive_url,
                        source_type="html",
                        title=title,
                        date=date,
                        content=content,
                        link_text=title,
                    )
                )
    return records


def scrape_penn_state_alerts() -> List[Dict[str, str]]:
    """Scrape Penn State timely warnings across campuses from the dedicated site."""
    university = "Penn State"
    # The index page lists all campus sub-sites, but each campus page uses simple numeric slugs.
    index_url = "https://timelywarnings.psu.edu/node/706"
    records: List[Dict[str, str]] = []
    campus_pages: List[str] = []
    soup, _ = get_html(index_url)
    if soup:
        for a in soup.find_all("a", href=True):
            href = urljoin(index_url, a["href"])
            if href.startswith("https://timelywarnings.psu.edu/") and href not in campus_pages:
                campus_pages.append(href)
    # Fallback to University Park if index fails
    if not campus_pages:
        campus_pages = ["https://timelywarnings.psu.edu/university-park"]
    seen: set = set()
    for archive_url in campus_pages:
        for page_url in collect_paginated_pages(archive_url):
            soup, _ = get_html(page_url)
            if soup is None:
                continue
            for a in soup.select("h2 a, h3 a, a"):
                href = a.get("href")
                if not href:
                    continue
                detail_url = urljoin(page_url, href)
                if detail_url in seen:
                    continue
                # Campus slug pattern: /campus-name/number
                if not re.search(r"/[a-z\-]+/\d", detail_url):
                    continue
                seen.add(detail_url)
                link_text = normalize_text(a.get_text(" ", strip=True))
                rec = parse_detail_page(
                    university=university,
                    record_family="alert_notice",
                    archive_url=archive_url,
                    detail_url=detail_url,
                    link_text=link_text,
                )
                if rec:
                    records.append(rec)
    return records


def scrape_ut_austin_alerts() -> List[Dict[str, str]]:
    """Scrape UT Austin crimefeed posts from the police site."""
    university = "UT Austin"
    archive_url = "https://police.utexas.edu/crimefeed"
    records: List[Dict[str, str]] = []
    seen: set = set()
    for page_url in collect_paginated_pages(archive_url):
        soup, _ = get_html(page_url)
        if soup is None:
            continue
        for a in soup.select("h2 a, h3 a, a"):
            href = a.get("href")
            if not href:
                continue
            detail_url = urljoin(page_url, href)
            if detail_url.rstrip("/") == archive_url.rstrip("/"):
                continue
            if detail_url in seen:
                continue
            # Accept only Crimefeed or relevant pages
            if "/crimefeed" not in detail_url and "/node/" not in detail_url:
                continue
            seen.add(detail_url)
            link_text = normalize_text(a.get_text(" ", strip=True))
            rec = parse_detail_page(
                university=university,
                record_family="alert_notice",
                archive_url=archive_url,
                detail_url=detail_url,
                link_text=link_text,
            )
            if rec:
                records.append(rec)
    return records


def scrape_ut_austin_reports() -> List[Dict[str, str]]:
    """Scrape UT Austin annual security and fire safety reports."""
    university = "UT Austin"
    page_url = "https://compliance.utexas.edu/asfsr"
    records: List[Dict[str, str]] = []
    links = collect_pdf_links(page_url, pdf_include_pattern=r"(annual security|fire safety|report)", use_cloud=False)
    for pdf_url, link_text in links:
        rec = parse_detail_page(
            university=university,
            record_family="annual_report",
            archive_url=page_url,
            detail_url=pdf_url,
            link_text=link_text,
        )
        if rec:
            records.append(rec)
    return records


def scrape_unc_alerts() -> List[Dict[str, str]]:
    """Scrape UNC Chapel Hill crime alerts from the Alert Carolina site.

    UNC uses Cloudflare on its site which may return 403 errors to normal requests.  When
    cloudscraper is available, we use it.  The function falls back to a normal request if
    cloudscraper is missing.
    """
    university = "UNC Chapel Hill"
    archive_url = "https://alertcarolina.unc.edu/notifications/category/crime/"
    records: List[Dict[str, str]] = []
    pages = collect_paginated_pages(archive_url, use_cloud=True)
    if archive_url not in pages:
        pages.insert(0, archive_url)
    seen: set = set()
    for page_url in pages:
        soup, _ = get_html(page_url, use_cloud=True)
        if soup is None:
            continue
        for a in soup.select("h2 a, h3 a, li a, a"):
            href = a.get("href")
            if not href:
                continue
            detail_url = urljoin(page_url, href)
            # Only follow detail pages (not categories)
            if "/category/" in detail_url:
                continue
            if "/notifications/" not in detail_url:
                continue
            if detail_url in seen:
                continue
            seen.add(detail_url)
            link_text = normalize_text(a.get_text(" ", strip=True))
            rec = parse_detail_page(
                university=university,
                record_family="alert_notice",
                archive_url=archive_url,
                detail_url=detail_url,
                link_text=link_text,
                use_cloud=True,
            )
            if rec:
                records.append(rec)
    return records


def scrape_uw_madison_alerts() -> List[Dict[str, str]]:
    """Scrape UW Madison incident reports and selected news events."""
    university = "UW Madison"
    base_urls = [
        "https://uwpd.wisc.edu/news-events/",
        "https://uwpd.wisc.edu/incident_report/",
    ]
    records: List[Dict[str, str]] = []
    seen: set = set()
    keyword_re = re.compile(
        r"(incident|crime|warning|alert|robbery|assault|burglary|theft|shooting|shots|battery|stalking|armed|weapon)",
        re.IGNORECASE,
    )
    for archive_url in base_urls:
        for page_url in collect_paginated_pages(archive_url):
            soup, _ = get_html(page_url)
            if soup is None:
                continue
            for a in soup.select("h2 a, h3 a, a"):
                href = a.get("href")
                if not href:
                    continue
                detail_url = urljoin(page_url, href)
                if detail_url in seen:
                    continue
                if not detail_url.startswith("https://uwpd.wisc.edu/"):
                    continue
                if detail_url.rstrip("/") == archive_url.rstrip("/"):
                    continue
                text = normalize_text(a.get_text(" ", strip=True))
                if not keyword_re.search(f"{detail_url} {text}"):
                    continue
                seen.add(detail_url)
                rec = parse_detail_page(
                    university=university,
                    record_family="alert_notice",
                    archive_url=archive_url,
                    detail_url=detail_url,
                    link_text=text,
                )
                if rec:
                    records.append(rec)
    return records


def scrape_asu_reports_and_logs() -> List[Dict[str, str]]:
    """Scrape Arizona State University annual security reports and crime logs."""
    university = "Arizona State University"
    records: List[Dict[str, str]] = []
    # Annual security and fire safety reports on the campus crime page
    annual_page = "https://cfo.asu.edu/campuscrime"
    annual_links = collect_pdf_links(annual_page, pdf_include_pattern=r"(annual security|fire safety|clery|report)")
    for pdf_url, link_text in annual_links:
        rec = parse_detail_page(
            university=university,
            record_family="annual_report",
            archive_url=annual_page,
            detail_url=pdf_url,
            link_text=link_text,
        )
        if rec:
            records.append(rec)
    # Crime and fire logs (recent) page – both HTML and linked PDFs
    log_page = "https://cfo.asu.edu/crime-logs"
    soup, _ = get_html(log_page)
    if soup:
        # HTML content summarising logs
        content = extract_main_text(soup)
        date = extract_date_from_soup(soup)
        if len(content) >= MIN_CONTENT_CHARS:
            records.append(
                make_record(
                    university=university,
                    record_family="crime_log",
                    archive_url=log_page,
                    source_url=log_page,
                    source_type="html",
                    title="ASU Crime and Fire Logs",
                    date=date,
                    content=content,
                    link_text="Crime and Fire Logs",
                )
            )
        # PDF logs
        log_links = collect_pdf_links(log_page, pdf_include_pattern=r"(crime|fire|log)")
        for pdf_url, link_text in log_links:
            rec = parse_detail_page(
                university=university,
                record_family="crime_log",
                archive_url=log_page,
                detail_url=pdf_url,
                link_text=link_text,
            )
            if rec:
                records.append(rec)
    return records


# -----------------------------------------------------------------------------
# Utility to collect PDF links from a page
# -----------------------------------------------------------------------------

def collect_pdf_links(page_url: str, pdf_include_pattern: Optional[str] = None, use_cloud: bool = False) -> List[Tuple[str, str]]:
    """Collect PDF links on a page that match an optional regex pattern."""
    found: List[Tuple[str, str]] = []
    soup, _ = get_html(page_url, use_cloud=use_cloud)
    if soup is None:
        return found
    for a in soup.find_all("a", href=True):
        href = urljoin(page_url, a.get("href"))
        text = normalize_text(a.get_text(" ", strip=True))
        combined = f"{href} {text}"
        if href.lower().endswith(".pdf"):
            if pdf_include_pattern is None or re.search(pdf_include_pattern, combined, re.IGNORECASE):
                found.append((href, text))
    # Deduplicate by URL while preserving order
    out: List[Tuple[str, str]] = []
    seen: set = set()
    for url, text in found:
        if url not in seen:
            seen.add(url)
            out.append((url, text))
    return out


# -----------------------------------------------------------------------------
# Master list of scraper functions
# -----------------------------------------------------------------------------

SCRAPERS: Sequence[Callable[[], List[Dict[str, str]]]] = [
    # UMass: feed, annual reports, and monthly crime logs
    scrape_umass_alerts,
    scrape_umass_reports,
    scrape_umass_crime_logs,
    # Berkeley: annual security/fire safety reports (no public alert archive)
    scrape_berkeley_reports,
    # University of Washington: HTML list and RSS feed
    scrape_washington_alerts,
    scrape_washington_feed,
    # Ohio State: enhanced pagination to capture older notices
    scrape_osu_alerts_enhanced,
    # UF: extended categories and annual summaries
    scrape_uf_alerts_extended,
    scrape_uf_summaries,
    # Penn State: campus-specific timely warnings
    scrape_penn_state_alerts,
    # UT Austin: crimefeed and annual reports
    scrape_ut_austin_alerts,
    scrape_ut_austin_reports,
    # UNC: HTML pages and RSS feed
    scrape_unc_alerts,
    scrape_unc_feed,
    # UW Madison: news and incident reports
    scrape_uw_madison_alerts,
    # ASU: annual reports/logs and Clery timely warning posts
    scrape_asu_reports_and_logs,
    scrape_asu_clery_notices,
]


def write_csv(records: Sequence[Dict[str, str]], filename: str) -> None:
    """Write a list of record dictionaries to a CSV file."""
    fieldnames = [
        "university",
        "record_family",
        "archive_url",
        "source_url",
        "source_type",
        "link_text",
        "title",
        "date",
        "incident_type",
        "location",
        "content",
        "content_length",
        "content_hash",
        "scrape_timestamp_utc",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in records:
            writer.writerow(row)


def main() -> None:
    log("Starting scrape")
    all_records: List[Dict[str, str]] = []
    for scraper in SCRAPERS:
        try:
            log(f"\n===== RUNNING {scraper.__name__} =====")
            rows = scraper()
            log(f"[OK] {scraper.__name__}: {len(rows)} rows")
            all_records.extend(rows)
        except Exception as exc:
            log(f"[FATAL] {scraper.__name__} failed: {exc}")
    all_records = dedupe_records(all_records)
    write_csv(all_records, OUTPUT_FILE)
    log(f"Finished. {len(all_records)} records written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()