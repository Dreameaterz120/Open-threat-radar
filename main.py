import calendar
import csv
import html
import io
import json
import re
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import feedparser


THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/recent/"

THREATFOX_COLUMNS = [
    "first_seen",
    "ioc_id",
    "ioc_value",
    "ioc_type",
    "threat_type",
    "malware_id",
    "malware_alias",
    "malware",
    "last_seen",
    "confidence",
    "is_compromised",
    "reference",
    "tags",
    "anonymous",
    "reporter",
]


def fetch_threatfox():
    request = urllib.request.Request(
        THREATFOX_URL,
        headers={"User-Agent": "OpenThreatRadar/0.2"},
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read().decode("utf-8", errors="replace")

    data_lines = [
        line
        for line in content.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    records = []

    for row in csv.reader(
        io.StringIO("\n".join(data_lines)),
        skipinitialspace=True,
    ):
        values = [value.strip() for value in row]

        if len(values) != len(THREATFOX_COLUMNS):
            continue

        record = dict(zip(THREATFOX_COLUMNS, values))

        try:
            record["confidence"] = int(record["confidence"])
        except ValueError:
            record["confidence"] = 0

        records.append(record)

    return records


def clean_summary(value):
    value = html.unescape(str(value or ""))
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip()

    if len(value) > 360:
        value = value[:357].rstrip() + "..."

    return value


def fetch_research_feeds():
    configuration = json.loads(
        Path("sources.json").read_text(encoding="utf-8")
    )

    articles = []
    errors = []
    seen = set()

    for source in configuration.get("research_feeds", []):
        source_name = source["name"]

        try:
            parsed = feedparser.parse(
                source["url"],
                request_headers={"User-Agent": "OpenThreatRadar/0.2"},
            )

            if not parsed.entries:
                errors.append(f"{source_name}: no entries returned")
                continue

            for entry in parsed.entries[:10]:
                title = str(
                    entry.get("title", "Untitled report")
                ).strip()

                link = str(entry.get("link", "")).strip()
                unique_key = link or f"{source_name}:{title}"

                if unique_key in seen:
                    continue

                seen.add(unique_key)

                published = (
                    entry.get("published")
                    or entry.get("updated")
                    or "Publication date unavailable"
                )

                parsed_date = (
                    entry.get("published_parsed")
                    or entry.get("updated_parsed")
                )

                timestamp = (
                    calendar.timegm(parsed_date)
                    if parsed_date
                    else 0
                )

                articles.append(
                    {
                        "title": title,
                        "link": link,
                        "published": published,
                        "timestamp": timestamp,
                        "summary": clean_summary(
                            entry.get("summary")
                            or entry.get("description")
                        ),
                        "source": source_name,
                        "category": source.get(
                            "category",
                            "Threat research",
                        ),
                    }
                )

        except Exception as error:
            errors.append(f"{source_name}: {error}")

    articles.sort(
        key=lambda article: article["timestamp"],
        reverse=True,
    )

    return articles, errors


def safe(value):
    return html.escape(str(value or "Unknown"))


def safe_link(value):
    value = str(value or "").strip()
    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return "#"

    return html.escape(value, quote=True)


def create_dashboard(indicators, articles, feed_errors):
    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    malware_counts = Counter(
        item["malware"]
        for item in indicators
        if item["malware"] not in (
            "",
            "None",
            "Unknown malware",
        )
    )

    threat_counts = Counter(
        item["threat_type"]
        for item in indicators
    )

    high_confidence = sum(
        item["confidence"] >= 75
        for item in indicators
    )

    active_sources = len(
        {article["source"] for article in articles}
    )

    malware_tags = "".join(
        f"<span class='tag'>{safe(name)} · {count}</span>"
        for name, count in malware_counts.most_common(10)
    ) or "<span class='muted'>No named malware found</span>"

    threat_tags = "".join(
        f"<span class='tag'>{safe(name)} · {count}</span>"
        for name, count in threat_counts.most_common(8)
    )

    article_cards = ""

    for article in articles[:50]:
        summary = (
            safe(article["summary"])
            if article["summary"]
            else "No summary supplied by this feed."
        )

        article_cards += f"""
        <article class="report">
            <div class="report-meta">
                <span class="source">
                    {safe(article["source"])}
                </span>
                <span>
                    {safe(article["category"])}
                </span>
            </div>

            <h3>
                <a href="{safe_link(article["link"])}"
                   target="_blank"
                   rel="noopener noreferrer">
                    {safe(article["title"])}
                </a>
            </h3>

            <p>{summary}</p>

            <div class="published">
                {safe(article["published"])}
            </div>
        </article>
        """

    if not article_cards:
        article_cards = """
        <p class="muted">
            No threat-research articles were returned.
        </p>
        """

    indicator_rows = ""

    for item in indicators[:250]:
        indicator_rows += f"""
        <tr>
            <td>{safe(item["first_seen"])}</td>
            <td>
                <code>{safe(item["ioc_value"])}</code>
            </td>
            <td>{safe(item["ioc_type"])}</td>
            <td>{safe(item["malware"])}</td>
            <td>{safe(item["threat_type"])}</td>
            <td>
                <span class="confidence">
                    {item["confidence"]}%
                </span>
            </td>
        </tr>
        """

    error_panel = ""

    if feed_errors:
        error_items = "".join(
            f"<li>{safe(error)}</li>"
            for error in feed_errors
        )

        error_panel = f"""
        <details class="panel errors">
            <summary>
                Feed warnings ({len(feed_errors)})
            </summary>
            <ul>{error_items}</ul>
        </details>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <meta
        name="description"
        content="An automated overview of public threat intelligence"
    >

    <title>Open Threat Radar</title>

    <style>
        :root {{
            color-scheme: dark;
            --background: #090e1a;
            --panel: #111a2d;
            --panel-light: #16223a;
            --border: #263754;
            --text: #e8eef8;
            --muted: #96a7c1;
            --accent: #43d6a5;
            --warning: #f4bd62;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background:
                radial-gradient(
                    circle at top right,
                    #13233d 0,
                    transparent 32%
                ),
                var(--background);
            color: var(--text);
            font-family:
                Inter,
                ui-sans-serif,
                system-ui,
                sans-serif;
        }}

        main {{
            width: min(1440px, 94%);
            margin: 42px auto 70px;
        }}

        h1 {{
            margin-bottom: 5px;
            font-size: clamp(30px, 5vw, 48px);
        }}

        h2 {{
            margin-top: 0;
        }}

        h3 {{
            margin: 12px 0 8px;
            line-height: 1.35;
        }}

        a {{
            color: var(--text);
            text-decoration: none;
        }}

        a:hover {{
            color: var(--accent);
        }}

        .muted,
        .published {{
            color: var(--muted);
        }}

        .intro {{
            max-width: 760px;
            line-height: 1.6;
        }}

        .cards {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(190px, 1fr));
            gap: 16px;
            margin: 30px 0;
        }}

        .card,
        .panel {{
            background: rgba(17, 26, 45, 0.94);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
        }}

        .number {{
            display: block;
            margin-top: 6px;
            color: var(--accent);
            font-size: 30px;
            font-weight: 750;
        }}

        .section-heading {{
            margin-top: 42px;
            margin-bottom: 16px;
        }}

        .reports {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(310px, 1fr));
            gap: 16px;
        }}

        .report {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 19px;
        }}

        .report p {{
            color: #bec9da;
            line-height: 1.55;
        }}

        .report-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .source {{
            color: var(--accent);
            font-weight: 700;
        }}

        .published {{
            margin-top: 15px;
            font-size: 13px;
        }}

        .tag {{
            display: inline-block;
            margin: 4px;
            padding: 7px 10px;
            background: var(--panel-light);
            border: 1px solid var(--border);
            border-radius: 999px;
        }}

        .table-wrapper {{
            overflow-x: auto;
            margin-top: 16px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th,
        td {{
            padding: 12px;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
        }}

        th {{
            color: var(--muted);
            font-size: 13px;
        }}

        code {{
            color: #ffcc7a;
            word-break: break-all;
        }}

        .confidence {{
            color: var(--accent);
            font-weight: 650;
        }}

        .errors {{
            margin-top: 18px;
            color: var(--warning);
        }}

        footer {{
            margin-top: 30px;
            color: var(--muted);
            font-size: 13px;
            line-height: 1.6;
        }}
    </style>
</head>

<body>
<main>
    <header>
        <h1>Open Threat Radar</h1>

        <div class="muted">
            Last updated: {generated_at}
        </div>

        <p class="intro muted">
            Automated overview of publicly available threat
            research, malware activity and technical indicators.
            External intelligence must be independently validated
            before use.
        </p>
    </header>

    <section class="cards">
        <div class="card">
            Research reports
            <span class="number">
                {len(articles)}
            </span>
        </div>

        <div class="card">
            Active research sources
            <span class="number">
                {active_sources}
            </span>
        </div>

        <div class="card">
            Recent indicators
            <span class="number">
                {len(indicators)}
            </span>
        </div>

        <div class="card">
            High-confidence IOCs
            <span class="number">
                {high_confidence}
            </span>
        </div>
    </section>

    {error_panel}

    <h2 class="section-heading">
        Threat-research radar
    </h2>

    <section class="reports">
        {article_cards}
    </section>

    <h2 class="section-heading">
        Malware pulse
    </h2>

    <section class="panel">
        {malware_tags}
    </section>

    <h2 class="section-heading">
        Technical activity
    </h2>

    <section class="panel">
        {threat_tags}
    </section>

    <h2 class="section-heading">
        Recent indicators
    </h2>

    <section class="panel">
        <p class="muted">
            Indicators originate from public external intelligence.
            Presence on this page is not an automatic blocking
            recommendation.
        </p>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>First seen</th>
                        <th>Indicator</th>
                        <th>Type</th>
                        <th>Malware</th>
                        <th>Activity</th>
                        <th>Confidence</th>
                    </tr>
                </thead>

                <tbody>
                    {indicator_rows}
                </tbody>
            </table>
        </div>
    </section>

    <footer>
        Research content remains with its original publishers.
        This radar displays metadata, short feed excerpts and links
        to the original sources. Technical indicators are supplied
        by ThreatFox, operated by abuse.ch.
    </footer>
</main>
</body>
</html>
"""


def main():
    indicators = fetch_threatfox()
    articles, feed_errors = fetch_research_feeds()

    output_directory = Path("docs")
    output_directory.mkdir(exist_ok=True)

    radar_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "research": articles,
        "indicators": indicators,
        "feed_errors": feed_errors,
    }

    (output_directory / "data.json").write_text(
        json.dumps(
            radar_data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    (output_directory / "index.html").write_text(
        create_dashboard(
            indicators,
            articles,
            feed_errors,
        ),
        encoding="utf-8",
    )

    print(
        f"Dashboard generated with {len(articles)} reports "
        f"and {len(indicators)} indicators."
    )

    if feed_errors:
        print("Feed warnings:")

        for error in feed_errors:
            print(f"- {error}")


if __name__ == "__main__":
    main()
