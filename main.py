import csv
import html
import io
import json
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

FEED_URL = "https://threatfox.abuse.ch/export/csv/recent/"

COLUMNS = [
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
        FEED_URL,
        headers={"User-Agent": "OpenThreatRadar/0.1"},
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read().decode("utf-8", errors="replace")

    data_lines = [
        line for line in content.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    records = []

    for row in csv.reader(io.StringIO("\n".join(data_lines))):
        values = [value.strip() for value in row]

        if len(values) != len(COLUMNS):
            continue

        record = dict(zip(COLUMNS, values))

        try:
            record["confidence"] = int(record["confidence"])
        except ValueError:
            record["confidence"] = 0

        records.append(record)

    return records


def safe(value):
    return html.escape(str(value or "Unknown"))


def create_dashboard(records):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    malware_counts = Counter(
        item["malware"] for item in records
        if item["malware"] not in ("", "None", "Unknown malware")
    )

    type_counts = Counter(item["threat_type"] for item in records)
    high_confidence = sum(item["confidence"] >= 75 for item in records)

    malware_cards = "".join(
        f"<span class='tag'>{safe(name)} · {count}</span>"
        for name, count in malware_counts.most_common(8)
    ) or "<span class='muted'>No named malware found</span>"

    type_cards = "".join(
        f"<span class='tag'>{safe(name)} · {count}</span>"
        for name, count in type_counts.most_common(6)
    )

    table_rows = ""

    for item in records[:250]:
        table_rows += f"""
        <tr>
            <td>{safe(item["first_seen"])}</td>
            <td><code>{safe(item["ioc_value"])}</code></td>
            <td>{safe(item["ioc_type"])}</td>
            <td>{safe(item["malware"])}</td>
            <td>{safe(item["threat_type"])}</td>
            <td><span class="confidence">{item["confidence"]}%</span></td>
        </tr>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Open Threat Radar</title>
    <style>
        :root {{
            color-scheme: dark;
            --background: #0b1020;
            --panel: #121a2e;
            --border: #263451;
            --text: #e7edf8;
            --muted: #93a4bf;
            --accent: #42d3a4;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            margin: 0;
            background: var(--background);
            color: var(--text);
            font-family: Inter, system-ui, sans-serif;
        }}

        main {{
            width: min(1400px, 94%);
            margin: 40px auto;
        }}

        h1 {{ margin-bottom: 4px; }}
        h2 {{ margin-top: 0; }}
        .muted {{ color: var(--muted); }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 28px 0;
        }}

        .card, .panel {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}

        .number {{
            display: block;
            margin-top: 6px;
            color: var(--accent);
            font-size: 30px;
            font-weight: 700;
        }}

        .tag {{
            display: inline-block;
            margin: 4px;
            padding: 7px 10px;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: #18243d;
        }}

        .table-wrapper {{
            overflow-x: auto;
            margin-top: 16px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
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
            font-weight: 600;
        }}

        a {{ color: var(--accent); }}
    </style>
</head>
<body>
<main>
    <h1>Open Threat Radar</h1>
    <div class="muted">Last updated: {generated_at}</div>

    <section class="cards">
        <div class="card">
            Recent indicators
            <span class="number">{len(records)}</span>
        </div>
        <div class="card">
            High confidence
            <span class="number">{high_confidence}</span>
        </div>
        <div class="card">
            Malware families
            <span class="number">{len(malware_counts)}</span>
        </div>
    </section>

    <section class="panel">
        <h2>Malware pulse</h2>
        {malware_cards}
    </section>

    <section class="panel" style="margin-top:16px">
        <h2>Threat activity</h2>
        {type_cards}
    </section>

    <section class="panel" style="margin-top:16px">
        <h2>Recent indicators</h2>
        <p class="muted">
            Indicators are unverified external intelligence and should not
            be treated as automatic blocking recommendations.
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
                    {table_rows}
                </tbody>
            </table>
        </div>
    </section>

    <p class="muted">
        Source:
        <a href="https://threatfox.abuse.ch/" target="_blank"
           rel="noopener noreferrer">ThreatFox by abuse.ch</a>
    </p>
</main>
</body>
</html>
"""


def main():
    records = fetch_threatfox()

    output_directory = Path("docs")
    output_directory.mkdir(exist_ok=True)

    (output_directory / "data.json").write_text(
        json.dumps(records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    (output_directory / "index.html").write_text(
        create_dashboard(records),
        encoding="utf-8",
    )

    print(f"Dashboard generated with {len(records)} indicators.")


if __name__ == "__main__":
    main()
