import html
import json
import os
import smtplib
import ssl
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo


DASHBOARD_URL = "https://dreameaterz120.github.io/Open-threat-radar/"
AMSTERDAM = ZoneInfo("Europe/Amsterdam")


def safe(value):
    return html.escape(str(value or "Unknown"))


def safe_link(value):
    value = str(value or "").strip()
    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https"):
        return "#"

    return html.escape(value, quote=True)


def parse_first_seen(value):
    try:
        return datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def load_radar_data():
    return json.loads(
        Path("docs/data.json").read_text(encoding="utf-8")
    )


def build_email(data):
    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone(AMSTERDAM)
    cutoff = now_utc - timedelta(hours=26)

    articles = [
        article
        for article in data.get("research", [])
        if article.get("timestamp", 0) >= cutoff.timestamp()
    ]

    indicators = data.get("indicators", [])
    new_indicators = []

    for indicator in indicators:
        first_seen = parse_first_seen(
            indicator.get("first_seen")
        )

        if first_seen and first_seen >= cutoff:
            new_indicators.append(indicator)

    high_confidence = sum(
        int(indicator.get("confidence", 0)) >= 75
        for indicator in new_indicators
    )

    malware_counts = Counter(
        indicator.get("malware")
        for indicator in new_indicators
        if indicator.get("malware")
        not in (
            None,
            "",
            "None",
            "Unknown malware",
        )
    )

    article_html = ""

    for article in articles[:10]:
        article_html += f"""
        <div class="report">
            <div class="source">
                {safe(article.get("source"))}
            </div>

            <h3>
                <a href="{safe_link(article.get("link"))}">
                    {safe(article.get("title"))}
                </a>
            </h3>

            <p>
                {safe(article.get("summary"))}
            </p>
        </div>
        """

    if not article_html:
        article_html = (
            "<p>No new research reports were published "
            "during the last 26 hours.</p>"
        )

    malware_html = "".join(
        f"<span class='tag'>{safe(name)} · {count}</span>"
        for name, count in malware_counts.most_common(8)
    ) or "<span class='muted'>No named malware observed.</span>"

    subject = (
        f"Open Threat Radar — {len(articles)} new reports — "
        f"{now_local:%d-%m-%Y}"
    )

    body = f"""<!doctype html>
<html>
<head>
    <meta charset="utf-8">

    <style>
        body {{
            margin: 0;
            background: #090e1a;
            color: #e8eef8;
            font-family: Arial, sans-serif;
        }}

        .container {{
            width: 92%;
            max-width: 780px;
            margin: 0 auto;
            padding: 30px 0;
        }}

        .muted {{
            color: #96a7c1;
        }}

        .stats {{
            display: table;
            width: 100%;
            margin: 24px 0;
        }}

        .stat {{
            display: table-cell;
            width: 33%;
            padding: 16px;
            background: #111a2d;
            border: 1px solid #263754;
        }}

        .number {{
            display: block;
            margin-top: 6px;
            color: #43d6a5;
            font-size: 26px;
            font-weight: bold;
        }}

        .report {{
            margin: 12px 0;
            padding: 17px;
            background: #111a2d;
            border: 1px solid #263754;
            border-radius: 10px;
        }}

        .report h3 {{
            margin: 7px 0;
        }}

        .report p {{
            color: #bec9da;
            line-height: 1.5;
        }}

        .source {{
            color: #43d6a5;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}

        a {{
            color: #e8eef8;
        }}

        .tag {{
            display: inline-block;
            margin: 4px;
            padding: 7px 10px;
            background: #16223a;
            border: 1px solid #263754;
            border-radius: 20px;
        }}

        .button {{
            display: inline-block;
            margin-top: 22px;
            padding: 12px 18px;
            background: #43d6a5;
            color: #07110e;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
        }}
    </style>
</head>

<body>
    <div class="container">
        <h1>Open Threat Radar</h1>

        <p class="muted">
            Daily briefing for {now_local:%A %d %B %Y}
        </p>

        <div class="stats">
            <div class="stat">
                New reports
                <span class="number">
                    {len(articles)}
                </span>
            </div>

            <div class="stat">
                New indicators
                <span class="number">
                    {len(new_indicators)}
                </span>
            </div>

            <div class="stat">
                High confidence
                <span class="number">
                    {high_confidence}
                </span>
            </div>
        </div>

        <h2>New threat research</h2>

        {article_html}

        <h2>Malware pulse</h2>

        <div>
            {malware_html}
        </div>

        <a class="button" href="{DASHBOARD_URL}">
            Open full radar
        </a>

        <p
            class="muted"
            style="margin-top:24px;font-size:12px;"
        >
            This automated briefing uses public external
            intelligence. Indicators must be validated
            independently before use.
        </p>
    </div>
</body>
</html>
"""

    return subject, body


def send_email(subject, html_body):
    email_user = os.environ.get("EMAIL_USER")
    email_password = os.environ.get("EMAIL_PASSWORD")
    email_to = os.environ.get("EMAIL_TO")

    if not email_user or not email_password or not email_to:
        raise RuntimeError(
            "EMAIL_USER, EMAIL_PASSWORD and EMAIL_TO are required."
        )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = email_user
    message["To"] = email_to

    message.set_content(
        "Your Open Threat Radar daily briefing is available at "
        f"{DASHBOARD_URL}"
    )

    message.add_alternative(
        html_body,
        subtype="html",
    )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
    ) as server:
        server.login(
            email_user,
            email_password,
        )

        server.send_message(message)


def main():
    local_now = datetime.now(AMSTERDAM)
    event_name = os.environ.get(
        "GITHUB_EVENT_NAME",
        "manual",
    )

    if event_name == "schedule" and local_now.hour != 8:
        print(
            f"Skipping: it is currently {local_now:%H:%M} "
            "in Europe/Amsterdam."
        )
        return

    data = load_radar_data()
    subject, html_body = build_email(data)

    send_email(
        subject,
        html_body,
    )

    print(
        "Daily threat radar email sent successfully."
    )


if __name__ == "__main__":
    main()
