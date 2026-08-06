from datetime import datetime, timezone
from html import escape
from pathlib import Path


def export_html_report(
    title,
    ioc_type,
    sources,
    report_data,
    output_directory="reports",
):
    output_path = Path(output_directory)
    output_path.mkdir(exist_ok=True)

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")

    file_path = output_path / f"ioc_report_{timestamp}.html"

    if isinstance(sources, (list, tuple, set)):
        source_text = ", ".join(str(source) for source in sources)
    else:
        source_text = str(sources)

    rows = []

    for label, value in report_data.items():
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value) or "N/A"

        if value is None:
            value = "N/A"

        rows.append(
            "<tr>"
            f"<th>{escape(str(label))}</th>"
            f"<td>{escape(str(value))}</td>"
            "</tr>"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape(title)}</title>

    <style>
        body {{
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
            font-family: Arial, sans-serif;
            color: #222;
            background: #f5f5f5;
        }}

        .header {{
            margin-bottom: 24px;
        }}

        h1 {{
            margin-bottom: 12px;
            color: #1f3a5f;
        }}

        .metadata {{
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 8px 16px;
            padding: 16px;
            background: #eaf0f6;
            border: 1px solid #d5dee8;
            border-radius: 6px;
        }}

        .metadata-label {{
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th,
        td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            width: 220px;
            background: #eaf0f6;
        }}
    </style>
</head>

<body>
    <div class="header">
        <h1>{escape(title)}</h1>

        <div class="metadata">
            <div class="metadata-label">Generated</div>
            <div>{escape(generated_at)}</div>

            <div class="metadata-label">IOC Type</div>
            <div>{escape(str(ioc_type))}</div>

            <div class="metadata-label">Sources</div>
            <div>{escape(source_text)}</div>
        </div>
    </div>

    <table>
        {"".join(rows)}
    </table>
</body>
</html>
"""

    file_path.write_text(
        html_content,
        encoding="utf-8",
    )

    return file_path
