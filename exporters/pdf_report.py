from datetime import datetime, timezone
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def export_pdf_report(
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

    file_path = output_path / f"ioc_report_{timestamp}.pdf"

    document = SimpleDocTemplate(
        str(file_path),
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            f"<b>{escape(str(title))}</b>",
            styles["Title"],
        )
    )

    story.append(Spacer(1, 12))

    metadata = [
        ["Generated", generated_at],
        ["IOC Type", str(ioc_type)],
        ["Sources", ", ".join(str(source) for source in sources)],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[
            document.width * 0.28,
            document.width * 0.72,
        ],
        hAlign="LEFT",
    )

    metadata_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.whitesmoke,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(metadata_table)
    story.append(Spacer(1, 18))

    label_style = ParagraphStyle(
        name="LabelCell",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        wordWrap="CJK",
        splitLongWords=True,
    )

    value_style = ParagraphStyle(
        name="ValueCell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        wordWrap="CJK",
        splitLongWords=True,
    )

    rows = []

    for label, value in report_data.items():
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value) or "N/A"

        if value is None:
            value = "N/A"

        rows.append(
            [
                Paragraph(
                    escape(str(label)),
                    label_style,
                ),
                Paragraph(
                    escape(str(value)),
                    value_style,
                ),
            ]
        )

    report_table = Table(
        rows,
        colWidths=[
            document.width * 0.32,
            document.width * 0.68,
        ],
        hAlign="LEFT",
    )

    report_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#eaf0f6"),
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(report_table)

    document.build(story)

    return file_path
