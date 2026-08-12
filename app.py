import os
import tkinter as tk
from tkinter import messagebox, ttk

from dotenv import load_dotenv

from builders.report_builder import build_html_data
from core.investigator import investigate
from exporters.report_exporter import export_report

from presenters.console_report import (
    DOMAIN_LABELS,
    HASH_LABELS,
    IP_LABELS,
    URL_LABELS,
)


def main():
    load_dotenv()

    vt_api_key = os.getenv("VT_API_KEY")
    abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")

    root = tk.Tk()
    root.title("IOC Investigation Toolkit")
    root.geometry("900x600")

    main_frame = ttk.Frame(
        root,
        padding=30,
    )
    main_frame.pack(
        fill="both",
        expand=True,
    )

    current_result = {
        "report": None,
        "ioc_type": None,
        "labels": None,
    }

    title_label = ttk.Label(
        main_frame,
        text="IOC Investigation Toolkit",
        font=("Arial", 24, "bold"),
    )
    title_label.pack(
        anchor="w",
        pady=(0, 25),
    )

    input_label = ttk.Label(
        main_frame,
        text="IOC",
        font=("Arial", 12, "bold"),
    )
    input_label.pack(
        anchor="w",
        pady=(0, 6),
    )

    ioc_entry = ttk.Entry(
        main_frame,
        font=("Arial", 14),
    )
    ioc_entry.pack(
        fill="x",
        pady=(0, 12),
    )

    result_frame = ttk.LabelFrame(
        main_frame,
        text="Investigation Result",
        padding=15,
    )

    result_text = tk.Text(
        result_frame,
        font=("Menlo", 12),
        wrap="word",
        state="disabled",
    )

    def run_investigation():
        ioc_value = ioc_entry.get().strip()

        if not ioc_value:
            messagebox.showerror(
                "Error",
                "Please enter an IOC.",
            )
            return

        result = investigate(
            ioc_value,
            vt_api_key,
            abuse_api_key,
        )

        if result.report is None:
            messagebox.showerror(
                "Investigation failed",
                ("Could not investigate IOC " f"type: {result.ioc_type}"),
            )
            return

        if result.ioc_type == "IP":
            labels = IP_LABELS

        elif result.ioc_type == "DOMAIN":
            labels = DOMAIN_LABELS

        elif result.ioc_type == "URL":
            labels = URL_LABELS

        elif result.ioc_type in {
            "MD5",
            "SHA1",
            "SHA256",
        }:
            labels = HASH_LABELS

        else:
            messagebox.showerror(
                "Error",
                f"Unsupported IOC type: {result.ioc_type}",
            )
            return

        current_result["report"] = result.report
        current_result["ioc_type"] = result.ioc_type
        current_result["labels"] = labels

        report_data = build_html_data(
            result.report,
            labels,
        )

        result_text.config(
            state="normal",
        )

        result_text.delete(
            "1.0",
            tk.END,
        )

        result_text.insert(
            tk.END,
            f"IOC Type: {result.ioc_type}\n\n",
        )

        for label, value in report_data.items():
            if isinstance(value, list):
                value = ", ".join(str(item) for item in value) or "N/A"

            result_text.insert(
                tk.END,
                f"{label:18}: {value}\n",
            )

        result_text.config(
            state="disabled",
        )

    def export_html():
        if current_result["report"] is None:
            messagebox.showerror(
                "Error",
                "No investigation result to export.",
            )
            return

        try:
            file_path = export_report(
                current_result["report"],
                current_result["ioc_type"],
                current_result["labels"],
                "html",
            )

        except (ValueError, OSError) as error:
            messagebox.showerror(
                "Export failed",
                str(error),
            )
            return

        messagebox.showinfo(
            "Export complete",
            f"HTML report exported:\n{file_path}",
        )

    def export_pdf():
        if current_result["report"] is None:
            messagebox.showerror(
                "Error",
                "No investigation result to export.",
            )
            return

        try:
            file_path = export_report(
                current_result["report"],
                current_result["ioc_type"],
                current_result["labels"],
                "pdf",
            )

        except (ValueError, OSError) as error:
            messagebox.showerror(
                "Export failed",
                str(error),
            )
            return

        messagebox.showinfo(
            "Export complete",
            f"PDF report exported:\n{file_path}",
        )

    investigate_button = ttk.Button(
        main_frame,
        text="Investigate",
        command=run_investigation,
    )
    investigate_button.pack(
        anchor="w",
    )

    export_frame = ttk.Frame(
        main_frame,
    )
    export_frame.pack(
        anchor="w",
        pady=(12, 0),
    )

    html_button = ttk.Button(
        export_frame,
        text="Export HTML",
        command=export_html,
    )
    html_button.pack(
        side="left",
        padx=(0, 10),
    )

    pdf_button = ttk.Button(
        export_frame,
        text="Export PDF",
        command=export_pdf,
    )
    pdf_button.pack(
        side="left",
    )

    result_frame.pack(
        fill="both",
        expand=True,
        pady=(25, 0),
    )

    result_text.pack(
        fill="both",
        expand=True,
    )

    root.mainloop()


if __name__ == "__main__":
    main()
