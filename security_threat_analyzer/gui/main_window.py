# ============================================================
# main_window.py — Main Application Window
# Sab modules ko jodta hai aur GUI launch karta hai
# ============================================================

import tkinter as tk
from tkinter import messagebox, filedialog
import threading

from gui.input_panel import InputPanel
from gui.results_panel import ResultsPanel
from modules.stride.stride_analyzer import StrideAnalyzer
from modules.dread.dread_scorer import DreadScorer
from modules.cve.cve_lookup import CveLookup
from modules.report.report_generator import ReportGenerator
from modules.report.pdf_exporter import PdfExporter


class MainWindow:
    """
    Main application window.
    Sab modules ko connect karta hai aur
    user interactions handle karta hai.
    """

    def __init__(self):
        # Main window setup
        self.root = tk.Tk()
        self.root.title("Security Threat Analyzer — Riphah University")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        self.root.configure(bg="#1a1a2e")

        # Custom Shield Lock Icon
        icon_image = self._create_shield_icon()
        self.root.iconphoto(True, icon_image)

        # Modules initialize karo
        self.stride_analyzer  = StrideAnalyzer()
        self.dread_scorer     = DreadScorer()
        self.cve_lookup       = CveLookup()
        self.report_generator = ReportGenerator()
        self.pdf_exporter     = PdfExporter()

        # Results store karne ke liye
        self.last_results = {}

        # UI build karo
        self._build_header()
        self._build_main_area()
        self._build_bottom_bar()

    def _create_shield_icon(self):
        """Shield Lock icon banata hai"""
        from PIL import Image, ImageDraw, ImageTk
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        shield_color = (0, 212, 255)
        points = [
            (32, 4), (58, 14), (58, 36), (32, 60), (6, 36), (6, 14),
        ]
        draw.polygon(points, fill=shield_color)
        draw.polygon(points, outline=(255, 255, 255), width=2)
        draw.rounded_rectangle([22, 30, 42, 48], radius=3, fill=(26, 26, 46))
        draw.arc([24, 20, 40, 36], start=180, end=0, fill=(26, 26, 46), width=4)
        draw.ellipse([29, 35, 35, 41], fill=shield_color)
        return ImageTk.PhotoImage(img)

    def _build_header(self):
        """Top header banata hai"""
        header = tk.Frame(self.root, bg="#16213e", pady=12)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text="🔒  Security Threat Analyzer",
            font=("Helvetica", 16, "bold"),
            bg="#16213e",
            fg="#00d4ff"
        ).pack(side=tk.LEFT, padx=20)

        tk.Label(
            header,
            text="Riphah International University | BS Cyber Security",
            font=("Helvetica", 9),
            bg="#16213e",
            fg="#888888"
        ).pack(side=tk.RIGHT, padx=20)

    def _build_main_area(self):
        """Main area — Input panel + Results panel"""
        main_frame = tk.Frame(self.root, bg="#1a1a2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Left side — Input Panel
        self.input_panel = InputPanel(
            main_frame,
            analyze_callback=self._on_analyze_click
        )
        self.input_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        # Right side — Results Panel
        self.results_panel = ResultsPanel(main_frame)
        self.results_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _build_bottom_bar(self):
        """Bottom bar — Status + Download button"""
        bottom = tk.Frame(self.root, bg="#16213e", pady=8)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_label = tk.Label(
            bottom,
            text="Ready — Select services and click Analyze",
            font=("Helvetica", 9),
            bg="#16213e",
            fg="#888888"
        )
        self.status_label.pack(side=tk.LEFT, padx=15)

        tk.Button(
            bottom,
            text="📄  Download PDF Report",
            command=self._on_download_click,
            font=("Helvetica", 10, "bold"),
            bg="#00d4ff",
            fg="#1a1a2e",
            activebackground="#0099bb",
            relief=tk.FLAT,
            padx=15,
            pady=5,
            cursor="hand2"
        ).pack(side=tk.RIGHT, padx=15)

    def _on_analyze_click(self):
        """Analyze button click hone pe chalta hai"""
        services = self.input_panel.get_selected_services()

        if not services:
            messagebox.showwarning(
                "No Services Selected",
                "Please select at least one service to analyze!"
            )
            return

        self.results_panel.show_loading()
        self._set_status("⏳ Analyzing threats...")

        thread = threading.Thread(target=self._run_analysis, args=(services,))
        thread.daemon = True
        thread.start()

    def _run_analysis(self, services):
        """Background mein analysis karta hai"""
        try:
            has_auth       = self.input_panel.get_auth_status()
            has_encryption = self.input_panel.get_encryption_status()

            # Step 1 — STRIDE
            self._set_status("⏳ Running STRIDE analysis...")
            stride_results = self.stride_analyzer.analyze(
                services, has_auth, has_encryption
            )

            # Step 2 — DREAD
            self._set_status("⏳ Calculating DREAD scores...")
            dread_results = self.dread_scorer.score_threats(stride_results)
            overall_risk  = self.dread_scorer.get_overall_risk()

            # Step 3 — CVE
            self._set_status("⏳ Looking up CVE database...")
            cve_results = self.cve_lookup.search_multiple(services)

            # Step 4 — Report
            report_data = self.report_generator.generate(
                services, has_auth, has_encryption,
                stride_results, dread_results,
                cve_results, overall_risk
            )

            self.last_results = report_data

            self.root.after(0, lambda: self._show_results(
                stride_results, dread_results, cve_results, overall_risk
            ))

        except Exception as e:
            self.root.after(0, lambda: self._set_status(f"❌ Error: {str(e)}"))

    def _show_results(self, stride_results, dread_results, cve_results, overall_risk):
        """Results GUI pe display karta hai"""
        self.results_panel.display_results(
            stride_results, dread_results, cve_results, overall_risk
        )

        total = self.stride_analyzer.get_threat_count()
        level = overall_risk.get("level", "LOW")

        self._set_status(
            f"✅ Analysis complete — {total} threats found — Overall Risk: {level}"
        )

    def _on_download_click(self):
        """PDF download button click hone pe chalta hai"""
        if not self.last_results:
            messagebox.showwarning(
                "No Results",
                "Please run analysis first before downloading report!"
            )
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile="security_report.pdf",
            title="Save Security Report"
        )

        if file_path:
            try:
                self._set_status("⏳ Generating PDF...")
                saved_path = self.pdf_exporter.export(self.last_results, file_path)
                self._set_status(f"✅ Report saved: {saved_path}")
                messagebox.showinfo(
                    "Report Saved!",
                    f"PDF report successfully saved!\n\n{saved_path}"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Could not save PDF:\n{str(e)}")
                self._set_status("❌ PDF export failed")

    def _set_status(self, message: str):
        """Status bar update karta hai"""
        self.status_label.config(text=message)

    def run(self):
        """Application start karta hai"""
        self.root.mainloop()