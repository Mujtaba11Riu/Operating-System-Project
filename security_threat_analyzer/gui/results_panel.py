# ============================================================
# results_panel.py — Results Display Panel
# STRIDE, DREAD aur CVE results dikhata hai
# ============================================================

import tkinter as tk
from tkinter import ttk


class ResultsPanel:
    """
    Analysis ke results ko screen pe display karta hai.
    Tabs mein organized hai — STRIDE, DREAD, CVE.
    """

    def __init__(self, parent):
        self.parent = parent

        self.frame = tk.LabelFrame(
            parent,
            text=" Analysis Results ",
            font=("Helvetica", 11, "bold"),
            bg="#1a1a2e",
            fg="#e0e0e0",
            padx=10,
            pady=10,
            relief=tk.GROOVE,
            bd=2
        )

        self._build_overall_risk_bar()
        self._build_tabs()

    def _build_overall_risk_bar(self):
        """Top pe overall risk show karta hai"""

        self.risk_frame = tk.Frame(self.frame, bg="#16213e", pady=8)
        self.risk_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            self.risk_frame,
            text="Overall Risk:",
            font=("Helvetica", 11, "bold"),
            bg="#16213e",
            fg="#e0e0e0"
        ).pack(side=tk.LEFT, padx=(10, 5))

        self.risk_label = tk.Label(
            self.risk_frame,
            text="— Analyze to see results —",
            font=("Helvetica", 11, "bold"),
            bg="#16213e",
            fg="#888888"
        )
        self.risk_label.pack(side=tk.LEFT)

    def _build_tabs(self):
        """3 tabs banata hai — STRIDE, DREAD, CVE"""

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.TNotebook",
            background="#1a1a2e",
            borderwidth=0
        )
        style.configure(
            "Custom.TNotebook.Tab",
            background="#16213e",
            foreground="#e0e0e0",
            padding=[15, 5],
            font=("Helvetica", 10, "bold")
        )
        style.map(
            "Custom.TNotebook.Tab",
            background=[("selected", "#00d4ff")],
            foreground=[("selected", "#1a1a2e")]
        )

        self.notebook = ttk.Notebook(self.frame, style="Custom.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1 — STRIDE
        self.stride_tab = tk.Frame(self.notebook, bg="#1a1a2e")
        self.notebook.add(self.stride_tab, text="  STRIDE Threats  ")
        self.stride_text = self._make_textbox(self.stride_tab)

        # Tab 2 — DREAD
        self.dread_tab = tk.Frame(self.notebook, bg="#1a1a2e")
        self.notebook.add(self.dread_tab, text="  DREAD Scores  ")
        self.dread_text = self._make_textbox(self.dread_tab)

        # Tab 3 — CVE
        self.cve_tab = tk.Frame(self.notebook, bg="#1a1a2e")
        self.notebook.add(self.cve_tab, text="  CVE Lookup  ")
        self.cve_text = self._make_textbox(self.cve_tab)

    def _make_textbox(self, parent) -> tk.Text:
        """Scrollable text box banata hai"""

        frame = tk.Frame(parent, bg="#1a1a2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        textbox = tk.Text(
            frame,
            font=("Courier New", 10),
            bg="#0f0f23",
            fg="#e0e0e0",
            insertbackground="#00d4ff",
            relief=tk.FLAT,
            padx=10,
            pady=10,
            yscrollcommand=scrollbar.set,
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        textbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=textbox.yview)

        # Text colors define karo
        textbox.tag_configure("critical", foreground="#FF0000", font=("Courier New", 10, "bold"))
        textbox.tag_configure("high",     foreground="#FF6600", font=("Courier New", 10, "bold"))
        textbox.tag_configure("medium",   foreground="#FFB300", font=("Courier New", 10, "bold"))
        textbox.tag_configure("low",      foreground="#00AA00", font=("Courier New", 10, "bold"))
        textbox.tag_configure("heading",  foreground="#00d4ff", font=("Courier New", 11, "bold"))
        textbox.tag_configure("normal",   foreground="#e0e0e0")
        textbox.tag_configure("source",   foreground="#888888")

        return textbox

    def display_results(self, stride_results, dread_results, cve_results, overall_risk):
        """Saare results display karta hai"""

        self._update_overall_risk(overall_risk)
        self._display_stride(stride_results)
        self._display_dread(dread_results)
        self._display_cve(cve_results)

    def _update_overall_risk(self, overall_risk):
        """Overall risk bar update karta hai"""

        level = overall_risk.get("level", "LOW")
        avg   = overall_risk.get("average", 0)

        colors = {
            "CRITICAL": "#FF0000",
            "HIGH":     "#FF6600",
            "MEDIUM":   "#FFB300",
            "LOW":      "#00AA00",
        }

        self.risk_label.config(
            text=f"{level}  ({avg}/10)",
            fg=colors.get(level, "#00AA00")
        )

    def _display_stride(self, stride_results):
        """STRIDE tab mein results dikhata hai"""

        self._clear_textbox(self.stride_text)
        self._write(self.stride_text, "STRIDE THREAT ANALYSIS\n", "heading")
        self._write(self.stride_text, "=" * 50 + "\n\n", "normal")

        if not stride_results:
            self._write(self.stride_text, "No threats identified.\n", "low")
            return

        for threat_type, threats in stride_results.items():
            self._write(self.stride_text, f"▶ {threat_type}\n", "heading")
            for threat in threats:
                self._write(self.stride_text, f"  Source : {threat['source']}\n", "source")
                self._write(self.stride_text, f"  Detail : {threat['description']}\n\n", "normal")

    def _display_dread(self, dread_results):
        """DREAD tab mein scores dikhata hai"""

        self._clear_textbox(self.dread_text)
        self._write(self.dread_text, "DREAD RISK SCORING\n", "heading")
        self._write(self.dread_text, "=" * 50 + "\n\n", "normal")

        if not dread_results:
            self._write(self.dread_text, "No scores available.\n", "low")
            return

        for threat_type, info in dread_results.items():
            level = info["level"]
            tag   = level.lower()

            self._write(self.dread_text, f"▶ {threat_type}\n", "heading")
            self._write(self.dread_text, f"  Risk Level : ", "normal")
            self._write(self.dread_text, f"{level} ({info['average']}/10)\n", tag)

            s = info["scores"]
            self._write(self.dread_text,
                f"  Damage:{s['Damage']}  "
                f"Repro:{s['Reproducibility']}  "
                f"Exploit:{s['Exploitability']}  "
                f"Users:{s['Affected_Users']}  "
                f"Discover:{s['Discoverability']}\n\n",
                "source"
            )

    def _display_cve(self, cve_results):
        """CVE tab mein vulnerabilities dikhata hai"""

        self._clear_textbox(self.cve_text)
        self._write(self.cve_text, "CVE VULNERABILITY LOOKUP\n", "heading")
        self._write(self.cve_text, "=" * 50 + "\n\n", "normal")

        if not cve_results:
            self._write(self.cve_text, "No CVE data found.\n", "low")
            return

        for service, cves in cve_results.items():
            self._write(self.cve_text, f"▶ {service}\n", "heading")
            for cve in cves:
                sev = cve["severity"].lower()
                tag = sev if sev in ["critical", "high", "medium", "low"] else "normal"
                self._write(self.cve_text, f"  {cve['id']} — ", "source")
                self._write(self.cve_text, f"{cve['severity']} ({cve['score']})\n", tag)
                self._write(self.cve_text, f"  {cve['description']}\n\n", "normal")

    def _clear_textbox(self, textbox):
        """Textbox clear karta hai"""
        textbox.config(state=tk.NORMAL)
        textbox.delete("1.0", tk.END)

    def _write(self, textbox, text, tag="normal"):
        """Textbox mein colored text likhta hai"""
        textbox.config(state=tk.NORMAL)
        textbox.insert(tk.END, text, tag)
        textbox.config(state=tk.DISABLED)

    def show_loading(self):
        """Loading message dikhata hai"""
        for textbox in [self.stride_text, self.dread_text, self.cve_text]:
            self._clear_textbox(textbox)
            self._write(textbox, "⏳ Analyzing... Please wait...\n", "heading")

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)