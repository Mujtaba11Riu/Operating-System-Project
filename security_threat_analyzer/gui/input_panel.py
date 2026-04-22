# ============================================================
# input_panel.py — User Input Panel
# Checkboxes, dropdowns aur buttons
# ============================================================

import tkinter as tk
from tkinter import ttk


class InputPanel:
    """
    User se system information leta hai.
    Services, Authentication aur Encryption select karta hai.
    """

    # Available services list
    SERVICES = ["FTP", "HTTP", "HTTPS", "SSH", "TELNET", "SMB", "DNS", "SMTP", "RDP"]

    def __init__(self, parent, analyze_callback):
        """
        Parameters:
            parent           : Parent window
            analyze_callback : Analyze button click hone pe yeh function call hoga
        """
        self.parent            = parent
        self.analyze_callback  = analyze_callback
        self.service_vars      = {}  # Har service ka checkbox variable

        self.frame = tk.LabelFrame(
            parent,
            text=" System Information ",
            font=("Helvetica", 11, "bold"),
            bg="#1a1a2e",
            fg="#e0e0e0",
            padx=15,
            pady=15,
            relief=tk.GROOVE,
            bd=2
        )

        self._build_services_section()
        self._build_auth_section()
        self._build_encryption_section()
        self._build_button()

    def _build_services_section(self):
        """Services checkboxes banata hai"""

        tk.Label(
            self.frame,
            text="Select Running Services:",
            font=("Helvetica", 10, "bold"),
            bg="#1a1a2e",
            fg="#00d4ff"
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        # Har service ka checkbox
        for i, service in enumerate(self.SERVICES):
            var = tk.BooleanVar()
            self.service_vars[service] = var

            cb = tk.Checkbutton(
                self.frame,
                text=service,
                variable=var,
                font=("Helvetica", 10),
                bg="#1a1a2e",
                fg="#e0e0e0",
                selectcolor="#16213e",
                activebackground="#1a1a2e",
                activeforeground="#00d4ff",
                cursor="hand2"
            )
            cb.grid(
                row=1 + i // 3,
                column=i % 3,
                sticky="w",
                padx=10,
                pady=3
            )

    def _build_auth_section(self):
        """Authentication radio buttons banata hai"""

        tk.Label(
            self.frame,
            text="Authentication:",
            font=("Helvetica", 10, "bold"),
            bg="#1a1a2e",
            fg="#00d4ff"
        ).grid(row=5, column=0, sticky="w", pady=(15, 5))

        self.auth_var = tk.StringVar(value="Yes")

        for i, option in enumerate(["Yes", "No"]):
            tk.Radiobutton(
                self.frame,
                text=option,
                variable=self.auth_var,
                value=option,
                font=("Helvetica", 10),
                bg="#1a1a2e",
                fg="#e0e0e0",
                selectcolor="#16213e",
                activebackground="#1a1a2e",
                activeforeground="#00d4ff",
                cursor="hand2"
            ).grid(row=5, column=i + 1, sticky="w", padx=10)

    def _build_encryption_section(self):
        """Encryption radio buttons banata hai"""

        tk.Label(
            self.frame,
            text="Encryption:",
            font=("Helvetica", 10, "bold"),
            bg="#1a1a2e",
            fg="#00d4ff"
        ).grid(row=6, column=0, sticky="w", pady=(5, 5))

        self.encryption_var = tk.StringVar(value="Yes")

        for i, option in enumerate(["Yes", "No"]):
            tk.Radiobutton(
                self.frame,
                text=option,
                variable=self.encryption_var,
                value=option,
                font=("Helvetica", 10),
                bg="#1a1a2e",
                fg="#e0e0e0",
                selectcolor="#16213e",
                activebackground="#1a1a2e",
                activeforeground="#00d4ff",
                cursor="hand2"
            ).grid(row=6, column=i + 1, sticky="w", padx=10)

    def _build_button(self):
        """Analyze button banata hai"""

        tk.Button(
            self.frame,
            text="🔍  Analyze Threats",
            command=self.analyze_callback,
            font=("Helvetica", 11, "bold"),
            bg="#00d4ff",
            fg="#1a1a2e",
            activebackground="#0099bb",
            activeforeground="#1a1a2e",
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2"
        ).grid(row=7, column=0, columnspan=3, pady=(20, 5))

    def get_selected_services(self) -> list:
        """User ne jo services select ki hain unki list return karta hai"""
        return [
            service
            for service, var in self.service_vars.items()
            if var.get()
        ]

    def get_auth_status(self) -> bool:
        """Authentication status return karta hai"""
        return self.auth_var.get() == "Yes"

    def get_encryption_status(self) -> bool:
        """Encryption status return karta hai"""
        return self.encryption_var.get() == "Yes"

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)