"""Catppuccin Mocha Dark Theme – geteilt von allen Modulen."""
from tkinter import ttk

DARK = {
    "bg":      "#1e1e2e",
    "fg":      "#cdd6f4",
    "entry":   "#313244",
    "accent":  "#89b4fa",
    "green":   "#a6e3a1",
    "red":     "#f38ba8",
    "yellow":  "#f9e2af",
    "orange":  "#fab387",
    "purple":  "#cba6f7",
    "teal":    "#94e2d5",
    "panel":   "#181825",
    "border":  "#45475a",
    "btn":     "#313244",
    "btn_act": "#45475a",
}

SEVERITY_COLORS = {
    "Kritisch": "#f38ba8",
    "Hoch":     "#fab387",
    "Mittel":   "#f9e2af",
    "Niedrig":  "#a6e3a1",
    "Info":     "#89b4fa",
}

CVSS_COLOR = {
    "critical": "#f38ba8",
    "high":     "#fab387",
    "medium":   "#f9e2af",
    "low":      "#a6e3a1",
    "none":     "#45475a",
}


def build_style(root):
    s = ttk.Style(root)
    s.theme_use("clam")

    # Basis-Widgets
    for w in ("TFrame", "TLabelframe", "TLabelframe.Label",
              "TLabel", "TNotebook"):
        s.configure(w, background=DARK["bg"], foreground=DARK["fg"],
                    bordercolor=DARK["border"])

    # Notebook-Tabs: etwas mehr Padding, Icon-Platz links
    s.configure("TNotebook",       background=DARK["panel"],
                                   tabmargins=[2, 4, 0, 0])
    s.configure("TNotebook.Tab",   padding=(10, 6),
                                   background=DARK["btn"],
                                   foreground=DARK["border"],
                                   font=("Segoe UI", 9))
    s.map("TNotebook.Tab",
          background=[("selected", DARK["panel"]),
                      ("active",   DARK["btn_act"])],
          foreground=[("selected", DARK["accent"]),
                      ("active",   DARK["fg"])],
          relief=[("selected", "flat")])

    # Entry / Combobox
    s.configure("TEntry",
                fieldbackground=DARK["entry"], foreground=DARK["fg"],
                insertcolor=DARK["accent"], bordercolor=DARK["border"],
                relief="flat", padding=4)
    s.configure("TCombobox",
                fieldbackground=DARK["entry"], foreground=DARK["fg"],
                background=DARK["entry"], selectbackground=DARK["accent"],
                bordercolor=DARK["border"])

    # Standard-Button
    s.configure("TButton",
                background=DARK["btn"], foreground=DARK["fg"],
                bordercolor=DARK["border"], relief="flat",
                padding=(10, 5), font=("Segoe UI", 9))
    s.map("TButton",
          background=[("active", DARK["btn_act"]),
                      ("pressed", DARK["border"])])

    # Farbige Buttons
    s.configure("Accent.TButton",
                background=DARK["accent"], foreground=DARK["bg"],
                padding=(10, 5), font=("Segoe UI", 9, "bold"))
    s.map("Accent.TButton",
          background=[("active", "#74c7ec"), ("pressed", "#89b4fa")])

    s.configure("Danger.TButton",
                background=DARK["red"], foreground=DARK["bg"],
                padding=(10, 5), font=("Segoe UI", 9, "bold"))
    s.map("Danger.TButton",
          background=[("active", "#eba0ac"), ("pressed", "#f38ba8")])

    s.configure("Success.TButton",
                background=DARK["green"], foreground=DARK["bg"],
                padding=(10, 5), font=("Segoe UI", 9, "bold"))
    s.map("Success.TButton",
          background=[("active", "#94e2d5"), ("pressed", "#a6e3a1")])

    s.configure("Teal.TButton",
                background=DARK["teal"], foreground=DARK["bg"],
                padding=(10, 5), font=("Segoe UI", 9))
    s.map("Teal.TButton",
          background=[("active", "#89dceb"), ("pressed", "#94e2d5")])

    s.configure("Warning.TButton",
                background=DARK["yellow"], foreground=DARK["bg"],
                padding=(10, 5), font=("Segoe UI", 9))
    s.map("Warning.TButton",
          background=[("active", "#fab387"), ("pressed", "#f9e2af")])

    # Checkbutton / Radiobutton
    s.configure("TCheckbutton",
                background=DARK["bg"], foreground=DARK["fg"],
                font=("Segoe UI", 9))
    s.configure("TRadiobutton",
                background=DARK["bg"], foreground=DARK["fg"],
                font=("Segoe UI", 9))

    # Scrollbar
    s.configure("TScrollbar",
                background=DARK["btn"], troughcolor=DARK["panel"],
                arrowcolor=DARK["border"], relief="flat", borderwidth=0)
    s.map("TScrollbar",
          background=[("active", DARK["btn_act"])])

    # Treeview
    s.configure("Treeview",
                background=DARK["entry"], foreground=DARK["fg"],
                fieldbackground=DARK["entry"], bordercolor=DARK["border"],
                rowheight=24, font=("Segoe UI", 9))
    s.configure("Treeview.Heading",
                background=DARK["panel"], foreground=DARK["accent"],
                relief="flat", font=("Segoe UI", 9, "bold"),
                bordercolor=DARK["border"])
    s.map("Treeview",
          background=[("selected", DARK["accent"])],
          foreground=[("selected", DARK["bg"])])
    s.map("Treeview.Heading",
          background=[("active", DARK["btn_act"])])

    # Spinbox / Scale / Separator / Progressbar
    s.configure("TSpinbox",
                fieldbackground=DARK["entry"], foreground=DARK["fg"],
                background=DARK["entry"], insertcolor=DARK["accent"])
    s.configure("TScale",
                background=DARK["bg"], troughcolor=DARK["entry"],
                sliderlength=16)
    s.configure("TSeparator",  background=DARK["border"])
    s.configure("TProgressbar",
                background=DARK["accent"], troughcolor=DARK["entry"],
                bordercolor=DARK["border"], lightcolor=DARK["accent"],
                darkcolor=DARK["accent"])
