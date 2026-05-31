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
    for w in ("TFrame", "TLabelframe", "TLabelframe.Label",
              "TLabel", "TNotebook", "TNotebook.Tab"):
        s.configure(w, background=DARK["bg"], foreground=DARK["fg"],
                    bordercolor=DARK["border"])
    s.configure("TNotebook.Tab", padding=(14, 6),
                background=DARK["btn"], foreground=DARK["fg"])
    s.map("TNotebook.Tab",
          background=[("selected", DARK["accent"])],
          foreground=[("selected", DARK["bg"])])
    s.configure("TEntry",
                fieldbackground=DARK["entry"], foreground=DARK["fg"],
                insertcolor=DARK["fg"], bordercolor=DARK["border"], relief="flat")
    s.configure("TCombobox",
                fieldbackground=DARK["entry"], foreground=DARK["fg"],
                background=DARK["entry"], selectbackground=DARK["accent"],
                bordercolor=DARK["border"])
    s.configure("TButton",
                background=DARK["btn"], foreground=DARK["fg"],
                bordercolor=DARK["border"], relief="flat", padding=(8, 4))
    s.map("TButton", background=[("active", DARK["btn_act"])])
    s.configure("Accent.TButton",
                background=DARK["accent"], foreground=DARK["bg"], padding=(10, 5))
    s.map("Accent.TButton", background=[("active", "#74c7ec")])
    s.configure("Danger.TButton",
                background=DARK["red"], foreground=DARK["bg"], padding=(10, 5))
    s.map("Danger.TButton", background=[("active", "#eba0ac")])
    s.configure("Success.TButton",
                background=DARK["green"], foreground=DARK["bg"], padding=(10, 5))
    s.map("Success.TButton", background=[("active", "#89dceb")])
    s.configure("TCheckbutton", background=DARK["bg"], foreground=DARK["fg"])
    s.configure("TScrollbar",
                background=DARK["btn"], troughcolor=DARK["panel"],
                arrowcolor=DARK["fg"])
    s.configure("Treeview",
                background=DARK["entry"], foreground=DARK["fg"],
                fieldbackground=DARK["entry"], bordercolor=DARK["border"],
                rowheight=22)
    s.configure("Treeview.Heading",
                background=DARK["btn"], foreground=DARK["accent"],
                relief="flat")
    s.map("Treeview", background=[("selected", DARK["accent"])],
          foreground=[("selected", DARK["bg"])])
    s.configure("TSpinbox",
                fieldbackground=DARK["entry"], foreground=DARK["fg"],
                background=DARK["entry"], insertcolor=DARK["fg"])
    s.configure("TScale",
                background=DARK["bg"], troughcolor=DARK["entry"])
    s.configure("TSeparator", background=DARK["border"])
