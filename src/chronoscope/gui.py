"""Desktop timeline viewer (Tkinter, part of the standard library).

Opens a case read-only, shows its events in timeline order a page at a time, and filters by
text, artifact, evidence, time range, timestomp flags and deleted entries.
"""

from __future__ import annotations

import json
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from chronoscope import __version__
from chronoscope.case import CaseError, StoredEvent
from chronoscope.timeutil import parse_iso
from chronoscope.viewer import Filters, TimelineReader, is_deleted, is_flagged

PAGE_SIZE = 1000
ALL = "(all)"
#: (column, heading, sample text that sets the initial width)
TREE_COLUMNS = (
    ("datetime", "Time (UTC)", "0000-00-00T00:00:00.000000Z"),
    ("timestamp_desc", "Description", "Content Modification Time"),
    ("artifact", "Artifact", "chromium_history"),
    ("evidence", "Evidence", "WORKSTATION-01"),
    ("message", "Message", "x" * 80),
)
FLAGGED_COLOR = "#b00020"
DELETED_COLOR = "#7a7a7a"


class TimelineApp:
    def __init__(self, root: tk.Tk, case_dir: Path | None = None) -> None:
        self.root = root
        self.reader: TimelineReader | None = None
        self.filters = Filters()
        self.offset = 0
        self.total = 0
        self.rows: dict[str, StoredEvent] = {}

        root.title(f"Chronoscope {__version__}")
        root.geometry("1280x800")
        root.minsize(800, 500)
        root.protocol("WM_DELETE_WINDOW", self.quit)
        self._build_menu()
        self._build_filters()
        self._build_body()
        self._build_status()
        root.bind("<Control-o>", lambda _e: self.choose_case())
        self._set_enabled(False)
        if case_dir is not None:
            self.open_case(case_dir)

    # -- layout ------------------------------------------------------------------------

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Open case...", accelerator="Ctrl+O", command=self.choose_case)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.quit)
        menu.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menu)

    def _build_filters(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(fill="x")
        self.text_var = tk.StringVar()
        self.artifact_var = tk.StringVar(value=ALL)
        self.evidence_var = tk.StringVar(value=ALL)
        self.start_var = tk.StringVar()
        self.end_var = tk.StringVar()
        self.flagged_var = tk.BooleanVar()
        self.deleted_var = tk.BooleanVar()

        ttk.Label(bar, text="Search").grid(row=0, column=0, sticky="w")
        self.text_entry = ttk.Entry(bar, textvariable=self.text_var, width=30)
        self.text_entry.grid(row=0, column=1, padx=(4, 12))
        ttk.Label(bar, text="Artifact").grid(row=0, column=2, sticky="w")
        self.artifact_box = ttk.Combobox(
            bar, textvariable=self.artifact_var, state="readonly", width=16
        )
        self.artifact_box.grid(row=0, column=3, padx=(4, 12))
        ttk.Label(bar, text="Evidence").grid(row=0, column=4, sticky="w")
        self.evidence_box = ttk.Combobox(
            bar, textvariable=self.evidence_var, state="readonly", width=16
        )
        self.evidence_box.grid(row=0, column=5, padx=(4, 12))
        self.flagged_check = ttk.Checkbutton(
            bar, text="Possible timestomp", variable=self.flagged_var
        )
        self.flagged_check.grid(row=0, column=6, padx=(0, 8))
        self.deleted_check = ttk.Checkbutton(bar, text="Deleted only", variable=self.deleted_var)
        self.deleted_check.grid(row=0, column=7)

        ttk.Label(bar, text="From").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.start_entry = ttk.Entry(bar, textvariable=self.start_var, width=30)
        self.start_entry.grid(row=1, column=1, padx=(4, 12), pady=(6, 0))
        ttk.Label(bar, text="To").grid(row=1, column=2, sticky="w", pady=(6, 0))
        self.end_entry = ttk.Entry(bar, textvariable=self.end_var, width=30)
        self.end_entry.grid(row=1, column=3, columnspan=3, sticky="w", padx=(4, 12), pady=(6, 0))
        self.apply_button = ttk.Button(bar, text="Apply", command=self.apply_filters)
        self.apply_button.grid(row=1, column=6, sticky="e", pady=(6, 0))
        self.reset_button = ttk.Button(bar, text="Reset", command=self.reset_filters)
        self.reset_button.grid(row=1, column=7, sticky="w", pady=(6, 0))
        ttk.Label(bar, text="Times are ISO 8601 with an offset, e.g. 2024-03-01T00:00:00Z").grid(
            row=2, column=1, columnspan=7, sticky="w", pady=(2, 0)
        )
        for entry in (self.text_entry, self.start_entry, self.end_entry):
            entry.bind("<Return>", lambda _e: self.apply_filters())
        for box in (self.artifact_box, self.evidence_box):
            box.bind("<<ComboboxSelected>>", lambda _e: self.apply_filters())
        for check in (self.flagged_check, self.deleted_check):
            check.configure(command=self.apply_filters)

    def _build_body(self) -> None:
        panes = ttk.PanedWindow(self.root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8)

        # Size rows and columns from the font so nothing is clipped on high-DPI displays.
        font = tkfont.nametofont("TkDefaultFont")
        ttk.Style(self.root).configure("Treeview", rowheight=font.metrics("linespace") + 6)
        table = ttk.Frame(panes)
        self.tree = ttk.Treeview(
            table, columns=[c[0] for c in TREE_COLUMNS], show="headings", selectmode="browse"
        )
        for key, heading, sample in TREE_COLUMNS:
            width = max(font.measure(sample), font.measure(heading)) + 16
            self.tree.heading(key, text=heading, anchor="w")
            self.tree.column(key, width=width, stretch=key == "message", anchor="w")
        self.tree.tag_configure("flagged", foreground=FLAGGED_COLOR)
        self.tree.tag_configure("deleted", foreground=DELETED_COLOR)
        yscroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_details())
        panes.add(table, weight=3)

        details = ttk.Frame(panes)
        self.details = tk.Text(details, height=12, wrap="word", state="disabled")
        dscroll = ttk.Scrollbar(details, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dscroll.set)
        self.details.pack(side="left", fill="both", expand=True)
        dscroll.pack(side="right", fill="y")
        panes.add(details, weight=1)

    def _build_status(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 4, 8, 8))
        bar.pack(fill="x")
        self.status_var = tk.StringVar(value="Open a case with File > Open case... (Ctrl+O)")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.next_button = ttk.Button(bar, text="Next >", command=self.next_page)
        self.next_button.pack(side="right")
        self.prev_button = ttk.Button(bar, text="< Previous", command=self.prev_page)
        self.prev_button.pack(side="right", padx=(0, 4))

    def _set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for widget in (
            self.text_entry,
            self.start_entry,
            self.end_entry,
            self.flagged_check,
            self.deleted_check,
            self.apply_button,
            self.reset_button,
        ):
            widget.configure(state=state)
        for box in (self.artifact_box, self.evidence_box):
            box.configure(state="readonly" if enabled else "disabled")
        if not enabled:
            self.prev_button.configure(state="disabled")
            self.next_button.configure(state="disabled")

    # -- actions -----------------------------------------------------------------------

    def choose_case(self) -> None:
        directory = filedialog.askdirectory(title="Open Chronoscope case", mustexist=True)
        if directory:
            self.open_case(Path(directory))

    def open_case(self, case_dir: Path) -> None:
        try:
            reader = TimelineReader(case_dir)
        except (CaseError, OSError, ValueError) as exc:
            messagebox.showerror("Cannot open case", str(exc), parent=self.root)
            return
        if self.reader is not None:
            self.reader.close()
        self.reader = reader
        name = reader.meta.get("name", case_dir.name)
        self.root.title(f"Chronoscope {__version__} - {name} (read-only)")
        self.artifact_box.configure(values=[ALL, *reader.distinct("artifact")])
        self.evidence_box.configure(values=[ALL, *reader.distinct("evidence_label")])
        self._set_enabled(True)
        self.reset_filters()

    def reset_filters(self) -> None:
        for var in (self.text_var, self.start_var, self.end_var):
            var.set("")
        self.artifact_var.set(ALL)
        self.evidence_var.set(ALL)
        self.flagged_var.set(False)
        self.deleted_var.set(False)
        self.apply_filters()

    def _read_filters(self) -> Filters | None:
        times = {}
        for key, var in (("start", self.start_var), ("end", self.end_var)):
            text = var.get().strip()
            if not text:
                times[key] = None
                continue
            try:
                times[key] = parse_iso(text)
            except ValueError as exc:
                messagebox.showerror(
                    "Invalid time",
                    f"{key.title()}: {exc}\n\nUse ISO 8601 with an offset, "
                    "e.g. 2024-03-01T00:00:00Z",
                    parent=self.root,
                )
                return None
        artifact = self.artifact_var.get()
        evidence = self.evidence_var.get()
        return Filters(
            text=self.text_var.get().strip(),
            artifact="" if artifact == ALL else artifact,
            evidence="" if evidence == ALL else evidence,
            start=times["start"],
            end=times["end"],
            flagged_only=self.flagged_var.get(),
            deleted_only=self.deleted_var.get(),
        )

    def apply_filters(self) -> None:
        if self.reader is None:
            return
        filters = self._read_filters()
        if filters is None:
            return
        self.filters = filters
        self.total = self.reader.count(filters)
        self.offset = 0
        self.load_page()

    def next_page(self) -> None:
        if self.offset + PAGE_SIZE < self.total:
            self.offset += PAGE_SIZE
            self.load_page()

    def prev_page(self) -> None:
        if self.offset > 0:
            self.offset = max(0, self.offset - PAGE_SIZE)
            self.load_page()

    def load_page(self) -> None:
        assert self.reader is not None
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        for i, ev in enumerate(self.reader.page(self.filters, self.offset, PAGE_SIZE)):
            iid = str(self.offset + i)
            tags = []
            if is_flagged(ev):
                tags.append("flagged")
            elif is_deleted(ev):
                tags.append("deleted")
            values = (ev.datetime, ev.timestamp_desc, ev.artifact, ev.evidence_label, ev.message)
            self.tree.insert("", "end", iid=iid, values=values, tags=tags)
            self.rows[iid] = ev
        shown = len(self.rows)
        if shown:
            self.status_var.set(
                f"Events {self.offset + 1:,}-{self.offset + shown:,} of {self.total:,}"
            )
        else:
            self.status_var.set("No events match the filters")
        self.prev_button.configure(state="normal" if self.offset > 0 else "disabled")
        more = self.offset + PAGE_SIZE < self.total
        self.next_button.configure(state="normal" if more else "disabled")
        self._write_details("")

    def show_details(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        ev = self.rows[selection[0]]
        attributes = json.dumps(json.loads(ev.attributes), indent=2, ensure_ascii=False)
        lines = [
            f"Time (UTC):   {ev.datetime}",
            f"Description:  {ev.timestamp_desc}",
            f"Source:       {ev.source}",
            f"Artifact:     {ev.artifact}",
            f"Evidence:     {ev.evidence_label} (#{ev.evidence_id})",
            f"Path:         {ev.path}",
            f"Message:      {ev.message}",
            f"Fingerprint:  {ev.fingerprint}",
            "",
            "Attributes:",
            attributes,
        ]
        self._write_details("\n".join(lines))

    def _write_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def quit(self) -> None:
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        self.root.destroy()


def run(case_dir: Path | None = None) -> None:
    root = tk.Tk()
    TimelineApp(root, case_dir)
    root.mainloop()
