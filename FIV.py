import os
import hashlib
import pathlib
import webbrowser
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ReportLab for PDFs
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, KeepTogether
    from reportlab.lib.units import mm
    REPORTLAB = True
except Exception:
    REPORTLAB = False

# Pillow for GUI icon image
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

ICON_PATH = os.path.abspath('/mnt/data/8a7fcc0a-4cfc-4801-b47c-c984147e870b.jpg')

ALGORITHMS = [
    'md5','sha1','sha224','sha256','sha384','sha512',
    'blake2b','blake2s','sha3_224','sha3_256','sha3_384','sha3_512'
]

# ---------------- Hash utilities ----------------
def compute_hash(path, algo='sha256'):
    h = hashlib.new(algo)
    with open(path, 'rb') as fh:
        while True:
            chunk = fh.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def build_manifest_from_files(file_paths, algos):
    if not file_paths:
        root = os.getcwd()
    else:
        try:
            root = os.path.commonpath(file_paths)
        except Exception:
            root = os.path.dirname(file_paths[0])
        if os.path.isfile(root):
            root = os.path.dirname(root) or os.getcwd()
    manifest = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'root_path': root,
        'algorithms': algos,
        'files': []
    }
    for p in dict.fromkeys(sorted(file_paths)):
        rel = os.path.relpath(p, root)
        if rel in ('.',''):
            rel = os.path.basename(p)
        st = os.stat(p)
        entry = {
            'relative_path': rel,
            'size': st.st_size,
            'modified': datetime.utcfromtimestamp(st.st_mtime).isoformat() + 'Z',
            'hashes': {}
        }
        for a in algos:
            entry['hashes'][a] = compute_hash(p, a)
        manifest['files'].append(entry)
    return manifest

def write_manifest_txt(manifest, out_txt):
    lines = [
        "File Integrity Report",
        f"Generated at: {manifest['generated_at']}",
        f"Root path: {manifest['root_path']}",
        f"Algorithms: {', '.join(manifest['algorithms'])}",
        ""
    ]
    for f in manifest['files']:
        lines.append(f"File: {f['relative_path']}")
        lines.append(f"  Size: {f['size']} bytes")
        lines.append(f"  Modified (UTC): {f['modified']}")
        for a, v in f['hashes'].items():
            lines.append(f"  {a}: {v}")
        lines.append("")
    with open(out_txt, 'w', encoding='utf-8') as fh:
        fh.write("\n".join(lines))
    return lines

def parse_manifest_txt(path):
    with open(path, 'r', encoding='utf-8') as fh:
        L = [l.rstrip('\n') for l in fh]
    algos = []
    files = []
    i = 0
    while i < len(L):
        line = L[i]
        if line.startswith("Algorithms:"):
            algos = [a.strip() for a in line.split(":", 1)[1].split(",")]
            i += 1
            continue
        if line.startswith("File:"):
            rel = line.split(":",1)[1].strip()
            size = 0; mod = ""; hashes = {}
            i += 1
            while i < len(L) and L[i].strip() != "":
                l = L[i].strip()
                if l.startswith("Size:"):
                    try:
                        size = int(l.split(":",1)[1].strip().split()[0])
                    except Exception:
                        size = 0
                elif l.startswith("Modified"):
                    mod = l.split(":",1)[1].strip()
                elif ":" in l:
                    a, v = l.split(":",1)
                    hashes[a.strip()] = v.strip()
                i += 1
            files.append({'relative_path': rel, 'size': size, 'modified': mod, 'hashes': hashes})
        else:
            i += 1
    return algos, files

def verify_manifest_txt_against_files(manifest_txt_path, evidence_paths):
    algos, files = parse_manifest_txt(manifest_txt_path)
    root = os.path.commonpath(evidence_paths) if len(evidence_paths) > 0 else os.getcwd()
    results = []
    ok = mism = missing = 0
    for f in files:
        rel = f['relative_path']
        candidate = os.path.join(root, rel)
        if not os.path.exists(candidate):
            matches = [p for p in evidence_paths if os.path.basename(p).lower() == os.path.basename(rel).lower()]
            candidate = matches[0] if matches else candidate
        if not os.path.exists(candidate):
            results.append((rel, 'MISSING', None, f['hashes'])); missing += 1; continue
        actual = {}
        for a in algos:
            try:
                actual[a] = compute_hash(candidate, a)
            except Exception:
                actual[a] = "ERR"
        status = 'OK' if all(f['hashes'].get(a) == actual.get(a) for a in algos) else 'MISMATCH'
        if status == 'OK': ok += 1
        else: mism += 1
        results.append((rel, status, actual, f['hashes']))
    lines = [
        "Verification Result",
        f"Checked at: {datetime.utcnow().isoformat()}Z",
        f"Algorithms: {', '.join(algos)}",
        ""
    ]
    for r in results:
        lines.append(f"File: {r[0]}")
        lines.append(f"  Status: {r[1]}")
        if r[1] != 'MISSING':
            lines.append("  Expected:")
            for a, v in r[3].items(): lines.append(f"    {a}: {v}")
            lines.append("  Actual:")
            for a, v in r[2].items(): lines.append(f"    {a}: {v}")
        lines.append("")
    lines.append(f"Summary: Total={len(results)}, OK={ok}, MISMATCH={mism}, MISSING={missing}")
    # Also return parsed results and counts for GUI display
    summary = {'total': len(results), 'ok': ok, 'mismatch': mism, 'missing': missing}
    return lines, results, summary

# ---------------- PDF: vertical per-file tables ----------------
def write_pdf_report_vertical(manifest, out_pdf, icon_path=ICON_PATH, icon_width_px=64):
    if not REPORTLAB:
        raise RuntimeError("reportlab not available")
    doc = SimpleDocTemplate(out_pdf, pagesize=A4, rightMargin=18, leftMargin=18, topMargin=18, bottomMargin=18)
    styles = getSampleStyleSheet()
    elems = []
    title_style = ParagraphStyle('title', parent=styles['Heading1'], fontSize=16, leading=20, spaceAfter=8)
    normal = styles['Normal']
    # header: icon + title (simple)
    header_cells = []
    if os.path.exists(icon_path):
        try:
            img = RLImage(icon_path)
            img.drawWidth = icon_width_px * mm * 0.3527777778
            img.drawHeight = img.imageHeight * (img.drawWidth / img.imageWidth)
            header_cells.append(img)
        except Exception:
            header_cells.append(Paragraph("", normal))
    else:
        header_cells.append(Paragraph("", normal))
    header_cells.append(Paragraph("File Integrity Verifier (FIV)", title_style))
    header_table = Table([header_cells], colWidths=[icon_width_px * mm * 0.3527777778, 420])
    header_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
    elems.append(header_table)
    elems.append(Spacer(1, 10))
    elems.append(Paragraph(f"Generated at: {manifest['generated_at']}", normal))
    elems.append(Paragraph(f"Root path: {manifest['root_path']}", normal))
    elems.append(Paragraph(f"Algorithms: {', '.join(manifest['algorithms'])}", normal))
    elems.append(Spacer(1,12))
    for f in manifest['files']:
        fname = f['relative_path'] if f['relative_path'] not in ('.','') else os.path.basename(f['relative_path'])
        # create a small paragraph style for wrapped values
        val_style = ParagraphStyle('val', parent=styles['Normal'], fontSize=9, leading=11)
        data = [
            ['File Name', Paragraph(fname, val_style)],
            ['Size (bytes)', Paragraph(str(f['size']), val_style)],
            ['Modified (UTC)', Paragraph(f['modified'], val_style)],
        ]
        for a in manifest['algorithms']:
            hash_val = f['hashes'].get(a, '')
            data.append([Paragraph(a, styles['Normal']), Paragraph(hash_val, val_style)])
        tbl = Table(data, colWidths=[120, doc.width - 120], hAlign='LEFT')
        tbl.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f1f5f9')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        elems.append(KeepTogether([tbl, Spacer(1,8)]))
    doc.build(elems)

def write_pdf_verification_vertical(lines_struct, out_pdf, icon_path=ICON_PATH, icon_width_px=64):
    # lines_struct: plain lines returned by write-style function
    if not REPORTLAB:
        raise RuntimeError("reportlab not available")
    doc = SimpleDocTemplate(out_pdf, pagesize=A4, rightMargin=18, leftMargin=18, topMargin=18, bottomMargin=18)
    styles = getSampleStyleSheet()
    elems = []
    title_style = ParagraphStyle('title', parent=styles['Heading1'], fontSize=16, leading=20, spaceAfter=8)
    normal = styles['Normal']

    header_cells = []
    if os.path.exists(icon_path):
        try:
            img = RLImage(icon_path)
            img.drawWidth = icon_width_px * mm * 0.3527777778
            img.drawHeight = img.imageHeight * (img.drawWidth / img.imageWidth)
            header_cells.append(img)
        except Exception:
            header_cells.append(Paragraph("", normal))
    else:
        header_cells.append(Paragraph("", normal))
    header_cells.append(Paragraph("Verification Report", title_style))
    header_table = Table([header_cells], colWidths=[icon_width_px * mm * 0.3527777778, 420])
    header_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
    elems.append(header_table)
    elems.append(Spacer(1, 10))

    text_lines = lines_struct[:]
    # Header lines (first three)
    for i in range(min(3, len(text_lines))):
        elems.append(Paragraph(text_lines[i], normal))
    elems.append(Spacer(1,8))
    # Parse blocks
    i = 3
    while i < len(text_lines):
        if text_lines[i].startswith("File:"):
            fname = text_lines[i].split(":",1)[1].strip()
            i += 1
            block = []
            while i < len(text_lines) and text_lines[i].strip() != "":
                block.append(text_lines[i].strip())
                i += 1
            data = [['Field', 'Value']]
            val_style = ParagraphStyle('val', parent=styles['Normal'], fontSize=9, leading=11)
            data.append([Paragraph('File Name', styles['Normal']), Paragraph(fname, val_style)])
            j = 0
            while j < len(block):
                ln = block[j]
                if ln.startswith("Status:"):
                    data.append([Paragraph('Status', styles['Normal']), Paragraph(ln.split(":",1)[1].strip(), val_style)])
                    j += 1
                elif ln.startswith("Expected:"):
                    j += 1
                    while j < len(block) and not block[j].startswith("Actual:"):
                        if ":" in block[j]:
                            k, v = block[j].split(":",1)
                            data.append([Paragraph(k.strip()+" (expected)", styles['Normal']), Paragraph(v.strip(), val_style)])
                        j += 1
                elif ln.startswith("Actual:"):
                    j += 1
                    while j < len(block):
                        if ":" in block[j]:
                            k, v = block[j].split(":",1)
                            data.append([Paragraph(k.strip()+" (actual)", styles['Normal']), Paragraph(v.strip(), val_style)])
                        j += 1
                else:
                    j += 1

            tbl = Table(data, colWidths=[140, doc.width - 140], hAlign='LEFT')
            tbl.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            elems.append(KeepTogether([tbl, Spacer(1,8)]))
        else:
            i += 1
    # summary line
    if text_lines and text_lines[-1].startswith("Summary:"):
        elems.append(Paragraph(text_lines[-1], normal))
    doc.build(elems)

# ---------------- GUI with full dark/light theming and icon in title ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Verifier")  # removed (Final)
        self.geometry("960x680")
        self.evidence = []
        self.manifest_file = None
        self.output_folder = None
        self.dark = False
        self.icon_img_tk = None
        self._load_icon_image()
        self._build_ui()
        self._apply_theme()

    def _load_icon_image(self):
        if os.path.exists(ICON_PATH) and PIL_AVAILABLE:
            try:
                img = Image.open(ICON_PATH)
                desired_px = 64
                img = img.convert("RGBA")
                img.thumbnail((desired_px, desired_px), Image.LANCZOS)
                self.icon_img_tk = ImageTk.PhotoImage(img)
            except Exception:
                self.icon_img_tk = None
        else:
            self.icon_img_tk = None

    def _build_ui(self):
        header = ttk.Frame(self); header.pack(fill='x', padx=12, pady=8)
        if self.icon_img_tk:
            lbl_icon = tk.Label(header, image=self.icon_img_tk)
            lbl_icon.pack(side='left', padx=(0,8))
        title_lbl = ttk.Label(header, text="File Integrity Verifier", font=('Segoe UI', 16, 'bold'))
        title_lbl.pack(side='left', padx=(0,8))
        btn_theme = ttk.Button(header, text="Toggle Theme", command=self.toggle_theme)
        btn_theme.pack(side='right')

        controls = ttk.Frame(self); controls.pack(fill='x', padx=12, pady=(0,8))
        ttk.Button(controls, text="Add Files", command=self.add_files).grid(row=0, column=0, padx=6, pady=2)
        ttk.Button(controls, text="Add Folder", command=self.add_folder).grid(row=0, column=1, padx=6, pady=2)
        ttk.Button(controls, text="Clear", command=self.clear).grid(row=0, column=2, padx=6, pady=2)
        ttk.Button(controls, text="Set Output Folder", command=self.set_output).grid(row=0, column=3, padx=6, pady=2)

        self.listbox = tk.Listbox(self, height=14)
        self.listbox.pack(fill='both', expand=False, padx=12, pady=(2,8))

        alg_frame = ttk.Frame(self); alg_frame.pack(fill='x', padx=12, pady=6)
        ttk.Label(alg_frame, text="Algorithms:").pack(anchor='w')
        self.algolist = tk.Listbox(alg_frame, selectmode='extended', height=6, exportselection=False)
        for a in ALGORITHMS: self.algolist.insert('end', a)
        self.algolist.selection_set(0,1)
        self.algolist.pack(fill='x', pady=4)
        ttk.Button(alg_frame, text="Generate Report (TXT + PDF)", command=self.generate_report).pack(side='left', padx=6)
        ttk.Button(alg_frame, text="Select Manifest TXT for Verification", command=self.select_manifest).pack(side='left', padx=6)
        ttk.Button(alg_frame, text="Run Verification", command=self.run_verification).pack(side='left', padx=6)

        ttk.Label(self, text="Activity Log:").pack(anchor='w', padx=12)
        self.log = tk.Text(self, height=12); self.log.pack(fill='both', expand=True, padx=12, pady=(4,12))

    def _apply_theme(self):
        # apply colors for whole GUI
        if self.dark:
            bg = '#0b1220'
            fg = '#e6eef8'
            widget_bg = '#0f1724'
            btn_bg = '#1f2937'
            list_fg = '#ffffff'  # strong readable color for unselected items
            select_bg = '#1e90ff'
        else:
            bg = '#f7fbff'
            fg = '#0b1220'
            widget_bg = '#ffffff'
            btn_bg = '#e6eef8'
            list_fg = '#0b1220'
            select_bg = '#3399ff'
        self.configure(bg=bg)
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame', background=bg)
        style.configure('TLabel', background=bg, foreground=fg)
        style.configure('TButton', background=btn_bg, foreground=fg)
        style.configure('TEntry', fieldbackground=widget_bg)
        # Listbox and Text colors
        self.listbox.configure(bg=widget_bg, fg=list_fg, selectbackground=select_bg)
        self.log.configure(bg=widget_bg, fg=fg, insertbackground=fg)

        # Also try to set per-item foreground so items are readable in dark mode.
        # Not all Tk versions support itemconfig; wrapped in try/except.
        try:
            for idx in range(self.algolist.size()):
                self.algolist.itemconfig(idx, fg=list_fg)
        except Exception:
            # fallback: set overall fg (already set via listbox.configure)
            pass

        # recolor children to propagate bg where tk widgets used
        def recolor(widget):
            try:
                widget.configure(bg=bg)
            except Exception:
                pass
            for child in widget.winfo_children():
                recolor(child)
        recolor(self)

    def toggle_theme(self):
        self.dark = not self.dark
        self._apply_theme()
        self._log(f"Theme set to {'dark' if self.dark else 'light'}")

    # file handlers
    def add_files(self):
        paths = filedialog.askopenfilenames(title="Select files", filetypes=[("All files","*.*")])
        if not paths: return
        added = 0
        for p in paths:
            if p not in self.evidence:
                self.evidence.append(p); self.listbox.insert('end', p); added += 1
        # ensure per-item color stays applied after adding items
        try:
            list_fg = '#ffffff' if self.dark else '#0b1220'
            for idx in range(self.algolist.size()):
                self.algolist.itemconfig(idx, fg=list_fg)
        except Exception:
            pass
        self._log(f"Added {added} file(s)")

    def add_folder(self):
        folder = filedialog.askdirectory(title="Select folder")
        if not folder: return
        added = 0
        for p in pathlib.Path(folder).rglob('*'):
            if p.is_file():
                s = str(p.resolve())
                if s not in self.evidence:
                    self.evidence.append(s); self.listbox.insert('end', s); added += 1
        # ensure algorithms item colors preserved
        try:
            list_fg = '#ffffff' if self.dark else '#0b1220'
            for idx in range(self.algolist.size()):
                self.algolist.itemconfig(idx, fg=list_fg)
        except Exception:
            pass
        self._log(f"Added {added} files from folder {folder}")

    def clear(self):
        self.evidence = [] ; self.listbox.delete(0,'end'); self._log("All files cleared from list.")

    def set_output(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.output_folder = p; self._log(f"Output folder: {p}")

    def generate_report(self):
        if not self.evidence:
            messagebox.showerror("No files", "Please add evidence files or folders first.")
            return
        sel = [self.algolist.get(i) for i in self.algolist.curselection()]
        if not sel:
            messagebox.showerror("No algorithms", "Select at least one hashing algorithm.")
            return
        supported = [a for a in sel if a in hashlib.algorithms_available]
        if not supported:
            messagebox.showerror("Algorithms", "Selected algorithms are not available in this Python environment.")
            return
        manifest = build_manifest_from_files(self.evidence, supported)
        out = self.output_folder or os.path.dirname(self.evidence[0])
        txt = os.path.join(out, "integrity_report.txt")
        lines = write_manifest_txt(manifest, txt)
        self._log(f"TXT report saved: {txt}")
        if REPORTLAB:
            try:
                pdf = os.path.join(out, "integrity_report.pdf")
                write_pdf_report_vertical(manifest, pdf, icon_path=ICON_PATH, icon_width_px=64)
                self._log(f"PDF report saved: {pdf}")
            except Exception as e:
                self._log(f"PDF generation failed: {e}")
        else:
            self._log("reportlab not installed — PDF not generated. Install with: pip install reportlab")
        messagebox.showinfo("Done", f"Report generated (TXT saved to {txt}).")

    def select_manifest(self):
        p = filedialog.askopenfilename(title="Select earlier manifest TXT", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if p:
            self.manifest_file = p; self._log(f"Selected manifest: {p}")

    def run_verification(self):
        if not self.manifest_file:
            messagebox.showerror("No manifest", "Please select a manifest TXT file to verify against.")
            return
        if not self.evidence:
            messagebox.showerror("No evidence", "Please add evidence files to verify.")
            return
        lines, results, summary = verify_manifest_txt_against_files(self.manifest_file, self.evidence)
        out = self.output_folder or os.path.dirname(self.evidence[0])
        txt = os.path.join(out, "verification_result.txt")
        with open(txt, 'w', encoding='utf-8') as fh:
            fh.write("\n".join(lines))
        self._log(f"Verification TXT saved: {txt}")
        pdf = None
        if REPORTLAB:
            try:
                pdf = os.path.join(out, "verification_result.pdf")
                write_pdf_verification_vertical(lines, pdf, icon_path=ICON_PATH, icon_width_px=64)
                self._log(f"Verification PDF saved: {pdf}")
            except Exception as e:
                self._log(f"Verification PDF failed: {e}")
        else:
            self._log("reportlab not installed — verification PDF not generated.")
        # Show the verification result dialog in GUI (filename + status + summary), with buttons to open saved files
        self._show_verification_dialog(results, summary, txt_path=txt, pdf_path=pdf)
        messagebox.showinfo("Verification complete", f"Verification TXT saved: {txt}")

    def _show_verification_dialog(self, results, summary, txt_path=None, pdf_path=None):
        # results: list of tuples (relative_path, status, actual, expected_hashes)
        dlg = tk.Toplevel(self)
        dlg.title("Verification Results")
        dlg.geometry("700x400")
        # summary frame
        sf = ttk.Frame(dlg); sf.pack(fill='x', padx=8, pady=8)
        ttk.Label(sf, text=f"Total: {summary.get('total',0)}").pack(side='left', padx=6)
        ttk.Label(sf, text=f"OK: {summary.get('ok',0)}").pack(side='left', padx=6)
        ttk.Label(sf, text=f"MISMATCH: {summary.get('mismatch',0)}").pack(side='left', padx=6)
        ttk.Label(sf, text=f"MISSING: {summary.get('missing',0)}").pack(side='left', padx=6)
        # buttons to open files if available
        btnf = ttk.Frame(dlg); btnf.pack(fill='x', padx=8, pady=(0,6))
        if txt_path and os.path.exists(txt_path):
            ttk.Button(btnf, text="Open verification TXT", command=lambda: webbrowser.open('file://' + os.path.abspath(txt_path))).pack(side='left', padx=6)
        if pdf_path and os.path.exists(pdf_path):
            ttk.Button(btnf, text="Open verification PDF", command=lambda: webbrowser.open('file://' + os.path.abspath(pdf_path))).pack(side='left', padx=6)
        # Treeview table for per-file status
        cols = ('file','status')
        tv = ttk.Treeview(dlg, columns=cols, show='headings', selectmode='browse')
        tv.heading('file', text='File')
        tv.heading('status', text='Status')
        tv.column('file', width=450)
        tv.column('status', width=100, anchor='center')
        for r in results:
            tv.insert('', 'end', values=(r[0], r[1]))
        tv.pack(fill='both', expand=True, padx=8, pady=8)
        # close button
        ttk.Button(dlg, text="Close", command=dlg.destroy).pack(pady=6)
        # apply same theme colors to dialog
        def style_dialog():
            bg = '#0b1220' if self.dark else '#f7fbff'
            fg = '#e6eef8' if self.dark else '#0b1220'
            dlg.configure(bg=bg)
            try:
                for widget in dlg.winfo_children():
                    widget.configure(bg=bg)
            except Exception:
                pass
        style_dialog()
        dlg.transient(self)
        dlg.grab_set()
        self.wait_window(dlg)

    def _log(self, msg):
        ts = datetime.utcnow().isoformat() + 'Z'
        self.log.insert('end', f"[{ts}] {msg}\n"); self.log.see('end')

if __name__ == "__main__":
    app = App()
    app.mainloop()
