import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import datetime
from vault_audit_core import VaultAuditEngine

# --- CUSTOM TOOLTIP CLASS ---
class ToolTip(object):
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tipwindow or not self.text: return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 27
        y = y + cy + self.widget.winfo_rooty() + 27
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                       background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                       font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw: tw.destroy()

def create_tooltip(widget, text):
    toolTip = ToolTip(widget)
    def enter(event): toolTip.showtip(text)
    def leave(event): toolTip.hidetip()
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)

# --- MAIN APPLICATION ---
class VaultAuditTool:
    def __init__(self, root):
        self.root = root
        self.root.title("HashiCorp Vault Policy Auditor v28 (Stable)")
        
        # Start Maximized
        try: self.root.state('zoomed')
        except: self.root.attributes('-zoomed', True)
        
        self.engine = VaultAuditEngine()
        
        # Data storage for filtering/sorting
        self.tree_data = {
            "risks": [],
            "matrix": [],
            "policies": []
        }

        self._setup_styles()
        self._setup_layout()
        
        # Context Menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy Path", command=self.copy_to_clipboard)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="View Details", command=self.show_details)

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam') # 'clam' allows better color customization than 'vista'
        
        # 1. General App Styling
        self.root.configure(bg="#F0F2F5")
        
        # 2. Treeview Header Styling (Bold, spacing)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#E2E8F0", foreground="#2D3748", relief="flat")
        style.map("Treeview.Heading", background=[('active', '#CBD5E0')])
        
        # 3. Treeview Row Styling
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=30, borderwidth=0, background="white")
        style.map("Treeview", background=[('selected', '#3182CE')], foreground=[('selected', 'white')])
        
        # 4. Severity Colors (Background / Foreground pairs)
        self.tag_critical = {'background': '#FFF5F5', 'foreground': '#C53030'} 
        self.tag_high = {'background': '#FFFAF0', 'foreground': '#C05621'}
        self.tag_medium = {'background': '#FFFFF0', 'foreground': '#B7791F'}
        self.tag_zebra = {'background': '#F7FAFC'}

    def _setup_layout(self):
        # --- HEADER ---
        header = tk.Frame(self.root, bg="white", padx=15, pady=15, relief="flat")
        header.pack(fill=tk.X, side=tk.TOP)
        
        # Title & Subtitle
        title_frame = tk.Frame(header, bg="white")
        title_frame.pack(side=tk.LEFT)
        tk.Label(title_frame, text="Vault Policy Auditor", font=("Segoe UI", 16, "bold"), bg="white", fg="#2D3748").pack(anchor="w")
        self.lbl_subtitle = tk.Label(title_frame, text="Ready to scan", font=("Segoe UI", 9), bg="white", fg="#718096")
        self.lbl_subtitle.pack(anchor="w")

        # Controls Frame
        controls = tk.Frame(header, bg="white")
        controls.pack(side=tk.RIGHT)
        
        # 1. Browse
        btn_browse = tk.Button(controls, text="📂 Browse Folder", command=self.browse_folder, 
                             bg="#EDF2F7", fg="#2D3748", relief="flat", font=("Segoe UI", 9), padx=10, pady=5)
        btn_browse.pack(side=tk.LEFT, padx=5)
        
        # 2. Extensions
        tk.Label(controls, text="Ext:", bg="white", fg="#718096").pack(side=tk.LEFT, padx=(10,2))
        self.ent_ext = tk.Entry(controls, width=8, relief="solid", bd=1)
        self.ent_ext.pack(side=tk.LEFT)
        create_tooltip(self.ent_ext, "Comma separated (e.g. .hcl, .txt). Leave empty for no extension.")

        # 3. Search Filter
        tk.Label(controls, text="🔍 Filter:", bg="white", fg="#718096").pack(side=tk.LEFT, padx=(15,2))
        self.var_search = tk.StringVar()
        
        # --- FIX: Replaced .trace() with .trace_add() ---
        self.var_search.trace_add("write", self.on_filter_change)
        
        self.ent_search = tk.Entry(controls, textvariable=self.var_search, width=20, relief="solid", bd=1)
        self.ent_search.pack(side=tk.LEFT)

        # 4. Exports
        tk.Frame(controls, width=20, bg="white").pack(side=tk.LEFT) # Spacer
        self.btn_html = tk.Button(controls, text="⬇ HTML", command=self.export_html, state="disabled", bg="#E2E8F0", relief="flat", padx=10)
        self.btn_html.pack(side=tk.LEFT, padx=2)
        self.btn_excel = tk.Button(controls, text="⬇ Excel", command=self.export_excel, state="disabled", bg="#E2E8F0", relief="flat", padx=10)
        self.btn_excel.pack(side=tk.LEFT, padx=2)

        # 5. Run Action
        self.btn_run = tk.Button(controls, text="▶ RUN AUDIT", command=self.run_audit, 
                               bg="#48BB78", fg="white", font=("Segoe UI", 9, "bold"), relief="flat", padx=15, pady=5)
        self.btn_run.pack(side=tk.LEFT, padx=15)

        # --- MAIN SPLIT VIEW (Content + Side Panel) ---
        self.paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # LEFT PANE: Notebook
        self.notebook = ttk.Notebook(self.paned)
        self.paned.add(self.notebook, weight=3)
        
        # Tab 1: Risks
        self.frame_risks = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.frame_risks, text=" Risks ")
        self.tree_risks = self._create_tree(self.frame_risks, ["Severity", "Policy", "Path", "Issue", "Recommendation"])
        
        # Tab 2: Access Explorer
        self.frame_matrix = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.frame_matrix, text=" Access Explorer ")
        self._add_tree_toolbar(self.frame_matrix, self.tree_matrix_action)
        self.tree_matrix = self._create_tree(self.frame_matrix, ["Capabilities", "Risk Level"], first_col="Path / Policy")

        # Tab 3: Policy Inspector
        self.frame_inspector = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.frame_inspector, text=" Policy Inspector ")
        self._add_tree_toolbar(self.frame_inspector, self.tree_inspector_action)
        self.tree_inspector = self._create_tree(self.frame_inspector, ["Capabilities", "Matches"], first_col="Policy / Path")

        # RIGHT PANE: Details Panel
        self.details_frame = tk.Frame(self.paned, bg="white", bd=1, relief="solid")
        self.paned.add(self.details_frame, weight=1)
        
        tk.Label(self.details_frame, text="Item Details", font=("Segoe UI", 11, "bold"), bg="#F7FAFC", pady=5).pack(fill=tk.X)
        self.txt_details = tk.Text(self.details_frame, wrap=tk.WORD, font=("Consolas", 9), bg="white", relief="flat", padx=10, pady=10)
        self.txt_details.pack(fill=tk.BOTH, expand=True)
        self.txt_details.insert("1.0", "Select a row to view details...")
        self.txt_details.config(state="disabled")

        # --- STATUS BAR ---
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#E2E8F0", font=("Segoe UI", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_tree(self, parent, cols, first_col=None):
        frame = tk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tree = ttk.Treeview(frame, columns=cols, selectmode="browse")
        
        # Scrollbars
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)

        # Columns
        if first_col:
            tree.heading("#0", text=first_col, command=lambda: self.sort_column(tree, "#0", False))
            tree.column("#0", width=300)
        else:
            tree["show"] = "headings"
        
        for c in cols:
            tree.heading(c, text=c, command=lambda: self.sort_column(tree, c, False))
            tree.column(c, width=150)

        # Tags configuration
        tree.tag_configure("CRITICAL", **self.tag_critical)
        tree.tag_configure("HIGH", **self.tag_high)
        tree.tag_configure("MEDIUM", **self.tag_medium)
        tree.tag_configure("odd", **self.tag_zebra)
        tree.tag_configure("IMPLICIT", foreground="#3182CE") 
        
        # Bindings
        tree.bind("<<TreeviewSelect>>", self.on_select)
        tree.bind("<Button-3>", self.show_context_menu)
        
        return tree

    def _add_tree_toolbar(self, parent, action_callback):
        tb = tk.Frame(parent, bg="#F7FAFC", pady=2)
        tb.pack(fill=tk.X)
        tk.Button(tb, text="+ Expand All", command=lambda: action_callback("expand"), 
                bg="white", relief="solid", bd=1, font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=5)
        tk.Button(tb, text="- Collapse All", command=lambda: action_callback("collapse"), 
                bg="white", relief="solid", bd=1, font=("Segoe UI", 8)).pack(side=tk.LEFT)

    # --- ACTIONS ---

    def browse_folder(self):
        f = filedialog.askdirectory()
        if f: 
            self.selected_folder = f
            self.lbl_subtitle.config(text=f"Target: {f}")

    def run_audit(self):
        if not hasattr(self, 'selected_folder'): 
            messagebox.showwarning("Warning", "Please select a folder first.")
            return

        # UI Reset
        for t in [self.tree_risks, self.tree_matrix, self.tree_inspector]:
            for i in t.get_children(): t.delete(i)
        
        # Extensions
        ext_raw = self.ent_ext.get()
        ext_list = [e.strip() for e in ext_raw.split(",")] if ext_raw.strip() else None

        # Run Engine
        self.status_bar.config(text="Scanning... please wait.")
        self.root.update()
        
        try:
            self.engine.reset()
            self.engine.scan_folder(self.selected_folder, extensions=ext_list)
            self.engine.analyze()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        # Store Data for sorting/filtering
        self.store_data()
        
        # Populate UI
        self.populate_trees()
        self.update_tabs_and_status()
        
        self.btn_html.config(state="normal")
        self.btn_excel.config(state="normal")

    def store_data(self):
        # Flatten Risks
        self.tree_data["risks"] = []
        sev_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_issues = sorted(self.engine.audit_issues, key=lambda x: sev_priority.get(x['sev'], 99))
        
        for i in sorted_issues:
            icon = "🔴" if i['sev'] == "CRITICAL" else "🟠" if i['sev'] == "HIGH" else "🟡" if i['sev'] == "MEDIUM" else "⚪"
            # Display severity with Icon
            display_sev = f"{icon} {i['sev']}"
            self.tree_data["risks"].append((display_sev, i['pol'], i['path'], i['msg'], i['fix'], i['sev'])) # Store raw sev at end

    def populate_trees(self, filter_text=""):
        # 1. Risks
        self.tree_risks.delete(*self.tree_risks.get_children())
        filter_text = filter_text.lower()
        
        for idx, item in enumerate(self.tree_data["risks"]):
            # item = (DisplaySev, Pol, Path, Msg, Fix, RawSev)
            if filter_text and not any(filter_text in str(x).lower() for x in item): continue
            
            raw_sev = item[5]
            row_tag = "odd" if idx % 2 != 0 else "even"
            tags = (raw_sev, row_tag)
            
            self.tree_risks.insert("", "end", values=item[:5], tags=tags)

        # 2. Access Matrix
        self.tree_matrix.delete(*self.tree_matrix.get_children())
        for path, entries in sorted(self.engine.path_matrix.items()):
            if filter_text and filter_text not in path.lower(): continue 
            
            node = self.tree_matrix.insert("", "end", text=path, open=False)
            for e in entries:
                disp = f"{e['policy']}" + (f" (via {e['via']})" if e['via'] else "")
                risk = self.engine.get_risk_flag(e['caps'])
                tags = ["IMPLICIT"] if e['via'] else []
                self.tree_matrix.insert(node, "end", text=disp, values=(", ".join(e['caps']), risk), tags=tags)

        # 3. Inspector
        self.tree_inspector.delete(*self.tree_inspector.get_children())
        for pol_name, data in sorted(self.engine.policies_data.items()):
            if filter_text and filter_text not in pol_name.lower(): continue 
            
            p_node = self.tree_inspector.insert("", "end", text=pol_name, open=False)
            for path_block in data['parsed'].get('path', []):
                for path_str, rules in path_block.items():
                    matches_str = ""
                    if ("*" in path_str or "+" in path_str):
                        matches = [m for m in self.engine.all_concrete_paths if self.engine._vault_match(path_str, m)]
                        if matches: matches_str = f"Matches {len(matches)} paths"
                    
                    item_id = self.tree_inspector.insert(p_node, "end", text=path_str, values=(", ".join(rules.get('capabilities', [])).upper(), matches_str))
                    if matches_str:
                         for m in matches: self.tree_inspector.insert(item_id, "end", text=f"↳ {m}", values=("(Inherited)", ""), tags=("IMPLICIT",))

    def update_tabs_and_status(self):
        c_risk = len(self.tree_risks.get_children())
        c_matrix = len(self.engine.path_matrix)
        c_pol = len(self.engine.policies_data)
        
        self.notebook.tab(0, text=f" Risks ({c_risk}) ")
        self.notebook.tab(1, text=f" Access Explorer ({c_matrix}) ")
        self.notebook.tab(2, text=f" Policy Inspector ({c_pol}) ")
        
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        stats = self.engine.stats
        msg = f"Last Scan: {ts} | Scanned: {c_pol} Policies | Found: {stats['CRITICAL']} Critical, {stats['HIGH']} High, {stats['MEDIUM']} Medium"
        self.status_bar.config(text=msg)

    # --- INTERACTION ---

    def on_filter_change(self, *args):
        txt = self.var_search.get()
        self.populate_trees(txt)

    def on_select(self, event):
        tree = event.widget
        selected_item = tree.selection()
        if not selected_item: return
        
        item = tree.item(selected_item[0])
        vals = item['values']
        txt = item['text']
        
        self.txt_details.config(state="normal")
        self.txt_details.delete("1.0", tk.END)
        
        self.txt_details.insert(tk.END, "--- SELECTION DETAILS ---\n\n")
        if txt: self.txt_details.insert(tk.END, f"Node: {txt}\n")
        if vals:
            for v in vals: self.txt_details.insert(tk.END, f"- {v}\n")
            
        self.txt_details.config(state="disabled")

    def sort_column(self, tree, col, reverse):
        l = [(tree.set(k, col), k) for k in tree.get_children('')]
        l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            tree.move(k, '', index)
            row_tag = "odd" if index % 2 != 0 else "even"
            current_tags = list(tree.item(k, "tags"))
            if "odd" in current_tags: current_tags.remove("odd")
            if "even" in current_tags: current_tags.remove("even")
            current_tags.append(row_tag)
            tree.item(k, tags=current_tags)
            
        tree.heading(col, command=lambda: self.sort_column(tree, col, not reverse))

    def show_context_menu(self, event):
        try:
            tree = event.widget
            item = tree.identify_row(event.y)
            if item:
                tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except: pass

    def copy_to_clipboard(self):
        try:
            self.root.clipboard_clear()
            widget = self.root.focus_get()
            if isinstance(widget, ttk.Treeview):
                item = widget.selection()[0]
                text = widget.item(item)['values'][2] 
                if not text: text = widget.item(item)['text']
                self.root.clipboard_append(text)
                self.status_bar.config(text="Copied to clipboard")
        except: pass

    def show_details(self):
        self.txt_details.focus_set()

    def tree_matrix_action(self, action):
        if action == "expand": self.expand_all(self.tree_matrix)
        else: self.collapse_all(self.tree_matrix)

    def tree_inspector_action(self, action):
        if action == "expand": self.expand_all(self.tree_inspector)
        else: self.collapse_all(self.tree_inspector)

    def expand_all(self, tree):
        def _expand_recursive(item):
            tree.item(item, open=True)
            for child in tree.get_children(item): _expand_recursive(child)
        for item in tree.get_children(): _expand_recursive(item)

    def collapse_all(self, tree):
        def _collapse_recursive(item):
            tree.item(item, open=False)
            for child in tree.get_children(item): _collapse_recursive(child)
        for item in tree.get_children(): _collapse_recursive(item)

    def export_html(self):
        f = filedialog.asksaveasfilename(defaultextension=".html", initialfile="vault_audit_report.html", filetypes=[("HTML", "*.html")])
        if f: self.engine.export_html(f); messagebox.showinfo("Success", "Exported HTML")

    def export_excel(self):
        f = filedialog.asksaveasfilename(defaultextension=".xlsx", initialfile="vault_audit_report.xlsx", filetypes=[("Excel", "*.xlsx")])
        if f: self.engine.export_excel(f); messagebox.showinfo("Success", "Exported Excel")

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultAuditTool(root)
    root.mainloop()
