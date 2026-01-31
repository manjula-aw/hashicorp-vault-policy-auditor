import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from vault_audit_core import VaultAuditEngine

class VaultAuditTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Hashicorp Vault Policy Auditor")
        
        try:
            self.root.state('zoomed')
        except:
            self.root.attributes('-zoomed', True)
        
        self.engine = VaultAuditEngine()
        self._setup_ui()
        self._setup_styles()

    def _setup_ui(self):
        # Top Frame
        top_frame = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.lbl_status = tk.Label(top_frame, text="No folder selected", bg="#f0f0f0", fg="blue")
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        tk.Button(top_frame, text="Browse Folder", command=self.browse_folder).pack(side=tk.LEFT)
        
        # NEW EXTENSION INPUT
        tk.Label(top_frame, text="Extensions (e.g. .hcl, .txt):", bg="#f0f0f0").pack(side=tk.LEFT, padx=(20, 5))
        self.ent_ext = tk.Entry(top_frame, width=15)
        self.ent_ext.pack(side=tk.LEFT)
        # Placeholder / Default tooltip logic could go here, but empty means Default
        
        tk.Button(top_frame, text="RUN AUDIT", command=self.run_audit, bg="#4CAF50", fg="white").pack(side=tk.RIGHT, padx=10)
        self.btn_export_html = tk.Button(top_frame, text="Export HTML", command=self.export_html, state="disabled")
        self.btn_export_html.pack(side=tk.RIGHT, padx=5)
        self.btn_export_excel = tk.Button(top_frame, text="Export Excel", command=self.export_excel, state="disabled")
        self.btn_export_excel.pack(side=tk.RIGHT, padx=5)

        # Tabs
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Risks
        self.tab_risks = tk.Frame(self.tabs); self.tabs.add(self.tab_risks, text="1. Risks")
        self.tree_risks = self._create_tree(self.tab_risks, ["Severity", "Policy", "Path", "Issue", "Fix"])
        
        # Tab 2: Access Explorer
        self.tab_matrix = tk.Frame(self.tabs); self.tabs.add(self.tab_matrix, text="2. Access Explorer")
        tb_matrix = tk.Frame(self.tab_matrix); tb_matrix.pack(fill=tk.X, padx=5, pady=2)
        tk.Button(tb_matrix, text="+ Expand All", command=lambda: self.expand_all(self.tree_matrix), font=("Arial", 8)).pack(side=tk.LEFT)
        tk.Button(tb_matrix, text="- Collapse All", command=lambda: self.collapse_all(self.tree_matrix), font=("Arial", 8)).pack(side=tk.LEFT, padx=5)
        self.tree_matrix = self._create_tree(self.tab_matrix, ["Capabilities", "Risk"], first_col="Path / Policy")

        # Tab 3: Inspector
        self.tab_policies = tk.Frame(self.tabs); self.tabs.add(self.tab_policies, text="3. Policy Inspector")
        tb_pol = tk.Frame(self.tab_policies); tb_pol.pack(fill=tk.X, padx=5, pady=2)
        tk.Button(tb_pol, text="+ Expand All", command=lambda: self.expand_all(self.tree_policies), font=("Arial", 8)).pack(side=tk.LEFT)
        tk.Button(tb_pol, text="- Collapse All", command=lambda: self.collapse_all(self.tree_policies), font=("Arial", 8)).pack(side=tk.LEFT, padx=5)
        self.tree_policies = self._create_tree(self.tab_policies, ["Capabilities", "Wildcard Matches"], first_col="Policy / Path")

    def _create_tree(self, parent, cols, first_col=None):
        tree = ttk.Treeview(parent, columns=cols)
        if first_col:
            tree.heading("#0", text=first_col)
            tree.column("#0", width=400)
        else:
            tree["show"] = "headings"
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=300)
        sb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(fill=tk.BOTH, expand=True)
        return tree

    def _setup_styles(self):
        self.tree_risks.tag_configure("CRITICAL", foreground="#D32F2F", font=("Segoe UI", 9, "bold"))
        self.tree_risks.tag_configure("HIGH", foreground="#E67E22")
        self.tree_risks.tag_configure("MEDIUM", foreground="#F1C40F")
        self.tree_matrix.tag_configure("ADMIN_RISK", foreground="#D32F2F", font=("Segoe UI", 9, "bold"))
        self.tree_matrix.tag_configure("IMPLICIT", foreground="#3498db")
        self.tree_policies.tag_configure("MATCH", foreground="#3498db")

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

    def browse_folder(self):
        f = filedialog.askdirectory()
        if f: 
            self.selected_folder = f
            self.lbl_status.config(text=f"Selected: {f}")

    def run_audit(self):
        if not hasattr(self, 'selected_folder'): return
        
        for t in [self.tree_risks, self.tree_matrix, self.tree_policies]:
            for i in t.get_children(): t.delete(i)
            
        # PARSE EXTENSIONS
        ext_raw = self.ent_ext.get()
        ext_list = [e.strip() for e in ext_raw.split(",")] if ext_raw.strip() else None

        self.engine.reset()
        self.engine.scan_folder(self.selected_folder, extensions=ext_list)
        self.engine.analyze()
        self._populate_ui()
        
        self.btn_export_html.config(state="normal")
        self.btn_export_excel.config(state="normal")
        messagebox.showinfo("Done", f"Found {self.engine.stats['CRITICAL']} Critical Risks.")

    def _populate_ui(self):
        sev_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.engine.audit_issues.sort(key=lambda x: sev_priority.get(x['sev'], 99))

        for i in self.engine.audit_issues:
            self.tree_risks.insert("", "end", values=(i['sev'], i['pol'], i['path'], i['msg'], i['fix']), tags=(i['sev'],))
            
        for path, entries in sorted(self.engine.path_matrix.items()):
            node = self.tree_matrix.insert("", "end", text=path, open=False)
            for e in entries:
                disp = e['policy'] + (f" (via {e['via']})" if e['via'] else "")
                risk_flag = self.engine.get_risk_flag(e['caps'])
                tags = []
                if "ADMIN" in risk_flag: tags.append("ADMIN_RISK")
                if e['via']: tags.append("IMPLICIT")
                self.tree_matrix.insert(node, "end", text=disp, values=(", ".join(e['caps']), risk_flag), tags=tuple(tags))

        for pol_name, data in sorted(self.engine.policies_data.items()):
            p_node = self.tree_policies.insert("", "end", text=pol_name, open=False)
            for path_block in data['parsed'].get('path', []):
                for path_str, rules in path_block.items():
                    matches_str = ""
                    if ("*" in path_str or "+" in path_str):
                        matches = [m for m in self.engine.all_concrete_paths if self.engine._vault_match(path_str, m)]
                        if matches: matches_str = f"Matches {len(matches)} paths"

                    item_id = self.tree_policies.insert(p_node, "end", text=path_str, values=(", ".join(rules.get('capabilities', [])).upper(), matches_str))
                    if matches_str:
                         for m in matches: self.tree_policies.insert(item_id, "end", text=f"↳ {m}", values=("(Inherited)", ""), tags=("MATCH",))

    def export_html(self):
        f = filedialog.asksaveasfilename(defaultextension=".html", initialfile="vault_audit_report.html", filetypes=[("HTML", "*.html")])
        if f:
            self.engine.export_html(f)
            messagebox.showinfo("Success", "Exported HTML")

    def export_excel(self):
        f = filedialog.asksaveasfilename(defaultextension=".xlsx", initialfile="vault_audit_report.xlsx", filetypes=[("Excel", "*.xlsx")])
        if f:
            self.engine.export_excel(f)
            messagebox.showinfo("Success", "Exported Excel")

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultAuditTool(root)
    root.mainloop()
