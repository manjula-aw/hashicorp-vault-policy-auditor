import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import fnmatch
from vault_audit_core import VaultAuditEngine

class VaultAuditTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Vault Policy Auditor (Modular UI)")
        self.root.geometry("1500x900")
        
        # Initialize Engine
        self.engine = VaultAuditEngine()
        self.var_no_ext = tk.BooleanVar(value=True) 

        # UI Setup
        self._setup_ui()

    def _setup_ui(self):
        # Top Frame
        top_frame = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.lbl_status = tk.Label(top_frame, text="No folder selected", bg="#f0f0f0", fg="blue")
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        tk.Button(top_frame, text="Browse Folder", command=self.browse_folder).pack(side=tk.LEFT)
        tk.Checkbutton(top_frame, text="No Extension Mode", variable=self.var_no_ext, bg="#f0f0f0").pack(side=tk.LEFT, padx=20)
        
        tk.Button(top_frame, text="RUN AUDIT", command=self.run_audit, bg="#4CAF50", fg="white").pack(side=tk.RIGHT, padx=10)
        self.btn_export_html = tk.Button(top_frame, text="Export HTML", command=self.export_html, state="disabled")
        self.btn_export_html.pack(side=tk.RIGHT, padx=5)
        self.btn_export_excel = tk.Button(top_frame, text="Export Excel", command=self.export_excel, state="disabled")
        self.btn_export_excel.pack(side=tk.RIGHT, padx=5)

        # Tabs
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tab_risks = tk.Frame(self.tabs); self.tabs.add(self.tab_risks, text="1. Risks")
        self.tree_risks = self._create_tree(self.tab_risks, ["Severity", "Policy", "Path", "Issue", "Fix"])
        
        self.tab_matrix = tk.Frame(self.tabs); self.tabs.add(self.tab_matrix, text="2. Matrix")
        self.tree_matrix = self._create_tree(self.tab_matrix, ["Capabilities", "Risk"], first_col="Path / Policy")

    def _create_tree(self, parent, cols, first_col=None):
        tree = ttk.Treeview(parent, columns=cols)
        if first_col:
            tree.heading("#0", text=first_col)
            tree.column("#0", width=400)
        else:
            tree["show"] = "headings"
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=200)
        tree.pack(fill=tk.BOTH, expand=True)
        return tree

    def browse_folder(self):
        f = filedialog.askdirectory()
        if f: 
            self.selected_folder = f
            self.lbl_status.config(text=f"Selected: {f}")

    def run_audit(self):
        if not hasattr(self, 'selected_folder'): return
        
        # Clear UI
        for t in [self.tree_risks, self.tree_matrix]:
            for i in t.get_children(): t.delete(i)
            
        # Use Engine
        self.engine.reset()
        self.engine.scan_folder(self.selected_folder, ignore_extensions=self.var_no_ext.get())
        self.engine.analyze()
        
        # Populate UI
        self._populate_ui()
        
        self.btn_export_html.config(state="normal")
        self.btn_export_excel.config(state="normal")
        messagebox.showinfo("Done", f"Found {self.engine.stats['CRITICAL']} Critical Risks.")

    def _populate_ui(self):
        # Risks
        for i in self.engine.audit_issues:
            self.tree_risks.insert("", "end", values=(i['sev'], i['pol'], i['path'], i['msg'], i['fix']))
            
        # Matrix
        for path, entries in sorted(self.engine.path_matrix.items()):
            node = self.tree_matrix.insert("", "end", text=path, open=False)
            for e in entries:
                disp = e['policy'] + (f" (via {e['via']})" if e['via'] else "")
                self.tree_matrix.insert(node, "end", text=disp, values=(", ".join(e['caps']), self.engine.get_risk_flag(e['caps'])))

    def export_html(self):
        f = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if f:
            self.engine.export_html(f)
            messagebox.showinfo("Success", "Exported HTML")

    def export_excel(self):
        f = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if f:
            self.engine.export_excel(f)
            messagebox.showinfo("Success", "Exported Excel")

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultAuditTool(root)
    root.mainloop()
