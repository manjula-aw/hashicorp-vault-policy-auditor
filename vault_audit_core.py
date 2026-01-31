import os
import hcl2
import fnmatch
import html
import datetime
import re
import shutil
import openpyxl
from openpyxl.styles import Font, PatternFill

class VaultAuditEngine:
    def __init__(self):
        # Core Data Structures
        self.policies_data = {}       # {filename: {'parsed': ..., 'raw': ..., 'path': ...}}
        self.path_matrix = {}         # {path: [{'policy':..., 'caps':..., 'via':...}]}
        self.all_concrete_paths = set()
        self.audit_issues = []        # [{'sev':..., 'pol':..., 'msg':..., 'fix':...}]
        self.processing_log = []      # [{'file':..., 'status':..., 'msg':...}]
        self.stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def reset(self):
        self.__init__()

    def scan_folder(self, folder_path, ignore_extensions=True):
        """Scans a directory and parses policy files."""
        if not os.path.exists(folder_path):
            raise FileNotFoundError(f"Directory not found: {folder_path}")

        for root, _, files in os.walk(folder_path):
            for filename in files:
                if filename.startswith('.'): continue
                
                _, ext = os.path.splitext(filename)
                if ignore_extensions and ext != "":
                    continue
                
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r') as f: raw_content = f.read()
                    with open(filepath, 'r') as f: parsed_dict = hcl2.load(f)
                    
                    self.policies_data[filename] = {
                        'parsed': parsed_dict, 
                        'raw': raw_content, 
                        'path': filepath
                    }
                    self.processing_log.append({"file": filename, "status": "SUCCESS", "msg": "Parsed OK"})
                    
                    # Index concrete paths
                    for path_block in parsed_dict.get('path', []):
                        for path_str, _ in path_block.items():
                            if "*" not in path_str:
                                self.all_concrete_paths.add(path_str)
                                
                except Exception as e:
                    self.processing_log.append({"file": filename, "status": "FAILED", "msg": str(e)})

    def analyze(self):
        """Performs the security analysis and wildcard mapping."""
        # 1. Direct Analysis
        for policy_name, data in self.policies_data.items():
            paths = data['parsed'].get('path', [])
            for path_entry in paths:
                for path_str, rules in path_entry.items():
                    caps = rules.get('capabilities', [])
                    if isinstance(caps, str): caps = [caps]
                    
                    if path_str not in self.path_matrix: self.path_matrix[path_str] = []
                    self.path_matrix[path_str].append({"policy": policy_name, "caps": caps, "via": None})
                    self._check_security(policy_name, path_str, caps)

        # 2. Wildcard Injection
        for concrete_path in self.all_concrete_paths:
            for policy_name, data in self.policies_data.items():
                paths = data['parsed'].get('path', [])
                for path_entry in paths:
                    for rule_path, rules in path_entry.items():
                        if "*" in rule_path and fnmatch.fnmatch(concrete_path, rule_path):
                            # Don't add if explicit exists
                            exists = any(x for x in self.path_matrix.get(concrete_path, []) 
                                         if x['policy'] == policy_name and x['via'] is None)
                            if not exists:
                                caps = rules.get('capabilities', [])
                                if isinstance(caps, str): caps = [caps]
                                self.path_matrix[concrete_path].append(
                                    {"policy": policy_name, "caps": caps, "via": rule_path}
                                )

    def _check_security(self, policy, path, caps):
        caps_lower = [c.lower() for c in caps]
        issue = None
        
        if "sudo" in caps_lower:
            issue = {"sev": "CRITICAL", "msg": "Grants 'sudo' capability", "fix": "Remove 'sudo' unless for root admin."}
        elif "*" in caps_lower:
            issue = {"sev": "CRITICAL", "msg": "Grants '*' capability", "fix": "Replace '*' with specific list [\"read\"]."}
        elif path.startswith("sys/") and any(x in caps_lower for x in ["create", "update", "delete", "sudo"]):
            issue = {"sev": "HIGH", "msg": "Write access to System Backend", "fix": "Restrict to read-only."}
        elif path == "*" or path == "/*":
            issue = {"sev": "HIGH", "msg": "Root wildcard path", "fix": "Scope to specific paths."}

        if issue:
            issue.update({"pol": policy, "path": path})
            self.audit_issues.append(issue)
            if issue['sev'] in self.stats:
                self.stats[issue['sev']] += 1

    def sanitize_id(self, s):
        return re.sub(r'[^a-zA-Z0-9]', '_', s)

    def get_risk_flag(self, caps):
        caps_str = ", ".join(caps).upper()
        if "SUDO" in caps_str or "*" in caps_str: return "⚠ ADMIN"
        return ""

    # --- REPORTING ---

    def export_excel(self, file_path):
        wb = openpyxl.Workbook()
        
        # Styles
        header_fill = PatternFill(start_color="34495E", end_color="34495E", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        crit_fill = PatternFill(start_color="E74C3C", fill_type="solid")

        # Sheet 1: Risks
        ws = wb.active; ws.title = "Security Risks"
        ws.append(["Severity", "Policy", "Path", "Issue", "Recommendation"])
        for cell in ws[1]: cell.fill, cell.font = header_fill, header_font

        for i in self.audit_issues:
            ws.append([i['sev'], i['pol'], i['path'], i['msg'], i['fix']])
            if i['sev'] == "CRITICAL":
                ws.cell(row=ws.max_row, column=1).fill = crit_fill

        # Sheet 2: Matrix
        ws2 = wb.create_sheet("Access Matrix")
        ws2.append(["Path", "Policy", "Via", "Capabilities", "Risk"])
        for cell in ws2[1]: cell.fill, cell.font = header_fill, header_font

        for path in sorted(self.path_matrix.keys()):
            for entry in self.path_matrix[path]:
                via = entry['via'] if entry['via'] else "Direct"
                caps = ", ".join(entry['caps']).upper()
                risk = self.get_risk_flag(entry['caps'])
                ws2.append([path, entry['policy'], via, caps, risk])

        # Sheet 3: Log
        ws3 = wb.create_sheet("Processing Log")
        ws3.append(["File", "Status", "Message"])
        for cell in ws3[1]: cell.fill, cell.font = header_fill, header_font
        for item in self.processing_log:
            ws3.append([item['file'], item['status'], item['msg']])

        wb.save(file_path)

    def export_html(self, file_path):
        # Logic to copy mermaid.min.js if available locally
        save_dir = os.path.dirname(file_path)
        script_dir = os.path.join(save_dir, "script")
        app_dir = os.path.dirname(os.path.abspath(__file__))
        mermaid_src = os.path.join(app_dir, "mermaid.min.js")
        mermaid_dest = os.path.join(script_dir, "mermaid.min.js")
        
        mermaid_tag = '<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs"; mermaid.initialize({ startOnLoad: true });</script>'
        
        if os.path.exists(mermaid_src):
            try:
                if not os.path.exists(script_dir): os.makedirs(script_dir)
                shutil.copy2(mermaid_src, mermaid_dest)
                mermaid_tag = '<script src="script/mermaid.min.js"></script>\n<script>mermaid.initialize({ startOnLoad: true });</script>'
            except Exception as e:
                print(f"Warning: Could not copy local mermaid script: {e}")

        # Graph Generation
        graph_def = "graph LR\n"
        has_graph = False
        for issue in self.audit_issues:
            if issue['sev'] in ["CRITICAL", "HIGH"]:
                pol_id = self.sanitize_id(issue['pol'])
                path_id = self.sanitize_id(issue['path'])
                graph_def += f"    {pol_id}[\"{html.escape(issue['pol'])}\"] -->|Risky| {path_id}(\"{html.escape(issue['path'])}\")\n"
                has_graph = True
        
        graph_def += "    classDef policy fill:#e1f5fe,stroke:#01579b,stroke-width:2px;\n"
        graph_def += "    classDef risk fill:#ffcdd2,stroke:#b71c1c,stroke-width:2px;\n"
        if not has_graph: graph_def += "    Ok[No High Risks Detected]:::policy\n"

        # HTML Rows
        rows = ""
        for i in self.audit_issues:
            sev_c = f"bg-{i['sev'].lower()}"
            rows += f"<tr><td><span class='badge {sev_c}'>{i['sev']}</span></td><td>{html.escape(i['pol'])}</td><td><span class='path-mono'>{html.escape(i['path'])}</span></td><td>{html.escape(i['msg'])}</td><td>{html.escape(i['fix'])}</td></tr>"

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML Template (Condensed for brevity)
        html_content = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Vault Audit</title>{mermaid_tag}
        <style>:root{{--bg:#f4f6f8;--white:#fff;--danger:#e74c3c;--warning:#f39c12;}} body{{font-family:sans-serif;background:var(--bg);padding:20px;}} .card{{background:var(--white);padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 5px rgba(0,0,0,0.05);}} table{{width:100%;border-collapse:collapse;}} th,td{{padding:12px;border-bottom:1px solid #eee;text-align:left;}} .badge{{padding:4px 8px;border-radius:12px;color:white;font-weight:bold;font-size:0.8em;}} .bg-critical{{background:var(--danger);}} .bg-high{{background:var(--warning);}} .bg-medium{{background:#f1c40f;color:#333;}} .bg-low{{background:#95a5a6;}} .path-mono{{font-family:monospace;color:#e83e8c;background:#fdf0f5;padding:2px 5px;}} .mermaid{{text-align:center;}}</style>
        </head><body><div class="container"><div class="card"><h1>Vault Policy Audit Report</h1><p>{timestamp}</p></div>
        <div class="card"><h2>Risk Graph</h2><div class="mermaid">{graph_def}</div></div>
        <div class="card"><h2>Security Risks</h2><table><thead><tr><th>Severity</th><th>Policy</th><th>Path</th><th>Issue</th><th>Fix</th></tr></thead><tbody>{rows}</tbody></table></div></div></body></html>"""

        with open(file_path, "w", encoding="utf-8") as f: f.write(html_content)
