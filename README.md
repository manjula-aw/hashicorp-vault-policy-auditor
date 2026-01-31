# HashiCorp Vault Policy Auditor

A Python-based tool (with UI and CLI versions) to audit HashiCorp Vault policies for security misconfigurations. It analyzes filesystem paths, capabilities, and wildcards to detect privileges that violate the Principle of Least Privilege.

## Features

* **Security Scanning:** Detects critical risks like `sudo` capability, `*` (full admin) rights, and write access to the `sys/` backend.
* **Wildcard Analysis:** "Explodes" wildcards to show exactly which concrete paths are accessible by a broad rule.
* **Reverse Access Matrix:** View permissions by Path (Who can access `/secret/payroll`?) or by Policy.
* **Professional Reporting:**
* **HTML:** Interactive dashboard with Executive Summary, Mermaid.js Visual Graphs, and Remediation advice.
* **Excel:** Multi-sheet workbook for detailed data analysis.


* **Portable:** The HTML export is self-contained or bundles dependencies in a simple folder structure.

---

## Installation & Setup

### 1. Prerequisites

* Python 3.8+
* Pip (Python Package Manager)

### 2. Dependencies

Create a `requirements.txt` file with the following content:

```text
python-hcl2
openpyxl

```

### 3. Setup Virtual Environment

It is recommended to run this tool in an isolated environment.

Open Command Prompt (`cmd.exe`) in your project folder and run:

```cmd
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt

```

---

## Using the GUI Tool

The Graphical User Interface is designed for security engineers to browse, analyze, and visualize data interactively.

**Run the script:**

```cmd
python vault_auditor_ui.py

```

1. **Select Input:** Click "Browse Folder" to select the directory containing your Policy files (`.hcl` or `.txt`).
2. **Filter (Optional):** Check "Scan files with NO extension" if your files lack extensions, or specify `.hcl, .txt`.
3. **Run Audit:** Click the "RUN AUDIT" button.
4. **Analyze Tabs:**
* **Tab 1 (Risks):** View Critical/High security issues and remediation steps.
* **Tab 2 (Matrix):** See who accesses specific paths.
* **Tab 3 (Inspector):** Deep dive into specific policy files.


5. **Export:** Use the buttons to generate HTML or Excel reports.

---

## Using the CLI Tool

The Command Line Interface is designed for headless operations or quick scans.

**Basic Run:**

```cmd
python vault_audit_cli.py my_policies_folder

```

**Generate Reports:**

```cmd
python vault_audit_cli.py policies --html report.html --excel report.xlsx

```

**Fail on Error (Exit Code 1):**
Use the `--fail-on-critical` flag. If any CRITICAL issues (like `sudo` or `*`) are found, the script returns Exit Code 1. This is useful for scripts that need to stop execution upon finding a risk.

```cmd
python vault_audit_cli.py policies --fail-on-critical

```

---

## Verifying with Test Policies

To verify that the tool correctly identifies security risks, you can run it against a set of known insecure policies.

**1. Prepare Test Data**
Create a new folder named `test_policies` and populate it with the following files (refer to the test policy set provided):

* `critical_sudo_grant.hcl` (Contains sudo capability)
* `lazy_admin_wildcard.hcl` (Contains * capability)
* `system_write_risk.hcl` (Contains write access to sys/)
* `root_path_exposure.hcl` (Contains root path *)
* `concrete_paths.hcl` (Safe paths for wildcard analysis)
* `advanced_syntax_plus.hcl` (Contains + wildcard)

**2. Run the Audit**
Execute the CLI tool against this folder and generate an HTML report.

```cmd
python vault_audit_cli.py test_policies --html verification_report.html

```

**3. Verify Results**
Open `verification_report.html` in your browser and check the following:

* **Graph:** Verify lines connecting `lazy_admin_wildcard` to the nodes defined in `concrete_paths`.
* **Risks Table:** Ensure `sudo` and `*` capabilities are flagged as **CRITICAL**, and `sys/` write access is flagged as **HIGH**.
* **Matrix:** Search for `secret/data/dev/app-config`. It should list two policies: `concrete_paths.hcl` (Direct) and `lazy_admin_wildcard.hcl` (Via wildcard).

---

## Security Checks Performed

The tool currently audits for the following misconfigurations:

| Severity | Check | Description |
| --- | --- | --- |
| **CRITICAL** | **Sudo Capability** | Checks if `capabilities = ["sudo"]` is granted. This allows bypassing audit logs and restrictions. |
| **CRITICAL** | **Wildcard Capability** | Checks for `capabilities = ["*"]`. This grants full Admin rights on the path. |
| **HIGH** | **System Write** | Checks for Write/Create/Update access to `sys/`. Allows modification of Auth methods and Audit backends. |
| **HIGH** | **Root Wildcard** | Checks for paths defined as `"*"` or `"/*"`. This applies rules to the entire Vault instance. |

---
