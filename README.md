# HashiCorp Vault Policy Auditor

A Python-based tool (UI and CLI version available) to audit HashiCorp Vault policies for security misconfigurations. It analyzes filesystem paths, capabilities, and wildcards to detect privileges that violate the Principle of Least Privilege.

## Features

* **Security Scanning:** Detects critical risks like `sudo` capability, `*` (full admin) rights, and write access to the `sys/` backend.
* **Smart Wildcard Analysis:** "Explodes" wildcards to show exactly which concrete paths are accessible.
 * **Full Wildcard (`*`):** Matches everything (Greedy).
 * **Segment Wildcard (`+`):** Matches exactly one directory level (e.g., `secret/+/config`).

* **Access Explorer (Reverse Matrix):** View permissions by Path (Who can access `/secret/payroll`?) or by Policy.
* **Professional Reporting:**
 * **HTML:** Interactive dashboard with Sticky Navigation, Executive Summary, Mermaid.js Visual Graphs, and color-coded Risk Tables.
 * **Excel:** Multi-sheet workbook for detailed data analysis.

* **Visual Highlighting:**
 * **Red:** CRITICAL risks and Admin privileges.
 * **Blue:** Implicit paths accessed via wildcards.


* **Portable:** The HTML export is self-contained or bundles dependencies in a simple folder structure.

---

## Installation & Setup

### 1. Clone the Repository

Start by cloning the code to your local machine:

```bash
git clone https://github.com/manjula-aw/hashicorp-vault-policy-auditor.git
cd hashicorp-vault-policy-auditor

```

### 2. Prerequisites

* Python 3.8+
* Pip (Python Package Manager)

### 3. Dependencies

Create a `requirements.txt` file (if not already present) with the following content:

```text
python-hcl2
openpyxl

```

### 4. Setup Virtual Environment

It is recommended to run this tool in an isolated environment.

**Windows (CMD):**

```cmd
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt

```

**Mac / Linux (Bash):**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

---

## Using the GUI Tool

The Graphical User Interface is designed for security engineers to browse, analyze, and visualize data interactively. It launches in **Full Screen** mode for better visibility.

**Run the script:**

**Windows:**

```cmd
python vault_auditor_ui.py

```

**Mac / Linux:**

```bash
python3 vault_auditor_ui.py

```

1. **Select Input:** Click "Browse Folder" to select the directory containing your Policy files (`.hcl` or `.txt`).
2. **Filter (Optional):** Check "Scan files with NO extension" if your files lack extensions, or specify `.hcl, .txt`.
3. **Run Audit:** Click the "RUN AUDIT" button.
4. **Analyze Tabs:**
* **Tab 1 (Risks):** View prioritized security issues (Critical → High → Medium). **CRITICAL** issues are highlighted in Red.
* **Tab 2 (Access Explorer):** Interactive tree view showing who accesses which path.
 * *Blue Text:* Indicates access granted via a wildcard rule.
 * *Red Text:* Indicates risky Admin capabilities.
 * *Controls:* Use **+ Expand All** / **- Collapse All** to navigate quickly.
* **Tab 3 (Policy Inspector):** Deep dive into specific policy files and see which real paths their rules match.

5. **Export:** Use the buttons to generate HTML or Excel reports.

---

## Using the CLI Tool

The Command Line Interface is designed for headless operations or quick scans.

### Basic Run

**Windows:**

```cmd
python vault_audit_cli.py my_policies_folder

```

**Mac / Linux:**

```bash
python3 vault_audit_cli.py my_policies_folder

```

### Generate Reports

**Windows:**

```cmd
python vault_audit_cli.py policies --html report.html --excel report.xlsx

```

**Mac / Linux:**

```bash
python3 vault_audit_cli.py policies --html report.html --excel report.xlsx

```

### Fail on Error (CI/CD Mode)

Use the `--fail-on-critical` flag. If any CRITICAL issues (like `sudo` or `*`) are found, the script returns Exit Code 1. This is useful for scripts that need to stop execution upon finding a risk.

**Windows:**

```cmd
python vault_audit_cli.py policies --fail-on-critical

```

**Mac / Linux:**

```bash
python3 vault_audit_cli.py policies --fail-on-critical

```

---

## Verifying with Test Policies

To verify that the tool correctly identifies security risks, you can run it against a set of known insecure policies.

**1. Prepare Test Data**
The `test_policies` folder contains the following files:

* `critical_sudo_grant.hcl` (Contains sudo capability)
* `lazy_admin_wildcard.hcl` (Contains * capability)
* `system_write_risk.hcl` (Contains write access to sys/)
* `root_path_exposure.hcl` (Contains root path *)
* `concrete_paths.hcl` (Safe paths for wildcard analysis)
* `advanced_syntax_plus.hcl` (Contains + wildcard)

**2. Run the Audit**
Execute the CLI tool against this folder and generate an HTML report.

**Windows:**

```cmd
python vault_audit_cli.py test_policies --html verification_report.html

```

**Mac / Linux:**

```bash
python3 vault_audit_cli.py test_policies --html verification_report.html

```

**3. Verify Results**
Open `verification_report.html` in your browser and check the following:

* **Graph:** Verify lines connecting `lazy_admin_wildcard` to the nodes defined in `concrete_paths`.
* **Risks Table:**
 * Ensure `sudo` and `*` capabilities are flagged as **CRITICAL** (Red).
 * Ensure `sys/` write access is flagged as **HIGH** (Orange).
 * Ensure `advanced_syntax_plus.hcl` is flagged as **MEDIUM** (Yellow) for "Uses Segment Wildcard (+)".


* **Matrix:** Search for `secret/data/dev/app-config`. It should list two policies: `concrete_paths.hcl` (Direct) and `lazy_admin_wildcard.hcl` (Via wildcard - highlighted in Blue).

---

## Security Checks Performed

The tool currently audits for the following misconfigurations:

| Severity | Check | Description |
| --- | --- | --- |
| **CRITICAL** | **Sudo Capability** | Checks if `capabilities = ["sudo"]` is granted. This allows bypassing audit logs and restrictions. |
| **CRITICAL** | **Wildcard Capability** | Checks for `capabilities = ["*"]`. This grants full Admin rights on the path. |
| **HIGH** | **System Write** | Checks for Write/Create/Update access to `sys/`. Allows modification of Auth methods and Audit backends. |
| **HIGH** | **Root Wildcard** | Checks for paths defined as `"*"` or `"/*"`. This applies rules to the entire Vault instance. |
| **MEDIUM** | **Segment Wildcard (+)** | Checks for usage of the `+` character. While valid, it often accidentally exposes sibling paths (e.g. `secret/+/keys` exposes keys for *all* apps). |

---
