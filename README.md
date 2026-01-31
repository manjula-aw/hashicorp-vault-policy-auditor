# HashiCorp Vault Policy Auditor

A Python-based tool to audit HashiCorp Vault policies for security misconfigurations. It analyzes filesystem paths, capabilities, and wildcards to detect privileges that violate the Principle of Least Privilege, and to highlight overly permissive policies.

## Features

* **Security Scanning:** Detects critical risks like `sudo` capability, `*` (full admin) rights, and write access to the `sys/` backend.
* **Wildcard Analysis:** "Explodes" wildcards to show exactly which concrete paths are accessible by a broad rule.
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

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

---

## Using the GUI Tool

**Run the script:**

```bash
python vault_auditor_ui.py

```

1. **Select Input:** Browse to the directory containing your `.hcl` or `.txt` policy files.
2. **Run Audit:** Click the green **RUN AUDIT** button.
3. **Export:**
* **HTML:** Creates a report file and a `/script` subfolder containing `mermaid.min.js`.
* **Excel:** Exports a complete matrix of permissions.



---

## 🦊 GitLab CI/CD Integration

To run this auditor automatically in GitLab, add the following to your `.gitlab-ci.yml`.

### Dockerfile Strategy (Recommended)

First, create a `Dockerfile` in your repo:

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vault_audit_cli.py .
ENTRYPOINT ["python", "vault_audit_cli.py"]

```

Then, configure `.gitlab-ci.yml`:

```yaml
stages:
  - security-audit

vault_policy_check:
  stage: security-audit
  image: python:3.9-slim
  before_script:
    - pip install python-hcl2 openpyxl
  script:
    # Assumes your policies are in a folder named 'policies'
    - python vault_audit_cli.py ./policies --output report.html --fail-on-critical
  artifacts:
    when: always
    paths:
      - report.html
    expire_in: 1 week
  allow_failure: false

```

### Explanation of Pipeline:

1. **Image:** Uses a lightweight Python image.
2. **Install:** Installs dependencies on the fly (or use your custom Docker image).
3. **Script:** Runs the CLI version of the tool against your policies folder.
* `--fail-on-critical`: If the tool finds any CRITICAL risks (sudo, *), the pipeline will **fail**, preventing the merge.


4. **Artifacts:** The `report.html` is saved so you can download and view the audit results from the GitLab UI.



