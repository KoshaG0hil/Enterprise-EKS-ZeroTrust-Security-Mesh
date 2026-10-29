# How to Run & Verify the EKS Zero-Trust Security Mesh

This document provides step-by-step instructions for running, testing, and verifying the Enterprise EKS Zero-Trust Security Mesh locally and in CI/CD.

---

## 1. Prerequisites

- **Python 3.11+** installed
- **Terraform 1.5+** installed (optional, for IaC validation)
- **Docker** (optional, for containerized execution)

---

## 2. Windows Quickstart (PowerShell)

```powershell
cd "c:\Users\gohil\Desktop\AWS\Enterprise-EKS-ZeroTrust-Security-Mesh"

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Run Pytest suite (12 tests, 100% pass)
pytest -v

# Run full attack simulation & autonomous pod quarantine
python -m src.cli simulate
```

Or execute the automated runner:
```powershell
.\run.ps1
```

---

## 3. Linux / macOS Quickstart (Bash)

```bash
cd Enterprise-EKS-ZeroTrust-Security-Mesh

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

pytest -v

chmod +x run.sh
./run.sh
```

---

## 4. Terraform Validation

```bash
cd terraform
terraform init -backend=false
terraform validate
```

---

## 5. Interactive Cyber SOC Console

Open `index.html` in any browser or visit:
[https://koshag0hil.github.io/Enterprise-EKS-ZeroTrust-Security-Mesh/](https://koshag0hil.github.io/Enterprise-EKS-ZeroTrust-Security-Mesh/)
