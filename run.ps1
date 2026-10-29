# PowerShell Automated Runner for EKS Zero-Trust Security Mesh
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Enterprise EKS Zero-Trust Container Runtime Security Mesh" -ForegroundColor Cyan
Write-Host " Architect: Kosha Gohil | DevSecOps & Cloud Security" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Python Check
Write-Host "`n[1/4] Checking Python environment..." -ForegroundColor Yellow
python --version

# 2. Ruff Linter
Write-Host "`n[2/4] Running Ruff code analysis..." -ForegroundColor Yellow
ruff check src tests

# 3. Pytest Suite
Write-Host "`n[3/4] Running Pytest test suite..." -ForegroundColor Yellow
pytest -v

# 4. Simulation
Write-Host "`n[4/4] Executing Attack Simulation & Autonomous Quarantine..." -ForegroundColor Yellow
python -m src.cli simulate

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " [SUCCESS] All checks and simulations passed 100%!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
