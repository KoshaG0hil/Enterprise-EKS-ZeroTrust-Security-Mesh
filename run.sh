#!/usr/bin/env bash
# Linux / macOS Automated Runner for EKS Zero-Trust Security Mesh
set -euo pipefail

echo "============================================================"
echo " Enterprise EKS Zero-Trust Container Runtime Security Mesh"
echo " Architect: Kosha Gohil | DevSecOps & Cloud Security"
echo "============================================================"

echo ""
echo "[1/3] Running Ruff Linter..."
ruff check src tests

echo ""
echo "[2/3] Executing Pytest Suite..."
pytest -v

echo ""
echo "[3/3] Executing Threat Simulation..."
python3 -m src.cli simulate

echo ""
echo "============================================================"
echo " [SUCCESS] All checks and simulations passed 100%!"
echo "============================================================"
