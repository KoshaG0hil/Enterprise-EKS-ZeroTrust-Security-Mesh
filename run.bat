@echo off
REM Windows Batch Automated Runner for EKS Zero-Trust Security Mesh
echo ============================================================
echo  Enterprise EKS Zero-Trust Container Runtime Security Mesh
echo  Architect: Kosha Gohil ^| DevSecOps ^& Cloud Security
echo ============================================================

echo.
echo [1/3] Running Ruff Linter...
ruff check src tests
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Ruff linter failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Running Pytest Suite...
pytest -v
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Pytest tests failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Running Threat Simulation...
python -m src.cli simulate
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Simulation failed.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo  [SUCCESS] All checks and simulations passed!
echo ============================================================
