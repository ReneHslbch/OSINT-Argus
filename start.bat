@echo off
echo ============================================================
echo OSINT-Argus - Worker + UI starten
echo ============================================================

echo.
echo [1/2] Mailbox Worker starten...
start "OSINT-Argus Mailbox Worker" powershell -NoExit -Command "cd '%~dp0'; .\.venv\Scripts\activate; python -m app.mailbox_watcher"

echo.
echo [2/2] Streamlit UI starten...
timeout /t 2 /nobreak >nul
start "OSINT-Argus UI" powershell -NoExit -Command "cd '%~dp0'; .\.venv\Scripts\activate; python -m streamlit run app/ui_main.py "

echo.
echo ============================================================
echo Beide Prozesse wurden gestartet!
echo - Worker: Neues Fenster für Mailbox-Polling
echo - UI: Neues Fenster für Streamlit (http://localhost:8501)
echo ============================================================
