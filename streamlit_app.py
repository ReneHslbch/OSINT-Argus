"""
streamlit_app.py
Einstiegspunkt im Repo-Root für Streamlit Cloud.
Stellt sicher, dass 'app' als Package importierbar ist,
unabhängig davon, welches Verzeichnis Streamlit als sys.path[0] setzt.
"""
import sys
import os

# Repo-Root zum Python-Pfad hinzufügen
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.ui_main import main

if __name__ == "__main__":
    main()
