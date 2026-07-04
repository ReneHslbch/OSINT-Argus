"""
app/mailbox_store.py

SQLite-Datenbank für User-Management und Mail-Analyse-Speicherung.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple
import threading

from app.models.mailbox_user import MailboxUser, MailAnalysis


class MailboxStore:
    """SQLite-Datenbank-Wrapper für User- und Mail-Speicherung."""

    def __init__(self, db_path: str = "data/mailbox_users.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Thread-sichere Datenbankverbindung."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        """Initialisiert die Datenbank-Tabellen."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Users-Tabelle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                access_key TEXT UNIQUE NOT NULL,
                email_address TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_active TEXT NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        """)

        # User-Mail-UID-Mapping (welche Mails gehören zu welchem User)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_mails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                mail_uid TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                UNIQUE(user_id, mail_uid)
            )
        """)

        # Analysen-Tabelle (gespeicherte Analyse-Ergebnisse)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                mail_uid TEXT NOT NULL,
                subject TEXT NOT NULL,
                from_address TEXT NOT NULL,
                received_at TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                risk_level TEXT,
                risk_score INTEGER,
                summary TEXT,
                full_report TEXT,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)

        # Indexe für schnellere Abfragen
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_access_key ON users(access_key)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_user_id ON analyses(user_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_is_read ON analyses(is_read)
        """)

        conn.commit()

    # ── User-Operationen ──────────────────────────────────────────────────────

    def create_user(self, email_address: str) -> MailboxUser:
        """Erstellt einen neuen Benutzer mit zufälligem Access-Key."""
        import secrets
        import string

        access_key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        now = datetime.now().isoformat()

        user = MailboxUser(
            access_key=access_key,
            email_address=email_address,
            created_at=datetime.fromisoformat(now),
            last_active=datetime.fromisoformat(now)
        )

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (user_id, access_key, email_address, created_at, last_active, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (user.user_id, user.access_key, user.email_address, now, now))
        conn.commit()

        return user

    def get_user_by_key(self, access_key: str) -> Optional[MailboxUser]:
        """Sucht einen Benutzer nach Access-Key."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, access_key, email_address, created_at, last_active, is_active
            FROM users WHERE access_key = ? AND is_active = 1
        """, (access_key,))
        row = cursor.fetchone()

        if row:
            return MailboxUser(
                user_id=row['user_id'],
                access_key=row['access_key'],
                email_address=row['email_address'],
                created_at=datetime.fromisoformat(row['created_at']),
                last_active=datetime.fromisoformat(row['last_active']),
                is_active=bool(row['is_active'])
            )
        return None

    def get_user_by_id(self, user_id: str) -> Optional[MailboxUser]:
        """Sucht einen Benutzer nach user_id."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, access_key, email_address, created_at, last_active, is_active
            FROM users WHERE user_id = ? AND is_active = 1
        """, (user_id,))
        row = cursor.fetchone()

        if row:
            return MailboxUser(
                user_id=row['user_id'],
                access_key=row['access_key'],
                email_address=row['email_address'],
                created_at=datetime.fromisoformat(row['created_at']),
                last_active=datetime.fromisoformat(row['last_active']),
                is_active=bool(row['is_active'])
            )
        return None

    def update_last_active(self, user_id: str):
        """Aktualisiert last_active-Zeitstempel."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
            UPDATE users SET last_active = ? WHERE user_id = ?
        """, (now, user_id))
        conn.commit()

    def deactivate_user(self, user_id: str):
        """Deaktiviert einen Benutzer."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET is_active = 0 WHERE user_id = ?
        """, (user_id,))
        conn.commit()

    # ── User-Mail-UID-Operationen ─────────────────────────────────────────────

    def link_mail_to_user(self, user_id: str, mail_uid: str):
        """Verknüpft eine Mail-UID mit einem Benutzer."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        try:
            cursor.execute("""
                INSERT INTO user_mails (user_id, mail_uid, created_at)
                VALUES (?, ?, ?)
            """, (user_id, mail_uid, now))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Already linked

    def get_user_mail_uids(self, user_id: str) -> List[str]:
        """Holt alle Mail-UIDs für einen Benutzer."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT mail_uid FROM user_mails WHERE user_id = ?
        """, (user_id,))
        return [row['mail_uid'] for row in cursor.fetchall()]

    # ── Analyse-Operationen ───────────────────────────────────────────────────

    def save_analysis(self, analysis: MailAnalysis):
        """Speichert eine Analyse."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO analyses
            (analysis_id, user_id, mail_uid, subject, from_address, received_at,
             analyzed_at, risk_level, risk_score, summary, full_report, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis.analysis_id,
            analysis.user_id,
            analysis.mail_uid,
            analysis.subject,
            analysis.from_address,
            analysis.received_at.isoformat(),
            analysis.analyzed_at.isoformat(),
            analysis.risk_level,
            analysis.risk_score,
            analysis.summary,
            json.dumps(analysis.full_report) if analysis.full_report else None,
            1 if analysis.is_read else 0
        ))
        conn.commit()

    def get_analysis(self, analysis_id: str) -> Optional[MailAnalysis]:
        """Holt eine Analyse nach ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM analyses WHERE analysis_id = ?
        """, (analysis_id,))
        row = cursor.fetchone()

        if row:
            return MailAnalysis(
                analysis_id=row['analysis_id'],
                user_id=row['user_id'],
                mail_uid=row['mail_uid'],
                subject=row['subject'],
                from_address=row['from_address'],
                received_at=datetime.fromisoformat(row['received_at']),
                analyzed_at=datetime.fromisoformat(row['analyzed_at']),
                risk_level=row['risk_level'],
                risk_score=row['risk_score'],
                summary=row['summary'],
                full_report=json.loads(row['full_report']) if row['full_report'] else None,
                is_read=bool(row['is_read'])
            )
        return None

    def get_user_analyses(self, user_id: str, unread_only: bool = False) -> List[MailAnalysis]:
        """Holt alle Analysen für einen Benutzer."""
        conn = self._get_connection()
        cursor = conn.cursor()

        if unread_only:
            cursor.execute("""
                SELECT * FROM analyses WHERE user_id = ? AND is_read = 0
                ORDER BY analyzed_at DESC
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT * FROM analyses WHERE user_id = ?
                ORDER BY analyzed_at DESC
            """, (user_id,))

        analyses = []
        for row in cursor.fetchall():
            analyses.append(MailAnalysis(
                analysis_id=row['analysis_id'],
                user_id=row['user_id'],
                mail_uid=row['mail_uid'],
                subject=row['subject'],
                from_address=row['from_address'],
                received_at=datetime.fromisoformat(row['received_at']),
                analyzed_at=datetime.fromisoformat(row['analyzed_at']),
                risk_level=row['risk_level'],
                risk_score=row['risk_score'],
                summary=row['summary'],
                full_report=json.loads(row['full_report']) if row['full_report'] else None,
                is_read=bool(row['is_read'])
            ))
        return analyses

    def mark_analysis_read(self, analysis_id: str):
        """Markiert eine Analyse als gelesen."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE analyses SET is_read = 1 WHERE analysis_id = ?
        """, (analysis_id,))
        conn.commit()

    def get_unread_count(self, user_id: str) -> int:
        """Holt die Anzahl ungelesener Analysen."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count FROM analyses WHERE user_id = ? AND is_read = 0
        """, (user_id,))
        return cursor.fetchone()['count']


# Singleton-Instanz
mailbox_store = MailboxStore()
