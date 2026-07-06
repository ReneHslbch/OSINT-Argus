"""
app/mailbox_auth.py

Registrierung und Key-Validierung für den Mailbox-Access.
"""

import email
from email.header import decode_header
from typing import Optional, Tuple

from app.utils.mail_branding import render_shell
from app.mailbox_store import mailbox_store
from app.models.mailbox_user import MailboxUser


def extract_sender_email(msg) -> str:
    """Extrahiert die E-Mail-Adresse aus dem From-Header."""
    # imap_tools MailMessage hat 'from_' Attribut
    if hasattr(msg, 'from_'):
        from_header = msg.from_
    elif hasattr(msg, 'get'):
        from_header = msg.get("From", "")
    else:
        return ""
    
    if not from_header:
        return ""
        
    decoded = decode_mime_header(str(from_header))
    
    # Parse "Name <email@example.com>" or just "email@example.com"
    if "<" in decoded and ">" in decoded:
        return decoded.split("<")[1].split(">")[0].strip()
    return decoded.strip()


def decode_mime_header(value: str) -> str:
    """Decodiert MIME-kodierte Email-Header."""
    if not value:
        return ""
    decoded_parts = []
    for text, encoding in email.header.decode_header(value):
        if isinstance(text, bytes):
            try:
                decoded_parts.append(text.decode(encoding or "utf-8", errors="replace"))
            except Exception:
                decoded_parts.append(text.decode("utf-8", errors="replace"))
        else:
            decoded_parts.append(text)
    return "".join(decoded_parts)


def process_registration_email(msg, mail_uid: str) -> Tuple[bool, str, Optional[MailboxUser]]:
    """
    Verarbeitet eine Registrierungs-Mail (Betreff: "REGISTER" oder "REGISTRATION").
    
    Args:
        msg: imap_tools MailMessage object
        mail_uid: IMAP UID der Mail
    
    Returns:
        (success, message, user_or_none)
    """
    # imap_tools MailMessage hat 'from_' und 'subject' Attribute
    subject = getattr(msg, 'subject', '') or ''
    from_email = getattr(msg, 'from_', '') or ''
    
    if not from_email or "@" not in from_email:
        return False, "Ungültige Absender-E-Mail", None
    
    # Prüfen ob Betreff REGISTER enthält
    subject_upper = subject.upper()
    if "REGISTER" not in subject_upper and "REGISTRATION" not in subject_upper:
        return False, "Betreff muss 'REGISTER' oder 'REGISTRATION' enthalten", None
    
    try:
        user = mailbox_store.create_user(from_email)
        mailbox_store.link_mail_to_user(user.user_id, mail_uid)
        
        return True, f"Registrierung erfolgreich! Dein Access-Key: {user.access_key}", user
        
    except Exception as e:
        return False, f"Registrierungsfehler: {str(e)}", None


def validate_access_key(access_key: str) -> Tuple[bool, str, Optional[MailboxUser]]:
    """
    Validiert einen Access-Key.
    
    Returns:
        (success, message, user_or_none)
    """
    if not access_key or len(access_key) != 12:
        return False, "Ungültiger Key-Format (erwartet 12 Zeichen)", None
    
    user = mailbox_store.get_user_by_key(access_key)
    
    if not user:
        return False, "Ungültiger oder abgelaufener Access-Key", None
    
    mailbox_store.update_last_active(user.user_id)
    return True, "Login erfolgreich", user


def get_registration_response(user: MailboxUser) -> str:
    """Erstellt die Antwort-Mail-Inhalt für Registrierungen (Text + HTML)."""
    text_body = f"""
OSINT-Argus Registrierung bestätigt
{'=' * 50}

Herzlich Willkommen!

Dein Access-Key für den Mailbox-Service:

>>> {user.access_key} <<<

Speichere diesen Key sicher! Du wirst ihn benötigen, um:
  1. Deine analysierten Mails in der UI einzusehen
  2. Weitere Mails zur Analyse einzureichen

So verwendest du den Key:
  - Gehe zur Streamlit-App (oder https://argus.your-domain.com)
  - Wähle den Tab "📧 Mail"
  - Gib deinen Access-Key ein

Bei Fragen oder Problemen antworte einfach auf diese Mail.

{'=' * 50}
OSINT-Argus Team
"""
    return text_body


def get_analysis_response(user: MailboxUser, analysis_subject: str, risk_level: str, risk_score: int) -> str:
    """Erstellt die Antwort-Mail-Inhalt für Analyse-Bestätigungen."""
    return f"""
OSINT-Argus Analyse abgeschlossen

Deine Mail "{analysis_subject}" wurde erfolgreich analysiert.

Ergebnis: {risk_level} (Score: {risk_score}/100)

Um den vollständigen Bericht einzusehen:
1. Gehe zur OSINT-Argus UI
2. Wähle den Tab "Mail Analyse"
3. Gib deinen Access-Key ein: {user.access_key}
4. Klicke auf den entsprechenden Eintrag

---
OSINT-Argus Team
"""

def get_registration_response_html(user: MailboxUser) -> str:
    """Erstellt die HTML-Version der Registrierungs-Bestätigung im einheitlichen Branding."""
    body = f"""
    <p>Herzlich willkommen! Dein Zugang zum Mailbox-Service wurde erfolgreich eingerichtet.</p>
    <p><strong>Dein persönlicher Access-Key:</strong></p>
    <div class="key-box">{user.access_key}</div>
    <div class="card warn">⚠️ Bewahre diesen Key sicher auf — er ist dein einziger Zugang zu deinen analysierten Mails.</div>
    <div class="card accent">
      <strong>So verwendest du deinen Key:</strong>
      <ol>
        <li>Öffne die OSINT-Argus Web-App</li>
        <li>Wechsle zum Tab <strong>„📧 Mail“</strong></li>
        <li>Gib deinen Access-Key ein, um deine analysierten Mails einzusehen</li>
      </ol>
    </div>
    <p>Bei Fragen oder Problemen antworte einfach auf diese E-Mail.</p>
    """
    return render_shell("👁️", "OSINT-Argus", "Registrierung bestätigt", body)