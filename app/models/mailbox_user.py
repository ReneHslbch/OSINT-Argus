from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional
import uuid


class MailboxUser(BaseModel):
    """Benutzer-Modell für den Mailbox-Access via Registration Key."""
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    access_key: str = Field(description="Ein eindeutiger 12-Zeichen-Access-Key")
    email_address: str = Field(description="Die E-Mail-Adresse des Nutzers")
    created_at: datetime = Field(default_factory=datetime.now)
    last_active: datetime = Field(default_factory=datetime.now)
    mail_uids: List[str] = Field(default_factory=list, description="Verarbeitete Mail-UIDs im Monitoring-Postfach")
    is_active: bool = Field(default=True)

    class Config:
        from_attributes = True


class MailAnalysis(BaseModel):
    """Modell für eine analysierte Mail mit Ergebnis."""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = Field(description="Zugehöriger Benutzer")
    mail_uid: str = Field(description="IMAP UID der originalen Mail")
    subject: str = Field(description="Betreff der Mail")
    from_address: str = Field(description="Absender der Mail")
    received_at: datetime = Field(default_factory=datetime.now)
    analyzed_at: datetime = Field(default_factory=datetime.now)
    risk_level: Optional[str] = Field(None, description="Risiko-Stufung: LOW, MEDIUM, HIGH, CRITICAL")
    risk_score: Optional[int] = Field(None, ge=0, le=100, description="Gesamtrisiko-Score")
    summary: Optional[str] = Field(None, description="Kurzzusammenfassung")
    full_report: Optional[dict] = Field(None, description="Vollständiger Analyse-Report")
    is_read: bool = Field(default=False, description="Ob der Nutzer den Report bereits gesehen hat")

    class Config:
        from_attributes = True
