from dotenv import load_dotenv
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import os
import smtplib
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
load_dotenv()


GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL")


def send_alert(photo_path: Path, reason: str) -> None:
    """
    Send an email alert with the photo attached.

    Parameters:
        photo_path : full path to the captured photo
        reason     : e.g. "WORKSTATION_UNLOCKED" or "LOGIN_FAILED"
    """
    if not all([GMAIL_ADDRESS, GMAIL_PASSWORD, RECIPIENT_EMAIL]):
        print("⚠  Email not configured — check your .env file.")
        return

    # ── Build the email ───────────────────────────────────────────────────────
    msg = MIMEMultipart()
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = RECIPIENT_EMAIL
    msg["Subject"] = f"⚠ SIEM Alert: {reason}"

    # Email body text
    body = f"""
Personal SIEM Security Alert

Event    : {reason}
Photo    : {photo_path.name}

This alert was generated automatically by your Personal SIEM.
    """
    msg.attach(MIMEText(body, "plain"))

    # Attach the photo
    if photo_path.exists():
        with open(photo_path, "rb") as f:
            img = MIMEImage(f.read(), name=photo_path.name)
            msg.attach(img)
    else:
        print(f"⚠  Photo not found: {photo_path}")
        return

    # ── Send via Gmail SMTP ───────────────────────────────────────────────────
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, RECIPIENT_EMAIL, msg.as_string())
        print(f"✅  Alert email sent to {RECIPIENT_EMAIL}")
    except smtplib.SMTPAuthenticationError:
        print("⚠  Gmail authentication failed — check your app password in .env")
    except Exception as e:
        print(f"⚠  Failed to send email: {e}")
