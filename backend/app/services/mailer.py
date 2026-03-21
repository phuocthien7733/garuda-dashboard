import smtplib
from email.message import EmailMessage

from app.core.config import get_settings


def _validate_mail_settings() -> None:
    settings = get_settings()
    required_values = {
        "SMTP_USERNAME": settings.smtp_username,
        "SMTP_PASSWORD": settings.smtp_password,
        "SMTP_FROM_EMAIL": settings.smtp_from_email,
    }
    missing = [key for key, value in required_values.items() if not value]
    if missing:
        raise RuntimeError(f"Missing SMTP configuration: {', '.join(missing)}")


def build_mfa_email_html(username: str, otp_code: str, expires_minutes: int) -> str:
    return f"""
    <html>
      <body style="margin:0;padding:0;background:#020617;font-family:Segoe UI,Arial,sans-serif;color:#e2e8f0;">
        <div style="max-width:680px;margin:0 auto;padding:32px 20px;">
          <div style="border:1px solid rgba(255,255,255,0.08);border-radius:28px;overflow:hidden;background:linear-gradient(135deg,#0f172a,#111827);box-shadow:0 24px 80px rgba(0,0,0,0.45);">
            <div style="padding:32px;background:radial-gradient(circle at top left, rgba(239,68,68,0.28), transparent 30%), radial-gradient(circle at top right, rgba(249,115,22,0.16), transparent 24%), linear-gradient(135deg, rgba(15,23,42,0.98), rgba(2,6,23,0.96));">
              <p style="margin:0;font-size:11px;letter-spacing:0.36em;text-transform:uppercase;color:#fdba74;">Test And Watch Security</p>
              <h1 style="margin:16px 0 0;font-size:30px;line-height:1.15;color:#ffffff;font-weight:800;">Multi-Factor Authentication Challenge</h1>
              <p style="margin:18px 0 0;font-size:15px;line-height:1.8;color:#cbd5e1;">
                A protected sign-in attempt was initiated for <strong style="color:#ffffff;">{username}</strong> on the T&W Falcon.
              </p>
            </div>
            <div style="padding:32px;">
              <div style="border:1px solid rgba(251,146,60,0.28);border-radius:24px;background:rgba(249,115,22,0.08);padding:28px;text-align:center;">
                <p style="margin:0;font-size:12px;letter-spacing:0.28em;text-transform:uppercase;color:#fdba74;">Verification Code</p>
                <p style="margin:18px 0 0;font-size:42px;letter-spacing:0.32em;font-weight:900;color:#ffffff;">{otp_code}</p>
                <p style="margin:18px 0 0;font-size:14px;color:#cbd5e1;">This code expires in <strong style="color:#ffffff;">{expires_minutes} minutes</strong>.</p>
              </div>
              <div style="margin-top:28px;border:1px solid rgba(255,255,255,0.08);border-radius:20px;background:rgba(15,23,42,0.7);padding:22px;">
                <p style="margin:0;font-size:13px;line-height:1.8;color:#cbd5e1;">
                  If this request was not initiated by you, reset your password and notify the Test And Watch security lead immediately.
                </p>
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>
    """


def build_mfa_email_text(username: str, otp_code: str, expires_minutes: int) -> str:
    return (
        f"Test And Watch Security\n\n"
        f"A protected sign-in attempt was initiated for {username}.\n"
        f"Your MFA verification code is: {otp_code}\n"
        f"This code expires in {expires_minutes} minutes.\n\n"
        f"If this was not you, reset your password and notify security immediately."
    )


def send_mfa_email(recipient_email: str, username: str, otp_code: str, expires_minutes: int) -> None:
    settings = get_settings()
    _validate_mail_settings()

    message = EmailMessage()
    message["Subject"] = "Test And Watch | MFA Verification Code"
    message["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
    message["To"] = recipient_email
    message.set_content(build_mfa_email_text(username, otp_code, expires_minutes))
    message.add_alternative(build_mfa_email_html(username, otp_code, expires_minutes), subtype="html")

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls()
        smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
