import os
from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

# SMTP Configuration
smtp_api = os.environ.get('SMTP_API')
smtp_email = os.environ.get('SMTP_EMAIL')
smtp_server = os.environ.get('SMTP_SERVER')
smtp_port = os.environ.get('SMTP_PORT')
smtp_sender = os.environ.get('SMTP_SENDER')

def send_email(subject, message, to_email):
    from_email = smtp_email
    password = smtp_api
    msg = MIMEMultipart()
    msg['From'] = formataddr((smtp_sender, from_email))
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'html'))
    server = SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()
    return True

# Verification Email

def send_verification_email(name, email, token):
    subject = "Welcome to Shardz, Please verify your email"
    message = f"""
    <div style="background: #222222; padding: 20px;">
<p><img style="display: block; margin-left: auto; margin-right: auto; padding-top: 30px;" src="https://ik.imagekit.io/shardz/shardz.png" width="300" height="100"  /></p>
<h2 style="text-align: center;"><span style="color: #ffffff;">Welcome to Shardz!</span></h2>
<div style="background: white; padding: 20px;">
<p>Hi <strong>{name}</strong>,</p>
<p data-sourcepos="7:1-7:132"><span class="pending">Thanks for signing up for Shardz!</span><span class="pending"> We're excited to help you unlock the power of unified storage across your favorite cloud services.</span></p>
<p data-sourcepos="9:1-9:169"><span class="pending">Before you can start using the power of Shardz</span><span class="pending">,</span><span class="pending"> we need to confirm your email address.</span><span class="pending"> Just click the button below to verify your account:</span></p>
<p data-sourcepos="9:1-9:169"><a href="https://shardz.io/verify?token={token}"><strong><span class="pending">Verify email</span></strong></a></p>
<p data-sourcepos="13:1-13:88"><span class="pending">Once you click the button,</span><span class="pending"> you'll be automatically redirected to Shardz and ready to go!</span></p>
<p data-sourcepos="15:1-15:98"><strong class="pending">Please note:</strong><span class="pending"> If you don't verify your email, you'll not be able to use our services.</span></p>
<p data-sourcepos="17:1-17:117"><span class="pending">If you're having trouble verifying your email,</span><span class="pending"> please reply to this message or contact us at <a href="https://telegram.me/w3Abhishek" target="_blank">Telegram</a>.</span></p>
<p data-sourcepos="19:1-19:13"><span class="pending">See you soon!</span></p>
<p data-sourcepos="21:1-21:15"><strong><span class="pending">The Shardz Team</span></strong></p>
</div>
</div>
    """
    return send_email(subject, message, email)

# Password Reset Email

def send_password_reset_email(name, email, token, ip2l):
    subject = "Shardz Password Reset"
    message = f"""
        <div style="background: #222222; padding: 20px;">
        <p><img style="display: block; margin-left: auto; margin-right: auto; padding-top: 30px;" src="https://ik.imagekit.io/shardz/shardz.png" width="300" height="100"  /></p>
        <h2 style="text-align: center;"><span style="color: #ffffff;">Reset Your Password</span></h2>
        <div style="background: white; padding: 20px;">
        <p>Hi <strong>{name}</strong>,</p>
        <p data-sourcepos="7:1-7:132"><span class="pending">Have you forgot your password?</span><span class="pending"> No worries, you can always get a new one for your Shardz account.</span></p>
        <p data-sourcepos="9:1-9:169"><span class="pending">To reset your password, click on the following link:</span></p>
        <p data-sourcepos="9:1-9:169"><a href="https://shardz.io/reset-password?token={token}"><strong><span class="pending">Reset password</span></strong></a></p>
        <p data-sourcepos="13:1-13:88"><span class="pending">{ip2l}</p>
        <p data-sourcepos="15:1-15:98"><strong class="pending">Please note:</strong><span class="pending"> If you didn't request a password reset, you can ignore this email.</span></p>
        <p data-sourcepos="17:1-17:117"><span class="pending">If you're having trouble resetting password,</span><span class="pending"> please reply to this message or contact us at <a href="https://telegram.me/w3Abhishek" target="_blank">Telegram</a>.</span></p>
        <p data-sourcepos="19:1-19:13"><span class="pending">See you soon!</span></p>
        <p data-sourcepos="21:1-21:15"><strong><span class="pending">The Shardz Team</span></strong></p>
        </div>
        </div>
    """
    return send_email(subject, message, email)