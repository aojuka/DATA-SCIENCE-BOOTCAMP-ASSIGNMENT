import secrets
import smtplib
from email.message import EmailMessage

from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from storage import VaultError, utc_stamp


CLASSIFICATIONS = ("Top Secret", "Secret", "Confidential")
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
EMAIL_NOT_CONFIGURED = "Email is not configured. Fill in the .env file (choose 'doctor' to check)."
DECRYPTION_FAILED = "Decryption failed: wrong password or data was tampered with."


def scrypt(salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)


def password_fields(password):
    salt = secrets.token_bytes(16)
    password_hash = scrypt(salt).derive(password.encode("utf-8"))
    return {
        "password_salt": salt.hex(),
        "password_hash": password_hash.hex(),
        "key_salt": secrets.token_bytes(16).hex(),
        "failed_attempts": "0",
        "locked_until": "0",
    }


def validate_password(password, confirmation):
    requirements = (
        (len(password) >= 12, "at least 12 characters"),
        (any(char.islower() for char in password), "a lowercase letter"),
        (any(char.isupper() for char in password), "an uppercase letter"),
        (any(char.isdigit() for char in password), "a digit"),
        (any(not char.isalnum() for char in password), "a symbol"),
    )
    missing = [label for passed, label in requirements if not passed]
    if missing:
        raise VaultError(f"Password must contain: {', '.join(missing)}.")
    if password != confirmation:
        raise VaultError("Passwords do not match.")


def valid_email(address):
    local, at, domain = address.partition("@")
    return bool(
        local and at and "." in domain and "@" not in domain
        and all(char.isprintable() and not char.isspace() for char in address)
        and not any(char in '<>,;:"()\\[]' for char in address)
    )


def mask_email(address):
    local, domain = address.split("@", 1)
    if len(local) <= 2:
        return f"{'*' * len(local)}@{domain}"
    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"


class User:
    def __init__(self, row):
        self.row = row
        self.agent_id = row["agent_id"]
        self.username = row["username"]
        self.email = row["email"]
        self.authorisation_level = row["authorisation_level"]
        self.tasks = []

    @property
    def password_hash(self):
        return self.row["password_hash"]

    def check_password(self, password):
        verifier = scrypt(bytes.fromhex(self.row["password_salt"]))
        try:
            verifier.verify(password.encode("utf-8"), bytes.fromhex(self.password_hash))
        except InvalidKey:
            return False
        return True

    def derive_key(self, password):
        salt = bytes.fromhex(self.row["key_salt"])
        return scrypt(salt).derive(password.encode("utf-8"))

    def add_task(self, password, description, due_date, classification):
        existing_ids = {task["task_id"] for task in self.tasks}
        task_id = secrets.token_hex(8)
        while task_id in existing_ids:
            task_id = secrets.token_hex(8)
        nonce = secrets.token_bytes(12)
        data = f"{classification}\n{description}".encode("utf-8")
        associated_data = f"{self.agent_id}:{task_id}".encode("utf-8")
        cipher = AESGCM(self.derive_key(password))
        encrypted = cipher.encrypt(nonce, data, associated_data)
        task = {
            "agent_id": self.agent_id,
            "task_id": task_id,
            "due_date": due_date,
            "created": utc_stamp(),
            "blob_hex": (nonce + encrypted).hex(),
        }
        self.tasks.append(task)
        return task

    def reveal_tasks(self, password):
        cipher = AESGCM(self.derive_key(password))
        revealed = []
        for task in self.tasks:
            task_id = task["task_id"]
            associated_data = f"{self.agent_id}:{task_id}".encode("utf-8")
            try:
                blob = bytes.fromhex(task["blob_hex"])
                data = cipher.decrypt(blob[:12], blob[12:], associated_data).decode("utf-8")
            except (InvalidTag, ValueError):
                raise VaultError(DECRYPTION_FAILED) from None
            classification, separator, description = data.partition("\n")
            if not separator or classification not in CLASSIFICATIONS:
                raise VaultError(DECRYPTION_FAILED)
            revealed.append({
                "task_id": task_id,
                "due_date": task["due_date"],
                "classification": classification,
                "description": description,
            })
        return revealed


def make_code():
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"{code[:4]}-{code[4:]}"


def code_digest(code):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(code.upper().replace(" ", "").encode("utf-8"))
    return digest.finalize()


def code_email(sender, recipient, purpose, code):
    message = EmailMessage()
    message["Subject"] = "Agency one-time code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your agency one-time code for {purpose} is {code}.\n\n"
        "It expires in 10 minutes and works once.\n"
        "Report this message to the agency if you did not request it.\n"
    )
    return message


class SmtpSettings:
    def __init__(self, values):
        self.host = values.get("SMTP_HOST", "").strip()
        self.port = values.get("SMTP_PORT", "587").strip()
        self.use_tls = values.get("SMTP_USE_TLS", "true").strip().lower()
        self.user = values.get("SMTP_USER", "").strip()
        self.password = values.get("SMTP_PASSWORD", "")
        self.sender = values.get("SMTP_FROM", "").strip() or self.user

    def require_configuration(self):
        if not self.host or not self.sender:
            raise VaultError(EMAIL_NOT_CONFIGURED)
        try:
            port = int(self.port)
        except ValueError:
            port = 0
        if not 1 <= port <= 65535:
            raise VaultError("SMTP_PORT must be a number from 1 to 65535.")
        tls_on = ("true", "yes", "1", "on")
        tls_off = ("false", "no", "0", "off")
        if self.use_tls not in tls_on + tls_off:
            raise VaultError("SMTP_USE_TLS must be true or false.")
        if not valid_email(self.sender):
            raise VaultError("SMTP_FROM must be a valid email address.")
        return port, self.use_tls in tls_on


def smtp_hello(client):
    status, reply = client.ehlo()
    if status != 250:
        raise smtplib.SMTPHeloError(status, reply)


def smtp_exchange(settings, message=None):
    port, use_tls = settings.require_configuration()
    client = smtplib.SMTP(settings.host, port, timeout=15)
    try:
        smtp_hello(client)
        if use_tls:
            client.starttls()
            smtp_hello(client)
        if settings.user:
            client.login(settings.user, settings.password)
        if message is not None:
            client.send_message(message)
    finally:
        try:
            client.quit()
        except OSError:
            client.close()


def smtp_error_details(error, *private_values):
    detail = str(error) or type(error).__name__
    for value in private_values:
        if value:
            detail = detail.replace(value, "[redacted]")
            detail = detail.replace(ascii(value)[1:-1], "[redacted]")
    return detail
