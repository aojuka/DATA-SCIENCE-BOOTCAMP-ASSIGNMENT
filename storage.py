import csv
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


BASE = Path(__file__).resolve().parent
USER_FIELDS = (
    "agent_id", "username", "email", "password_salt", "password_hash", "key_salt",
    "authorisation_level", "failed_attempts", "locked_until",
)
TASK_FIELDS = ("agent_id", "task_id", "due_date", "created", "blob_hex")
TOKEN_FIELDS = ("agent_id", "purpose", "expires", "digest", "used", "guesses")
PRIVATE_WRITE = os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
csv.field_size_limit(2**31 - 1)


class VaultError(Exception):
    pass


def load_env(path):
    try:
        file = path.open(encoding="utf-8-sig")
    except FileNotFoundError:
        return
    with file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = (part.strip() for part in line.split("=", 1))
            if not name or "\x00" in name or "\x00" in value:
                continue
            if len(value) >= 2 and value[0] in ("'", '"') and value[0] == value[-1]:
                value = value[1:-1]
            os.environ.setdefault(name, value)


def data_directory():
    path = Path(os.environ.get("TODO_DATA_DIR") or "data")
    if path.anchor and not path.is_absolute():
        raise VaultError("Use a full path or a path relative to the program for TODO_DATA_DIR.")
    return (BASE / path).resolve()


def utc_seconds():
    return datetime.now(timezone.utc).timestamp()


def utc_stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_csv(path, fields):
    try:
        file = path.open(newline="", encoding="utf-8")
    except FileNotFoundError:
        return []
    with file:
        reader = csv.DictReader(file, strict=True)
        if reader.fieldnames != list(fields):
            raise VaultError(f"Invalid CSV header in {path.name}.")
        rows = list(reader)
    if any(None in row or None in row.values() for row in rows):
        raise VaultError(f"Invalid CSV row in {path.name}.")
    return rows


def replace_file(path, mode, write):
    temp = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temp, PRIVATE_WRITE | os.O_EXCL, 0o600)
    try:
        options = {"encoding": "utf-8", "newline": ""} if mode == "w" else {}
        with os.fdopen(fd, mode, **options) as file:
            write(file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def write_csv(path, fields, rows):
    def write(file):
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    replace_file(path, "w", write)


class DataLock:
    def __init__(self, directory, recover):
        self.path = directory / ".vault.lock.tmp"
        self.recover = recover

    def __enter__(self):
        try:
            fd = os.open(self.path, PRIVATE_WRITE | os.O_EXCL, 0o600)
        except FileExistsError:
            raise VaultError("Data folder is busy. Try again.") from None
        try:
            os.close(fd)
            self.recover()
        except BaseException:
            self.path.unlink(missing_ok=True)
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        self.path.unlink()


class AuditLog:
    def __init__(self, path, key):
        self.path = path
        self.key = key

    def cipher(self):
        key = self.key
        error = "AGENCY_LOG_KEY must be a valid Fernet key."
        if not key:
            key_path = self.path.parent / ".log_key"
            error = "The audit key in .log_key is invalid."
            try:
                key = key_path.read_bytes().strip()
            except FileNotFoundError:
                key = Fernet.generate_key()
                replace_file(key_path, "wb", lambda file: file.write(key + b"\n"))
        try:
            return Fernet(key)
        except ValueError:
            raise VaultError(error) from None

    def write(self, event, agent_id="-", detail=""):
        fields = (utc_stamp(), event, agent_id, detail)
        if any("|" in field for field in fields):
            raise VaultError("Invalid audit field.")
        line = self.cipher().encrypt("|".join(fields).encode("utf-8"))
        fd = os.open(self.path, PRIVATE_WRITE | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as file:
            file.write(line + b"\n")
            file.flush()
            os.fsync(file.fileno())

    def latest(self, count):
        cipher = self.cipher()
        try:
            with self.path.open("rb") as file:
                lines = file.readlines()
        except FileNotFoundError:
            return []
        entries = []
        for line in reversed(lines[-count:]):
            try:
                text = cipher.decrypt(line.rstrip(b"\r\n")).decode("utf-8")
                stamp, event, agent, detail = text.split("|")
            except (InvalidToken, ValueError):
                stamp, event, agent, detail = "-", "CORRUPT", "-", "Invalid audit entry"
            entries.append((stamp, event, agent, detail))
        return entries
