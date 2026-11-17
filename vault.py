from datetime import date

from cryptography.hazmat.primitives import constant_time

from security import (
    User, code_digest, code_email, make_code, mask_email, password_fields,
    scrypt, smtp_error_details, smtp_exchange, valid_email, validate_password,
    CLASSIFICATIONS,
)
from storage import (
    AuditLog, DataLock, VaultError, read_csv, utc_seconds, write_csv,
    TASK_FIELDS, TOKEN_FIELDS, USER_FIELDS,
)


PURPOSES = ("view", "reset")
CODE_LIFETIME = 600
CODE_GUESSES = 3
LOGIN_ATTEMPTS = 5
LOCK_DURATION = 300
LOCKED = "Account temporarily locked. Try again later."
INVALID_CREDENTIALS = "Invalid credentials."


class Vault:
    def __init__(self, directory, smtp, log_key="", mailer=smtp_exchange):
        self.directory = directory
        self.smtp = smtp
        self.mailer = mailer
        self.users_path = directory / "users.csv"
        self.tasks_path = directory / "tasks.csv"
        self.tokens_path = directory / "tokens.csv"
        self.reset_path = directory / ".pending_reset.tmp"
        self.audit = AuditLog(directory / "audit.log", log_key)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _lock(self):
        return DataLock(self.directory, self._recover_reset)

    def register(self, agent_id, username, email, password, confirmation):
        agent_id, username, email = agent_id.strip(), username.strip(), email.strip()
        with self._lock():
            try:
                if not 4 <= len(agent_id) <= 16 or not agent_id.isascii() or not all(
                    char.isalnum() or char == "-" for char in agent_id
                ):
                    raise VaultError("Agent ID must be 4 to 16 characters using A-Z, 0-9 or hyphen.")
                if not 3 <= len(username) <= 32 or not all(
                    char.isalnum() or char in "_.-" for char in username
                ):
                    raise VaultError("Username must be 3 to 32 characters using letters, digits, _, . or -.")
                if not valid_email(email):
                    raise VaultError("Enter a valid email address.")
                agent_id = agent_id.upper()
                users = read_csv(self.users_path, USER_FIELDS)
                for row in users:
                    if row["agent_id"] == agent_id or row["username"].casefold() == username.casefold():
                        raise VaultError("Agent ID or username already registered.")
                validate_password(password, confirmation)
            except VaultError:
                self.audit.write("REGISTER_REJECTED", detail="registration rejected")
                raise
            self.audit.cipher()
            role = "agent" if users else "admin"
            account = {
                "agent_id": agent_id,
                "username": username,
                "email": email,
                "authorisation_level": role,
                **password_fields(password),
            }
            users.append(account)
            write_csv(self.users_path, USER_FIELDS, users)
            self.audit.write("REGISTER", agent_id, role)
            return User(account)

    def login(self, username, password):
        username = username.strip().casefold()
        with self._lock():
            users = read_csv(self.users_path, USER_FIELDS)
            account = next((row for row in users if row["username"].casefold() == username), None)
            if account is None:
                scrypt(bytes(16)).derive(password.encode("utf-8"))
                self.audit.write("LOGIN_FAILED", detail="invalid credentials")
                raise VaultError(INVALID_CREDENTIALS)

            user = User(account)
            locked_until = float(account["locked_until"])
            if locked_until > utc_seconds():
                self.audit.write("LOGIN_BLOCKED", user.agent_id, "locked")
                raise VaultError(LOCKED)
            if user.check_password(password):
                if account["failed_attempts"] != "0" or locked_until:
                    account.update(failed_attempts="0", locked_until="0")
                    write_csv(self.users_path, USER_FIELDS, users)
                self.audit.write("LOGIN_OK", user.agent_id)
                return user

            attempts = 1 if locked_until else int(account["failed_attempts"]) + 1
            account["failed_attempts"] = str(attempts)
            if attempts >= LOGIN_ATTEMPTS:
                account["locked_until"] = str(utc_seconds() + LOCK_DURATION)
            write_csv(self.users_path, USER_FIELDS, users)
            self.audit.write("LOGIN_FAILED", user.agent_id, "invalid credentials")
            if attempts >= LOGIN_ATTEMPTS:
                self.audit.write("ACCOUNT_LOCKED", user.agent_id)
                raise VaultError(LOCKED)
            raise VaultError(INVALID_CREDENTIALS)

    def _account(self, agent_id):
        agent_id = agent_id.strip().upper()
        for row in read_csv(self.users_path, USER_FIELDS):
            if row["agent_id"] == agent_id:
                return row
        return None

    def _current_user(self, actor):
        account = self._account(actor.agent_id)
        if account is None:
            raise VaultError(INVALID_CREDENTIALS)
        current_hash = bytes.fromhex(account["password_hash"])
        previous_hash = bytes.fromhex(actor.password_hash)
        if not constant_time.bytes_eq(current_hash, previous_hash):
            raise VaultError(INVALID_CREDENTIALS)
        if float(account["locked_until"]) > utc_seconds():
            self.audit.write("LOGIN_BLOCKED", actor.agent_id, "locked")
            raise VaultError(LOCKED)
        return User(account)

    def _require_admin(self, actor):
        user = self._current_user(actor)
        if user.authorisation_level != "admin":
            self.audit.write("UNAUTHORISED", user.agent_id)
            raise VaultError("Admin authorisation required.")
        return user

    def check_admin(self, actor):
        with self._lock():
            self._require_admin(actor)

    def add_task(self, actor, password, description, due_date, classification):
        if not description.strip():
            raise VaultError("Description cannot be empty.")
        try:
            if date.fromisoformat(due_date).isoformat() != due_date:
                raise ValueError
        except ValueError:
            raise VaultError("Enter a valid due date in YYYY-MM-DD format.") from None
        if classification not in CLASSIFICATIONS:
            raise VaultError("Invalid classification.")
        with self._lock():
            user = self._current_user(actor)
            if not user.check_password(password):
                raise VaultError(INVALID_CREDENTIALS)
            tasks = read_csv(self.tasks_path, TASK_FIELDS)
            user.tasks = [task for task in tasks if task["agent_id"] == user.agent_id]
            task = user.add_task(password, description, due_date, classification)
            tasks.append(task)
            write_csv(self.tasks_path, TASK_FIELDS, tasks)
            self.audit.write("TASK_ADDED", user.agent_id, task["task_id"])
            return task["task_id"]

    def _agent_tasks(self, agent_id, task_id="", require=False):
        task_id = task_id.strip().lower()
        tasks = [
            task for task in read_csv(self.tasks_path, TASK_FIELDS)
            if task["agent_id"] == agent_id and (not task_id or task["task_id"] == task_id)
        ]
        if require and not tasks:
            raise VaultError("No such task." if task_id else "You have no tasks.")
        return tasks

    def list_tasks(self, actor):
        with self._lock():
            user = self._current_user(actor)
            tasks = self._agent_tasks(user.agent_id)
            self.audit.write("TASK_LIST", user.agent_id, str(len(tasks)))
            return [
                {
                    "task_id": task["task_id"], "due_date": task["due_date"],
                    "classification": "########", "description": "##################",
                }
                for task in tasks
            ]

    def check_has_tasks(self, actor):
        with self._lock():
            user = self._current_user(actor)
            self._agent_tasks(user.agent_id, require=True)

    def request_view_code(self, actor, task_id):
        with self._lock():
            user = self._current_user(actor)
            self._agent_tasks(user.agent_id, task_id, require=True)
            self._send_code(user, "view")
            return mask_email(user.email)

    def view_tasks(self, actor, password, task_id, code):
        with self._lock():
            user = self._current_user(actor)
            user.tasks = self._agent_tasks(user.agent_id, task_id, require=True)
            codes, match = self._find_code(user.agent_id, "view", code)
            if match is None:
                self.audit.write("DECRYPT_DENIED", user.agent_id, "invalid code")
                raise VaultError("Invalid or expired one-time code.")
            match["used"] = "1"
            write_csv(self.tokens_path, TOKEN_FIELDS, codes)
            try:
                tasks = user.reveal_tasks(password)
            except VaultError:
                self.audit.write("DECRYPT_DENIED", user.agent_id, "decryption failed")
                raise
            task_ids = ",".join(task["task_id"] for task in tasks)
            self.audit.write("TASK_DECRYPTED", user.agent_id, task_ids)
            return tasks

    def _send_code(self, user, purpose):
        self.smtp.require_configuration()
        self.audit.cipher()
        now = utc_seconds()
        active = [
            row for row in read_csv(self.tokens_path, TOKEN_FIELDS)
            if row["used"] == "0" and float(row["expires"]) > now
        ]
        digests = {row["digest"] for row in active if row["agent_id"] == user.agent_id}
        while True:
            code = make_code()
            digest = code_digest(code).hex()
            if digest not in digests:
                break
        message = code_email(self.smtp.sender, user.email, purpose, code)
        row = {
            "agent_id": user.agent_id,
            "purpose": purpose,
            "expires": str(now + CODE_LIFETIME),
            "digest": digest,
            "used": "0",
            "guesses": "0",
        }
        write_csv(self.tokens_path, TOKEN_FIELDS, active + [row])
        try:
            self.mailer(self.smtp, message)
        except (OSError, RuntimeError, ValueError) as error:
            write_csv(self.tokens_path, TOKEN_FIELDS, active)
            self.audit.write("CODE_SEND_FAILED", user.agent_id, purpose)
            details = smtp_error_details(error, self.smtp.password, user.email, code, code.replace("-", ""))
            raise VaultError(f"Could not send email: {details}") from None
        self.audit.write("CODE_SENT", user.agent_id, purpose)

    def _find_code(self, agent_id, purpose, code):
        rows = read_csv(self.tokens_path, TOKEN_FIELDS)
        now = utc_seconds()
        guess = code_digest(code)
        active = [
            row for row in rows
            if row["agent_id"] == agent_id and row["purpose"] == purpose
            and row["used"] == "0" and float(row["expires"]) > now
        ]
        match = None
        for row in active:
            if constant_time.bytes_eq(guess, bytes.fromhex(row["digest"])):
                match = row
        if match is None and active:
            for row in active:
                guesses = int(row["guesses"]) + 1
                row["guesses"] = str(guesses)
                if guesses >= CODE_GUESSES:
                    row["used"] = "1"
            write_csv(self.tokens_path, TOKEN_FIELDS, rows)
        return rows, match

    def _reset_account(self, agent_id, username, email):
        account = self._account(agent_id)
        if (
            account is not None
            and account["username"].casefold() == username.strip().casefold()
            and account["email"].casefold() == email.strip().casefold()
        ):
            return account
        return None

    def request_reset(self, agent_id, username, email):
        with self._lock():
            account = self._reset_account(agent_id, username, email)
            if account is None:
                self.audit.write("RESET_REQUEST_REJECTED", detail="identity mismatch")
            self.smtp.require_configuration()
            if account is not None:
                self._send_code(User(account), "reset")

    def reset_password(self, agent_id, username, email, code, password, confirmation, erase):
        with self._lock():
            account = self._reset_account(agent_id, username, email)
            target = account["agent_id"] if account is not None else "-"
            try:
                validate_password(password, confirmation)
                if erase != "ERASE":
                    raise VaultError("Password reset cancelled. Type ERASE to confirm.")
            except VaultError:
                self.audit.write("RESET_FAILED", target, "password validation or confirmation failed")
                raise

            match = None
            if account is not None:
                _, match = self._find_code(target, "reset", code)
            if match is None:
                self.audit.write("RESET_FAILED", target, "invalid code")
                raise VaultError("Invalid or expired reset code.")

            self.audit.cipher()
            new_account = {**account, **password_fields(password)}
            write_csv(self.reset_path, USER_FIELDS, [new_account])
            self._recover_reset()

    def _recover_reset(self):
        pending = read_csv(self.reset_path, USER_FIELDS)
        if not pending:
            return
        if len(pending) != 1:
            raise VaultError("Invalid pending password reset.")
        new_account = pending[0]
        agent_id = new_account["agent_id"]
        users = read_csv(self.users_path, USER_FIELDS)
        if not any(row["agent_id"] == agent_id for row in users):
            raise VaultError("Account for the pending password reset is missing.")
        self.audit.cipher()
        tokens = read_csv(self.tokens_path, TOKEN_FIELDS)
        tasks = read_csv(self.tasks_path, TASK_FIELDS)
        write_csv(self.tokens_path, TOKEN_FIELDS, [row for row in tokens if row["agent_id"] != agent_id])
        write_csv(self.tasks_path, TASK_FIELDS, [row for row in tasks if row["agent_id"] != agent_id])
        write_csv(self.users_path, USER_FIELDS, [
            new_account if row["agent_id"] == agent_id else row for row in users
        ])
        self.audit.write("PASSWORD_RESET", agent_id)
        self.reset_path.unlink()

    def admin_send_code(self, actor, agent_id, purpose):
        with self._lock():
            admin = self._require_admin(actor)
            if purpose not in PURPOSES:
                raise VaultError("Invalid code purpose.")
            account = self._account(agent_id)
            if account is None:
                raise VaultError("No such agent.")
            self._send_code(User(account), purpose)
            self.audit.write("ADMIN_CODE_SENT", admin.agent_id, f"{account['agent_id']} {purpose}")

    def read_audit(self, actor, count="50"):
        with self._lock():
            admin = self._require_admin(actor)
            try:
                count = int(count)
            except ValueError:
                count = 0
            if count < 1:
                raise VaultError("Enter a positive number of audit entries.")
            entries = self.audit.latest(count)
            self.audit.write("AUDIT_VIEWED", admin.agent_id, str(len(entries)))
            return entries

    def doctor(self):
        self.smtp.require_configuration()
        try:
            self.mailer(self.smtp)
        except (OSError, RuntimeError, ValueError) as error:
            raise VaultError(smtp_error_details(error, self.smtp.password)) from None
