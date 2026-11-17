import csv
import os
import secrets
from pathlib import Path

from security import CODE_ALPHABET, DECRYPTION_FAILED, EMAIL_NOT_CONFIGURED, SmtpSettings, code_digest
from storage import BASE, TASK_FIELDS, TOKEN_FIELDS, USER_FIELDS, VaultError, read_csv, utc_seconds, write_csv
from vault import CODE_GUESSES, LOGIN_ATTEMPTS, LOCKED, Vault


def run_self_test(real_directory):
    if not __debug__:
        raise VaultError("Self-test requires assertions. Run Python without -O.")
    configured = os.environ.get("TMPDIR") or os.environ.get("TEMP") or os.environ.get("TMP")
    parent = (BASE / Path(configured or ("/tmp" if os.name == "posix" else "."))).resolve()
    if parent == real_directory or real_directory in parent.parents:
        parent = real_directory.parent
    temporary = parent / f"todo-self-test-{secrets.token_hex(12)}.tmp"
    temporary.mkdir(mode=0o700)

    messages = []
    checks = 0

    def record_email(settings, message=None):
        if message is not None:
            messages.append(message)

    def latest_code():
        return messages[-1].get_content().splitlines()[0].removesuffix(".").rsplit(" ", 1)[-1]

    def check(label, condition):
        nonlocal checks
        assert condition, label
        checks += 1

    def rejects(label, expected, operation, *arguments):
        try:
            operation(*arguments)
        except VaultError as error:
            check(label, str(error) == expected)
        else:
            check(label, False)

    try:
        smtp = SmtpSettings({"SMTP_HOST": "example.invalid", "SMTP_FROM": "vault@agency.test"})
        vault = Vault(temporary, smtp, mailer=record_email)
        password = "Test-Vault-75!"
        new_password = "New-Vault-23!"
        address = "jane.doe@agency.test"
        identity = ("ag-01", "JANE", "JANE.DOE@AGENCY.TEST")
        admin = vault.register("ag-01", "jane", address, password, password)
        agent = vault.register("AG-02", "agent", "agent@agency.test", password, password)
        check("first account is admin", admin.authorisation_level == "admin" and admin.agent_id == "AG-01")
        check("second account is agent", agent.authorisation_level == "agent")
        duplicate = "Agent ID or username already registered."
        rejects("duplicate agent ID", duplicate, vault.register, "ag-01", "other", address, password, password)
        rejects("case-insensitive duplicate username", duplicate,
                vault.register, "AG-03", "JaNe", address, password, password)
        weak = "Password must contain: at least 12 characters, an uppercase letter, a digit, a symbol."
        rejects("weak registration password", weak, vault.register, "AG-03", "other", address, "weak", "weak")
        rejects("password confirmation", "Passwords do not match.",
                vault.register, "AG-03", "other", address, password, new_password)
        check("password hash is stored as hex",
              len(bytes.fromhex(admin.row["password_hash"])) == 32
              and password not in vault.users_path.read_text(encoding="utf-8"))
        check("password and task salts are distinct",
              admin.row["password_salt"] != admin.row["key_salt"]
              and len(bytes.fromhex(admin.row["key_salt"])) == 16)
        rejects("unknown account uses generic error", "Invalid credentials.", vault.login, "unknown", "wrong")
        for attempt in range(1, LOGIN_ATTEMPTS + 1):
            rejects(f"wrong login {attempt}", LOCKED if attempt == LOGIN_ATTEMPTS else "Invalid credentials.",
                    vault.login, "JaNe", "wrong")
        rejects("correct password is blocked during lockout", LOCKED, vault.login, "jane", password)
        rows = read_csv(vault.users_path, USER_FIELDS)
        check("lockout state is persisted",
              rows[0]["failed_attempts"] == str(LOGIN_ATTEMPTS) and float(rows[0]["locked_until"]) > utc_seconds())
        rows[0]["locked_until"] = "1"
        write_csv(vault.users_path, USER_FIELDS, rows)
        admin = vault.login("JaNe", password)
        check("successful login clears counters",
              admin.row["failed_attempts"] == "0" and admin.row["locked_until"] == "0")

        rejects("no tasks means no code", "You have no tasks.", vault.request_view_code, admin, "")
        task_text = "Sensitive sample, line one\nSecond line with [markup] and \u2603."
        task_id = vault.add_task(admin, password, task_text, "2032-05-20", "Top Secret")
        other_task = vault.add_task(agent, password, "Separate agent's task", "2032-05-21", "Confidential")
        stored_tasks = vault.tasks_path.read_text(encoding="utf-8")
        check("sensitive task fields stay off disk",
              "Sensitive sample" not in stored_tasks and "Top Secret" not in stored_tasks
              and "2032-05-20" in stored_tasks)
        check("redacted isolated task list", vault.list_tasks(admin) == [{
            "task_id": task_id, "due_date": "2032-05-20",
            "classification": "########", "description": "##################",
        }])
        rejects("invalid task ID means no code", "No such task.", vault.request_view_code, admin, other_task)
        check("no delivery for absent and foreign tasks", not messages)
        check("address is masked", vault.request_view_code(admin, task_id) == "j******e@agency.test")
        code = latest_code()
        check("one-time code format",
              len(code) == 9 and code[4] == "-" and all(char in CODE_ALPHABET for char in code.replace("-", "")))
        token_csv = vault.tokens_path.read_text(encoding="utf-8")
        check("only the digest of the code is stored", code not in token_csv and code_digest(code).hex() in token_csv)
        invalid_view = "Invalid or expired one-time code."
        rejects("wrong view code", invalid_view, vault.view_tasks, admin, password, task_id, "wrong")
        revealed = vault.view_tasks(admin, password, task_id, code.lower().replace("-", " - "))
        check("valid view code reveals the original task",
              len(revealed) == 1 and revealed[0]["description"] == task_text
              and revealed[0]["classification"] == "Top Secret")
        rejects("view code cannot be reused", invalid_view, vault.view_tasks, admin, password, task_id, code)

        vault.request_view_code(admin, "")
        check("used codes are pruned on issue", len(read_csv(vault.tokens_path, TOKEN_FIELDS)) == 1)
        code = latest_code()
        for attempt in range(1, CODE_GUESSES + 1):
            rejects(f"wrong code guess {attempt}", invalid_view, vault.view_tasks, admin, password, "", "wrong")
        rejects("three guesses burn the code", invalid_view, vault.view_tasks, admin, password, "", code)
        vault.request_view_code(admin, "")
        code = latest_code()
        rows = read_csv(vault.tokens_path, TOKEN_FIELDS)
        rows[0]["expires"] = "1"
        write_csv(vault.tokens_path, TOKEN_FIELDS, rows)
        rejects("expired code is rejected", invalid_view, vault.view_tasks, admin, password, "", code)
        vault.request_view_code(admin, "")
        check("expired codes are pruned on issue", len(read_csv(vault.tokens_path, TOKEN_FIELDS)) == 1)
        code = latest_code()
        rejects("wrong password fails after code use", DECRYPTION_FAILED,
                vault.view_tasks, admin, "wrong", "", code)
        rejects("code stays consumed after decryption failure", invalid_view,
                vault.view_tasks, admin, password, "", code)

        vault.request_view_code(admin, task_id)
        original_tasks = read_csv(vault.tasks_path, TASK_FIELDS)
        tampered_tasks = [dict(row) for row in original_tasks]
        blob = bytearray.fromhex(tampered_tasks[0]["blob_hex"])
        blob[-1] ^= 1
        tampered_tasks[0]["blob_hex"] = blob.hex()
        write_csv(vault.tasks_path, TASK_FIELDS, tampered_tasks)
        rejects("tampered ciphertext is detected", DECRYPTION_FAILED,
                vault.view_tasks, admin, password, task_id, latest_code())
        write_csv(vault.tasks_path, TASK_FIELDS, original_tasks)

        deliveries = len(messages)
        for incorrect in (
            ("AG-99", identity[1], identity[2]),
            (identity[0], "different", identity[2]),
            (identity[0], identity[1], "different@agency.test"),
        ):
            vault.request_reset(*incorrect)
        check("each wrong reset identity field prevents delivery", len(messages) == deliveries)
        vault.request_reset(*identity)
        reset_code = latest_code()
        check("matching identity receives a reset code",
              len(messages) == deliveries + 1 and messages[-1]["To"] == address
              and "for reset" in messages[-1].get_content())
        rejects("a reset code cannot reveal a task", invalid_view,
                vault.view_tasks, admin, password, "", reset_code)
        rejects("weak reset password does not consume a code", weak,
                vault.reset_password, *identity, reset_code, "weak", "weak", "ERASE")
        rejects("reset requires erasure confirmation", "Password reset cancelled. Type ERASE to confirm.",
                vault.reset_password, *identity, reset_code, new_password, new_password, "NO")
        vault.reset_password(*identity, reset_code, new_password, new_password, "ERASE")
        rejects("old password is rejected", "Invalid credentials.", vault.login, admin.username, password)
        admin = vault.login(admin.username, new_password)
        check("reset erases only the matching agent's tasks",
              not vault.list_tasks(admin) and vault.list_tasks(agent)[0]["task_id"] == other_task)
        rejects("reset code cannot be reused", "Invalid or expired reset code.",
                vault.reset_password, *identity, reset_code, password, password, "ERASE")

        admin_error = "Admin authorisation required."
        rejects("agent cannot send codes", admin_error, vault.admin_send_code, agent, agent.agent_id, "view")
        rejects("agent cannot read the audit log", admin_error, vault.read_audit, agent)
        vault.admin_send_code(admin, agent.agent_id, "view")
        check("admin can send a code", messages[-1]["To"] == agent.email)
        check("admin-issued code works for its recipient",
              vault.view_tasks(agent, password, other_task, latest_code())[0]["task_id"] == other_task)
        encrypted_log = vault.audit.path.read_bytes()
        check("audit events are encrypted",
              all(event not in encrypted_log for event in (b"REGISTER", b"LOGIN_OK", b"PASSWORD_RESET")))
        entries = vault.read_audit(admin)
        check("admin can read the audit log",
              any(event == "ADMIN_CODE_SENT" for _, event, _, _ in entries)
              and any(event == "PASSWORD_RESET" for _, event, _, _ in entries))
        with vault.audit.path.open("ab") as handle:
            handle.write(b"invalid-audit-entry\n")
        check("corrupt audit entry renders safely", vault.read_audit(admin, "1")[0][1] == "CORRUPT")
        unconfigured = Vault(temporary, SmtpSettings({}), mailer=record_email)
        rejects("missing configuration prevents email", EMAIL_NOT_CONFIGURED,
                unconfigured.admin_send_code, admin, agent.agent_id, "view")
        rejects("doctor catches missing configuration", EMAIL_NOT_CONFIGURED, unconfigured.doctor)
        return checks
    except (AssertionError, VaultError, OSError, csv.Error, ValueError) as error:
        raise VaultError(f"Self-test failed: {error}") from None
    finally:
        for path in temporary.iterdir():
            path.unlink()
        temporary.rmdir()
