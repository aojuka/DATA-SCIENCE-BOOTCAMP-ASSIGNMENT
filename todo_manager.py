import csv
import os

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from security import CLASSIFICATIONS, SmtpSettings
from self_test import run_self_test
from storage import BASE, VaultError, data_directory, load_env
from vault import PURPOSES, Vault


console = Console(markup=False, highlight=False, emoji=False)
border = type(Panel("").box)("+-++\n| ||\n+-++\n| ||\n+-++\n+-++\n| ||\n+-++\n")
classification_colors = {
    "Top Secret": "bold red", "Secret": "bold yellow", "Confidential": "bold cyan",
}
RESET_NOTICE = "If those details match our records, a reset code has been emailed to you."


class HiddenPrompt(Prompt):
    def process_response(self, value):
        return value


def terminal_text(value):
    return "".join(char if " " <= char <= "~" else ascii(char)[1:-1] for char in value)


def show_panel(text):
    console.print(Panel(text, box=border, border_style="cyan", expand=False))


def show_error(text):
    console.print(f"Error: {terminal_text(text)}", style="bold red", soft_wrap=True)


def show_success(text):
    console.print(terminal_text(text), style="green")


def ask(label, **options):
    return Prompt.ask(label, console=console, **options)


def ask_secret(label):
    return HiddenPrompt.ask(label, console=console, password=True)


def credentials(vault):
    username = ask("Username")
    password = ask_secret("Password")
    return vault.login(username, password), password


def make_table(*headers):
    table = Table(box=border)
    for header in headers:
        table.add_column(header, overflow="fold")
    return table


def show_tasks(tasks):
    if not tasks:
        console.print("You have no tasks.", style="dim")
        return
    table = make_table("ID", "Due date", "Classification", "Description")
    for task in tasks:
        classification = task["classification"]
        color = classification_colors.get(classification, "dim")
        table.add_row(
            terminal_text(task["task_id"]),
            terminal_text(task["due_date"]),
            console.render_str(terminal_text(classification), style=color),
            terminal_text(task["description"]),
        )
    console.print(table)


def menu_register(vault):
    agent_id = ask("Agency-issued agent ID")
    username = ask("Username")
    email = ask("Email")
    password = ask_secret("Password")
    confirmation = ask_secret("Repeat password")
    user = vault.register(agent_id, username, email, password, confirmation)
    show_success(f"OK. Registered {user.agent_id} as {user.authorisation_level}.")


def menu_login(vault):
    user, _ = credentials(vault)
    show_success(f"OK. Credentials verified for {user.agent_id} ({user.authorisation_level}).")


def menu_add_task(vault):
    user, password = credentials(vault)
    description = ask("Description")
    due_date = ask("Due date (YYYY-MM-DD)")
    classification = ask("Classification", choices=list(CLASSIFICATIONS), default="Secret")
    task_id = vault.add_task(user, password, description, due_date, classification)
    show_success(f"OK. Task {task_id} added.")


def menu_list_tasks(vault):
    user, _ = credentials(vault)
    show_tasks(vault.list_tasks(user))


def menu_view_tasks(vault):
    user, password = credentials(vault)
    vault.check_has_tasks(user)
    task_id = ask("Task ID (Enter for all)", default="", show_default=False)
    address = vault.request_view_code(user, task_id)
    show_success(f"OK. Code sent to {address}.")
    code = ask_secret("One-time code")
    show_tasks(vault.view_tasks(user, password, task_id, code))


def menu_reset(vault):
    agent_id = ask("Agency-issued agent ID")
    username = ask("Username")
    email = ask("Registered email")
    vault.request_reset(agent_id, username, email)
    console.print(RESET_NOTICE, style="dim")
    code = ask_secret("Reset code")
    password = ask_secret("New password")
    confirmation = ask_secret("Repeat new password")
    console.print("Existing tasks are encrypted with your old password and will be erased.", style="bold yellow")
    erase = ask("Type ERASE to confirm")
    vault.reset_password(agent_id, username, email, code, password, confirmation, erase)
    show_success("OK. Password reset and old tasks erased.")


def menu_admin_send(vault):
    user, _ = credentials(vault)
    vault.check_admin(user)
    agent_id = ask("Target agent ID")
    purpose = ask("Purpose", choices=list(PURPOSES))
    vault.admin_send_code(user, agent_id, purpose)
    show_success("OK. Code sent to the agent's registered address.")


def menu_admin_audit(vault):
    user, _ = credentials(vault)
    vault.check_admin(user)
    count = ask("Number of entries", default="50")
    table = make_table("Timestamp", "Event", "Agent", "Detail")
    for entry in vault.read_audit(user, count):
        table.add_row(*(terminal_text(field) for field in entry))
    console.print(table)


def menu_doctor(vault):
    settings = vault.smtp
    fields = (
        ("Data folder", str(vault.directory)),
        ("SMTP host", settings.host or "(unset)"),
        ("SMTP port", settings.port),
        ("SMTP TLS", settings.use_tls),
        ("SMTP user", settings.user or "(unset)"),
        ("SMTP From", settings.sender or "(unset)"),
    )
    for label, value in fields:
        console.print(f"{label} = {terminal_text(value)}", style="dim")
    vault.doctor()
    show_success("SMTP connection and login OK.")


def menu_self_test(vault):
    checks = run_self_test(vault.directory)
    show_success(f"Self-test passed: {checks} checks")


menu_options = {
    "1": ("Register", menu_register),
    "2": ("Login (check credentials)", menu_login),
    "3": ("Add task", menu_add_task),
    "4": ("List tasks (redacted)", menu_list_tasks),
    "5": ("View tasks (reveal with emailed code)", menu_view_tasks),
    "6": ("Reset password", menu_reset),
    "7": ("[Admin] Send one-time code to an agent", menu_admin_send),
    "8": ("[Admin] View audit log", menu_admin_audit),
    "9": ("Doctor (check .env and SMTP)", menu_doctor),
    "10": ("Self-test", menu_self_test),
}


def run_menu(vault):
    show_panel("Secure Task Management")
    menu = "\n".join(f"{number}. {label}" for number, (label, _) in menu_options.items())
    while True:
        console.print(f"\n{menu}\n0. Exit")
        choice = ask("Select an option", choices=[*menu_options, "0"])
        if choice == "0":
            return
        label, action = menu_options[choice]
        show_panel(label)
        try:
            action(vault)
        except VaultError as error:
            show_error(str(error))
        except OSError as error:
            show_error(f"Could not access stored data: {error.strerror or 'file operation failed'}.")
        except (csv.Error, ValueError):
            show_error("Could not read stored data or configuration.")


def main():
    try:
        load_env(BASE / ".env")
        settings = SmtpSettings(os.environ)
        vault = Vault(data_directory(), settings, os.environ.get("AGENCY_LOG_KEY", ""))
        run_menu(vault)
    except KeyboardInterrupt:
        console.print("Aborted.")
        raise SystemExit(130) from None
    except EOFError:
        return 0
    except VaultError as error:
        show_error(str(error))
        return 1
    except (OSError, ValueError):
        show_error("Could not open the data folder or read configuration.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
