"""Run one reviewed command on a directly reachable Linux SSH server.

Install: python -m pip install paramiko
Run:     python ssh_command.py
Fill in the configuration below first. Passwords are prompted, not stored.
This is a connection example, not a validator for LLM-generated commands.
"""

import getpass
import shlex
import sys
import time
from pathlib import Path

import paramiko


# ---- Company details: replace these placeholders ----
HOST = "<COMPANY_SERVER_HOSTNAME_OR_IP>"
PORT = 22  # Confirm the company's SSH port.
USERNAME = "<COMPANY_SSH_USERNAME>"
KNOWN_HOSTS_FILE = r"<LOCAL_PATH_TO_COMPANY_VERIFIED_KNOWN_HOSTS_FILE>"

AUTH_METHOD = "password"  # Choose "password" or "key".
PRIVATE_KEY_FILE = r"<LOCAL_PATH_TO_PRIVATE_KEY>"  # Only for AUTH_METHOD="key".
# Use a Paramiko-compatible OpenSSH/PEM key, not a PuTTY .ppk file.

# Command runs on the REMOTE Linux server. Change only to a reviewed command.
COMMAND = "uname -r"
# Optional VERIFIED absolute remote directory, e.g. "/opt/company/application".
REMOTE_DIRECTORY = None

CONNECT_TIMEOUT = 15
COMMAND_TIMEOUT = 30
MAX_OUTPUT_BYTES = 1024 * 1024


def execute_command(client, command):
    """Drain both streams to avoid blocking when either output buffer fills."""
    stdin, stdout, stderr = client.exec_command(
        command, timeout=COMMAND_TIMEOUT, get_pty=False
    )
    stdin.close()
    channel = stdout.channel
    channel.shutdown_write()  # No interactive input for this command.
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + COMMAND_TIMEOUT
    try:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Command exceeded the configured read deadline.")
            if channel.recv_ready():
                output.extend(channel.recv(32768))
            if channel.recv_stderr_ready():
                errors.extend(channel.recv_stderr(32768))
            if len(output) + len(errors) > MAX_OUTPUT_BYTES:
                raise RuntimeError("Command output exceeded the configured limit.")
            if channel.exit_status_ready():
                if not channel.recv_ready() and not channel.recv_stderr_ready():
                    return (
                        output.decode("utf-8", errors="replace"),
                        errors.decode("utf-8", errors="replace"),
                        channel.recv_exit_status(),
                    )
            time.sleep(0.05)
    finally:
        stdout.close()
        stderr.close()
        channel.close()


def main():
    for label, value in (
        ("HOST", HOST), ("USERNAME", USERNAME),
        ("KNOWN_HOSTS_FILE", KNOWN_HOSTS_FILE),
    ):
        if not value or "<" in value:
            raise ValueError(f"Replace the {label} placeholder first.")
    known_hosts = Path(KNOWN_HOSTS_FILE).expanduser()
    if not known_hosts.is_file():
        raise FileNotFoundError("The configured known_hosts file does not exist.")

    auth = {}
    if AUTH_METHOD == "password":
        auth["password"] = getpass.getpass("Company SSH password: ")
    elif AUTH_METHOD == "key":
        if "<" in PRIVATE_KEY_FILE:
            raise ValueError("Replace PRIVATE_KEY_FILE first.")
        key_path = Path(PRIVATE_KEY_FILE).expanduser()
        if not key_path.is_file():
            raise FileNotFoundError("The configured private key does not exist.")
        auth["key_filename"] = str(key_path)
        auth["passphrase"] = getpass.getpass(
            "Private-key passphrase (Enter if unencrypted): "
        ) or None
    else:
        raise ValueError("AUTH_METHOD must be 'password' or 'key'.")

    command = COMMAND
    if REMOTE_DIRECTORY:
        if not REMOTE_DIRECTORY.startswith("/"):
            raise ValueError("REMOTE_DIRECTORY must be an absolute Linux path.")
        command = f"cd {shlex.quote(REMOTE_DIRECTORY)} && {command}"

    with paramiko.SSHClient() as client:
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=HOST, port=PORT, username=USERNAME,
            timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT,
            auth_timeout=CONNECT_TIMEOUT, channel_timeout=CONNECT_TIMEOUT,
            look_for_keys=False, allow_agent=False, **auth,
        )
        print("SSH connection established.")
        output, errors, exit_code = execute_command(client, command)
        print("STDOUT:\n" + (output.strip() or "(empty)"))
        print("STDERR:\n" + (errors.strip() or "(empty)"))
        print(f"Remote exit code: {exit_code}")
        return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (paramiko.SSHException, OSError, ValueError, RuntimeError) as exc:
        print(f"Connection/command failed: {exc}", file=sys.stderr)
        sys.exit(1)
