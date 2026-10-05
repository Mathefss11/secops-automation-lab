"""Parse command lines found in telemetry.

Command lines are untrusted DATA. Everything here works on strings only:
nothing is executed, evaluated, passed to a shell or used to make a network
request. Decoded PowerShell is returned as text for analyst context only.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from urllib.parse import urlsplit

POWERSHELL_IMAGES = {"powershell.exe", "pwsh.exe"}
OFFICE_IMAGES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
DOWNLOAD_TOOLS = {"curl", "wget"}


def file_name(path: str | None) -> str:
    """File name for Windows (``\\``) or Linux (``/``) paths, case preserved."""
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


def basename(path: str | None) -> str:
    """Lower-cased file name, for case-insensitive comparisons."""
    return file_name(path).lower()


# --- PowerShell -------------------------------------------------------------


def _powershell_options(command_line: str) -> list[tuple[str, str | None]]:
    """Return ``(option_name, next_token)`` pairs, e.g. ``("enc", "SQBFAFgA...")``.

    PowerShell accepts ``-`` or ``/`` and any unambiguous prefix of a
    parameter name (``-e``, ``-enc``, ``-EncodedCommand`` ...), so option
    names are returned lower-cased without the prefix character.
    """
    tokens = command_line.split()
    options = []
    for index, token in enumerate(tokens):
        if len(token) > 1 and token[0] in "-/":
            value = tokens[index + 1] if index + 1 < len(tokens) else None
            options.append((token[1:].lower(), value))
    return options


def _is_prefix_of(name: str, parameter: str) -> bool:
    return bool(name) and parameter.startswith(name)


def get_encoded_command(command_line: str | None) -> str | None:
    """Return the ``-EncodedCommand`` argument, if present."""
    if not command_line:
        return None
    for name, value in _powershell_options(command_line):
        # "-ec" is an accepted alias; "-ex..." (ExecutionPolicy) is not a prefix.
        if name == "ec" or _is_prefix_of(name, "encodedcommand"):
            return value
    return None


def has_hidden_window(command_line: str | None) -> bool:
    """True for ``-WindowStyle Hidden`` and abbreviations such as ``-W Hidden``."""
    if not command_line:
        return False
    for name, value in _powershell_options(command_line):
        if _is_prefix_of(name, "windowstyle") and (value or "").lower() == "hidden":
            return True
    return False


def decode_encoded_command(value: str | None) -> str | None:
    """Decode a PowerShell ``-EncodedCommand`` value (Base64 of UTF-16LE text).

    Returns the decoded text, or ``None`` if the value is not valid Base64 or
    not valid UTF-16LE. The result is for display only and is never executed.
    """
    if not value:
        return None
    try:
        decoded_bytes = base64.b64decode(value, validate=True)
        return decoded_bytes.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


# --- Linux commands ---------------------------------------------------------


def _split_shell(command_line: str | None) -> list[str]:
    """Tokenize like a POSIX shell would, without running anything."""
    if not command_line:
        return []
    try:
        return shlex.split(command_line)
    except ValueError:  # e.g. unbalanced quotes
        return []


def get_download_output_path(command_line: str | None) -> str | None:
    """Return the absolute file path a curl/wget command writes to.

    Supports ``curl -o PATH`` / ``--output PATH`` and ``wget -O PATH`` /
    ``--output-document PATH`` (including clustered short options such as
    ``-sLo PATH``). Returns ``None`` for stdout (``-``), relative paths (the
    working directory is unknown) or commands that do not name an output file.
    """
    tokens = _split_shell(command_line)
    if not tokens or basename(tokens[0]) not in DOWNLOAD_TOOLS:
        return None

    short_flag = "o" if basename(tokens[0]) == "curl" else "O"
    long_flag = "--output" if short_flag == "o" else "--output-document"

    path = None
    for index, token in enumerate(tokens[1:], start=1):
        next_token = tokens[index + 1] if index + 1 < len(tokens) else None
        if token == long_flag:
            path = next_token
        elif token.startswith(long_flag + "="):
            path = token.split("=", 1)[1]
        elif token.startswith("-") and not token.startswith("--") and token.endswith(short_flag):
            path = next_token
    if path and path.startswith("/"):
        return path
    return None


def _mode_adds_execute(mode: str) -> bool:
    """``+x``, ``u+x``, ``a=rx`` or an octal mode with any execute bit."""
    if mode.isdigit():
        return any(int(digit) & 1 for digit in mode[-3:])
    for clause in mode.split(","):
        for operator in "+=":
            if operator in clause and "x" in clause.split(operator, 1)[1]:
                return True
    return False


def get_chmod_execute_targets(command_line: str | None) -> list[str]:
    """Paths that a ``chmod`` command makes executable (empty list otherwise)."""
    tokens = _split_shell(command_line)
    if not tokens or basename(tokens[0]) != "chmod":
        return []
    # Skip options such as -R. ("-x" removes execute permission, so skipping it is correct.)
    arguments = [token for token in tokens[1:] if not token.startswith("-")]
    if len(arguments) < 2 or not _mode_adds_execute(arguments[0]):
        return []
    return arguments[1:]


def get_url_hosts(command_line: str | None) -> list[str]:
    """Hostnames/IPs of http(s)/ftp URLs in a command line (parsing only;
    nothing is fetched)."""
    hosts = []
    for token in _split_shell(command_line):
        if token.lower().startswith(("http://", "https://", "ftp://")):
            host = urlsplit(token).hostname
            if host and host not in hosts:
                hosts.append(host)
    return hosts
