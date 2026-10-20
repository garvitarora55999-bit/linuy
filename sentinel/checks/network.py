"""Read-only local network endpoint and connection inspection ('network').

Implements Part F (Section 12):
- Inspects local listening TCP/UDP endpoints and established/other connections.
- Clearly distinguishes between listening endpoints and established connections.
- Displays Protocol, Local address and port, Remote address and port, PID,
  Process name (where available), Evidence source, and Permission limitations.
- Uses psutil when available, with native /proc/net/{tcp,tcp6,udp,udp6} on Linux
  and allowlisted netstat on Windows as fallbacks.
- Never performs external port scanning, packet capture, or firewall changes.
- Does not classify an unfamiliar port as malicious without evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import struct

from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import TerminalStyle, format_table
from sentinel.utils.validation import (
    read_bounded_file,
    run_allowlisted_command,
    sanitize_output_text,
)

# Linux /proc/net/tcp state map
LINUX_TCP_STATES: dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


@dataclass(frozen=True)
class NetworkEndpointRecord:
    """Normalized local network socket or connection record."""

    protocol: str  # TCP, TCP6, UDP, UDP6
    state: str  # LISTEN, BOUND, ESTABLISHED, etc.
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int | None
    pid: int | None
    process_name: str
    evidence_source: str

    @property
    def is_listening(self) -> bool:
        if self.state in ("LISTEN", "BOUND"):
            return True
        if self.protocol.startswith("UDP") and self.remote_address in ("0.0.0.0", "::", "*", ""):
            return True
        return False

    @property
    def is_wildcard_listener(self) -> bool:
        return self.is_listening and self.local_address in ("0.0.0.0", "::", "*")


def _decode_proc_ipv4(hex_addr: str) -> str:
    try:
        packed = struct.pack("<I", int(hex_addr, 16))
        return socket.inet_ntop(socket.AF_INET, packed)
    except Exception:
        return hex_addr


def _decode_proc_ipv6(hex_addr: str) -> str:
    try:
        if len(hex_addr) != 32:
            return hex_addr
        words = [int(hex_addr[i : i + 8], 16) for i in range(0, 32, 8)]
        packed = struct.pack("<4I", *words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return hex_addr


def _build_inode_to_proc_map(proc_root: Path = Path("/proc")) -> tuple[dict[str, tuple[int, str]], int]:
    """Map socket inodes to (pid, process_name) for accessible processes in /proc."""
    inode_map: dict[str, tuple[int, str]] = {}
    restricted_pids = 0
    if not proc_root.is_dir():
        return inode_map, 0

    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return inode_map, 0

    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        fd_dir = entry / "fd"
        comm_file = entry / "comm"
        proc_name = "unknown"
        try:
            if comm_file.is_file():
                proc_name = sanitize_output_text(
                    read_bounded_file(comm_file, max_bytes=4096, allow_symlinks=False).strip(), 48
                )
            for fd_entry in fd_dir.iterdir():
                try:
                    target = os.readlink(fd_entry)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    inode = target[8:-1]
                    inode_map[inode] = (pid, proc_name)
        except PermissionError:
            restricted_pids += 1
        except (OSError, ValueError):
            continue

    return inode_map, restricted_pids


def parse_proc_net_table(
    content: str,
    protocol: str,
    inode_map: dict[str, tuple[int, str]] | None = None,
) -> list[NetworkEndpointRecord]:
    """Parse /proc/net/{tcp,tcp6,udp,udp6} content into NetworkEndpointRecord objects."""
    records: list[NetworkEndpointRecord] = []
    is_ipv6 = protocol.endswith("6")
    is_udp = protocol.startswith("UDP")
    imap = inode_map or {}

    for idx, line in enumerate(content.splitlines()):
        stripped = line.strip()
        if not stripped or idx == 0 or stripped.startswith("sl"):
            continue
        parts = stripped.split()
        if len(parts) < 10:
            continue
        local_raw = parts[1]
        rem_raw = parts[2]
        state_hex = parts[3].upper()
        inode = parts[9]

        if ":" not in local_raw or ":" not in rem_raw:
            continue
        l_addr_hex, _, l_port_hex = local_raw.partition(":")
        r_addr_hex, _, r_port_hex = rem_raw.partition(":")

        try:
            l_port = int(l_port_hex, 16)
            r_port = int(r_port_hex, 16)
        except ValueError:
            continue

        l_ip = _decode_proc_ipv6(l_addr_hex) if is_ipv6 else _decode_proc_ipv4(l_addr_hex)
        r_ip = _decode_proc_ipv6(r_addr_hex) if is_ipv6 else _decode_proc_ipv4(r_addr_hex)

        if is_udp:
            state = "BOUND" if r_port == 0 and r_ip in ("0.0.0.0", "::") else "ESTABLISHED"
        else:
            state = LINUX_TCP_STATES.get(state_hex, f"STATE_{state_hex}")

        pid_info = imap.get(inode)
        pid = pid_info[0] if pid_info else None
        pname = pid_info[1] if pid_info else "<restricted or kernel>"

        records.append(
            NetworkEndpointRecord(
                protocol=protocol,
                state=state,
                local_address=l_ip,
                local_port=l_port,
                remote_address=r_ip,
                remote_port=r_port if r_port != 0 else None,
                pid=pid,
                process_name=pname,
                evidence_source=f"/proc/net/{protocol.lower()}",
            )
        )
    return records


def collect_network_psutil() -> tuple[list[NetworkEndpointRecord], list[str]]:
    """Collect network endpoints using psutil.net_connections(kind='inet')."""
    import psutil  # type: ignore

    records: list[NetworkEndpointRecord] = []
    limitations: list[str] = []
    restricted_pids = 0

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        raise PermissionError(f"psutil.net_connections requires elevated privileges on this OS: {exc}") from exc

    for c in conns:
        is_v6 = c.family == socket.AF_INET6
        is_tcp = c.type == socket.SOCK_STREAM
        proto = ("TCP6" if is_v6 else "TCP") if is_tcp else ("UDP6" if is_v6 else "UDP")

        l_ip = c.laddr.ip if c.laddr else "0.0.0.0"
        l_port = int(c.laddr.port) if c.laddr else 0
        r_ip = c.raddr.ip if c.raddr else ("*" if not is_tcp else "0.0.0.0")
        r_port = int(c.raddr.port) if c.raddr else None

        raw_state = str(getattr(c, "status", "") or "")
        if not is_tcp and raw_state in ("NONE", ""):
            state = "BOUND" if r_port is None else "ESTABLISHED"
        else:
            state = sanitize_output_text(raw_state or "UNKNOWN", 24)

        pid = c.pid
        pname = "<restricted>"
        if pid is not None:
            try:
                pname = sanitize_output_text(psutil.Process(pid).name(), 48)
            except (psutil.AccessDenied, PermissionError):
                pname = "<permission denied>"
                restricted_pids += 1
            except (psutil.NoSuchProcess, OSError):
                pname = "<exited>"
        else:
            restricted_pids += 1

        records.append(
            NetworkEndpointRecord(
                protocol=proto,
                state=state,
                local_address=sanitize_output_text(l_ip, 64),
                local_port=l_port,
                remote_address=sanitize_output_text(r_ip, 64),
                remote_port=r_port,
                pid=pid,
                process_name=pname,
                evidence_source="psutil.net_connections",
            )
        )

    if restricted_pids > 0:
        limitations.append(
            f"PID/process ownership was hidden for {restricted_pids} socket(s) owned by other users or root."
        )
    return records, limitations


def collect_network_linux_proc(proc_root: Path = Path("/proc")) -> tuple[list[NetworkEndpointRecord] | None, list[str]]:
    """Collect TCP/UDP sockets on Linux from /proc/net/{tcp,tcp6,udp,udp6}."""
    limitations: list[str] = []
    net_dir = proc_root / "net"
    if not net_dir.is_dir():
        limitations.append(f"Directory {net_dir} is not accessible.")
        return None, limitations

    inode_map, restricted_pids = _build_inode_to_proc_map(proc_root)
    records: list[NetworkEndpointRecord] = []

    for proto, fname in (("TCP", "tcp"), ("TCP6", "tcp6"), ("UDP", "udp"), ("UDP6", "udp6")):
        fpath = net_dir / fname
        try:
            if fpath.is_file() and os.access(fpath, os.R_OK):
                content = read_bounded_file(fpath, max_bytes=2 * 1024 * 1024, allow_symlinks=False)
                records.extend(parse_proc_net_table(content, proto, inode_map))
        except (OSError, ValueError):
            continue

    if restricted_pids > 0:
        limitations.append(
            f"Could not inspect /proc/<pid>/fd for {restricted_pids} process(es) owned by other users; "
            "those sockets display PID/process as '<restricted or kernel>'."
        )
    limitations.append(
        "Passive local socket table inspection only; no network packets or port scans were transmitted."
    )
    return records, limitations


def parse_windows_netstat_ano(stdout: str) -> list[NetworkEndpointRecord]:
    """Parse Windows 'netstat -ano' output into NetworkEndpointRecord objects."""
    records: list[NetworkEndpointRecord] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        proto_raw = parts[0].upper()
        if proto_raw not in ("TCP", "UDP"):
            continue
        local_ep = parts[1]
        remote_ep = parts[2]
        if proto_raw == "TCP" and len(parts) >= 5:
            state = sanitize_output_text(parts[3].upper(), 24)
            pid_str = parts[4]
        else:
            state = "BOUND" if remote_ep.startswith("*:*") or remote_ep.endswith(":*") else "UDP"
            pid_str = parts[3]

        is_v6 = local_ep.startswith("[")
        proto = f"{proto_raw}6" if is_v6 else proto_raw

        def _split_ep(ep: str) -> tuple[str, int | None]:
            if ep in ("*:*", "*"):
                return "*", None
            if ":" not in ep:
                return ep, None
            addr, _, port_s = ep.rpartition(":")
            addr = addr.strip("[]")
            return addr, int(port_s) if port_s.isdigit() else None

        l_ip, l_port = _split_ep(local_ep)
        r_ip, r_port = _split_ep(remote_ep)
        pid = int(pid_str) if pid_str.isdigit() else None

        records.append(
            NetworkEndpointRecord(
                protocol=proto,
                state=state if state != "LISTENING" else "LISTEN",
                local_address=sanitize_output_text(l_ip, 64),
                local_port=l_port or 0,
                remote_address=sanitize_output_text(r_ip, 64),
                remote_port=r_port,
                pid=pid,
                process_name="(see processes table)",
                evidence_source="netstat -ano",
            )
        )
    return records


def collect_network_endpoints(
    profile: PlatformProfile | None = None,
    prefer_psutil: bool = True,
) -> tuple[list[NetworkEndpointRecord] | None, list[str]]:
    """Collect local network sockets and connections across Linux and Windows."""
    pf = profile or detect_platform()
    psutil_error_note = ""
    if prefer_psutil and pf.psutil_available:
        try:
            return collect_network_psutil()
        except Exception as exc:
            psutil_error_note = f"psutil socket query failed ({sanitize_output_text(exc, 80)}); using OS fallback."

    if pf.os_family == "Linux":
        recs, lims = collect_network_linux_proc()
        if psutil_error_note:
            lims = [psutil_error_note, *lims]
        return recs, lims

    if pf.os_family == "Windows":
        res = run_allowlisted_command("netstat", args=["-ano"], timeout=8.0)
        if not res.ok:
            return None, [f"Failed to execute 'netstat -ano': {res.error_message or 'command failed'}."]
        recs = parse_windows_netstat_ano(res.stdout)
        return recs, [
            "Collected via allowlisted 'netstat -ano' fallback.",
            "Unfamiliar listening ports are not automatically malicious; correlate PIDs with 'processes'.",
        ]

    return None, [f"Network socket inspection is unsupported on OS '{pf.os_family}' without psutil."]


def render_network_command(
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
) -> tuple[str, list[Finding]]:
    """Render 'network' command output separating Listening Endpoints from Active Connections."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    records, limitations = collect_network_endpoints(pf)
    now = utc_now_iso()

    lines = [
        st.header("LOCAL NETWORK ENDPOINT & CONNECTION INSPECTION"),
        f"OS / Version: {pf.display_label} | Execution mode: Read-only | Scope: Local",
    ]

    if records is None:
        lines.append("\n  [ERROR/UNSUPPORTED] Could not inspect local network endpoints.")
        for lim in limitations:
            lines.append(f"  - {lim}")
        finding = Finding(
            finding_id="NET-0001",
            rule_id="NET-SOCK-001",
            title="Local Network Endpoint Inspection",
            severity=Severity.LOW.value,
            status=FindingStatus.ERROR.value if pf.os_family in ("Linux", "Windows") else FindingStatus.UNSUPPORTED.value,
            platform=pf.display_label,
            description="Unable to query local TCP/UDP socket tables.",
            evidence="records=None",
            detection_rationale="Attempted read-only local socket inspection.",
            remediation="Verify permissions or install psutil.",
            timestamp=now,
            limitations=" | ".join(limitations),
            inspected_item="Local TCP/UDP listening sockets and active connections",
            why_it_matters="Listening sockets define the host's network reachability surface.",
            determination_method="Read-only inspection of OS socket tables.",
        )
        return "\n".join(lines), [finding]

    listening = [r for r in records if r.is_listening]
    connections = [r for r in records if not r.is_listening]
    wildcard_listeners = [r for r in listening if r.is_wildcard_listener]

    def _fmt_rows(items: list[NetworkEndpointRecord]) -> list[list[str]]:
        return [
            [
                r.protocol,
                r.state,
                f"{r.local_address}:{r.local_port}",
                f"{r.remote_address}:{r.remote_port}" if r.remote_port is not None else r.remote_address,
                str(r.pid) if r.pid is not None else "n/a",
                r.process_name,
                r.evidence_source,
            ]
            for r in items
        ]

    headers = ["Proto", "State", "Local Endpoint", "Remote Endpoint", "PID", "Process", "Evidence Source"]

    lines.append(st.section(f"1. Listening / Bound Endpoints ({len(listening)})"))
    if not listening:
        lines.append("  Confirmed 0 local listening TCP/UDP endpoints observed.")
    else:
        lines.append(format_table(headers, _fmt_rows(listening), max_col_width=36))

    lines.append(st.section(f"2. Established / Other Connections ({len(connections)})"))
    if not connections:
        lines.append("  Confirmed 0 active/established connections observed.")
    else:
        lines.append(format_table(headers, _fmt_rows(connections), max_col_width=36))

    if limitations:
        lines.append(st.section("Inspection Limitations & Guidance"))
        for lim in limitations:
            lines.append(f"  - {lim}")
        lines.append(
            "  - Note: An unfamiliar port is not inherently malicious. Verify the owning binary "
            "and whether the listener is bound to loopback (127.0.0.1/::1) vs all interfaces (0.0.0.0/::)."
        )

    if wildcard_listeners:
        w_ports = [f"{r.protocol}:{r.local_port} ({r.process_name})" for r in wildcard_listeners[:8]]
        status = FindingStatus.REVIEW.value
        sev = Severity.LOW.value
        desc = (
            f"Observed {len(listening)} listening endpoint(s), including {len(wildcard_listeners)} "
            f"bound to wildcard interfaces (0.0.0.0 or ::)."
        )
        ev = f"listening={len(listening)}; established={len(connections)}; wildcard={w_ports}"
    else:
        status = FindingStatus.PASS.value
        sev = Severity.INFO.value
        desc = (
            f"Observed {len(listening)} listening endpoint(s) (none bound to wildcard interfaces) "
            f"and {len(connections)} active connection(s)."
        )
        ev = f"listening={len(listening)}; established={len(connections)}; wildcard=0"

    finding = Finding(
        finding_id="NET-0001",
        rule_id="NET-SOCK-001",
        title="Local Network Socket & Listener Inventory",
        severity=sev,
        status=status,
        platform=pf.display_label,
        description=desc,
        evidence=ev,
        detection_rationale=(
            "Enumerated local TCP/UDP sockets and separated listening endpoints from established connections."
        ),
        remediation=(
            "Review any wildcard (0.0.0.0 / ::) listeners to confirm they are required and protected by host firewall rules."
        ),
        timestamp=now,
        limitations=" | ".join(limitations),
        inspected_item="Local TCP/UDP listening sockets and established connections",
        why_it_matters="Services bound to 0.0.0.0 or :: accept connections from external network interfaces.",
        determination_method="Read-only inspection of psutil.net_connections or /proc/net / netstat tables.",
    )
    return "\n".join(lines), [finding]
