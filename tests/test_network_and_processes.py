"""Tests for network endpoint inspection and process enumeration across Linux, Windows, and psutil."""

from __future__ import annotations

from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from sentinel.checks.network import (
    collect_network_psutil,
    parse_proc_net_table,
    parse_windows_netstat_ano,
    render_network_command,
)
from sentinel.checks.processes import (
    collect_processes_linux_proc,
    collect_processes_psutil,
    parse_windows_tasklist_csv,
    render_processes_command,
)


class TestNetworkAndProcessInspection(unittest.TestCase):
    """Verify network listener/connection separation and safe process inspection."""

    def test_parse_linux_proc_net_tcp_and_udp(self) -> None:
        # 0100007F:0035 -> 127.0.0.1:53 (LISTEN = 0A)
        # 00000000:0016 -> 0.0.0.0:22 (LISTEN = 0A)
        # 0A00020F:C350 -> 15.2.0.10:50000 connected to 586433C6:01BB (198.51.100.88:443, ESTABLISHED = 01)
        proc_tcp = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 11111 1 0000000000000000 100 0 0 10 0\n"
            "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0\n"
            "   2: 0A00020F:C350 586433C6:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000000000000000 20 4 30 10 -1\n"
        )
        inode_map = {"22222": (850, "sshd"), "33333": (1200, "curl")}
        records = parse_proc_net_table(proc_tcp, "TCP", inode_map)
        self.assertEqual(len(records), 3)

        self.assertEqual(records[0].local_address, "127.0.0.1")
        self.assertEqual(records[0].local_port, 53)
        self.assertTrue(records[0].is_listening)
        self.assertFalse(records[0].is_wildcard_listener)
        self.assertIsNone(records[0].pid)

        self.assertEqual(records[1].local_address, "0.0.0.0")
        self.assertEqual(records[1].local_port, 22)
        self.assertTrue(records[1].is_wildcard_listener)
        self.assertEqual(records[1].pid, 850)
        self.assertEqual(records[1].process_name, "sshd")

        self.assertEqual(records[2].state, "ESTABLISHED")
        self.assertFalse(records[2].is_listening)
        self.assertEqual(records[2].remote_port, 443)

    def test_parse_windows_netstat_ano(self) -> None:
        netstat_out = (
            "\nActive Connections\n\n"
            "  Proto  Local Address          Foreign Address        State           PID\n"
            "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       912\n"
            "  TCP    192.168.1.10:52100     198.51.100.10:443      ESTABLISHED     4120\n"
            "  UDP    127.0.0.1:1900         *:*                                    1840\n"
        )
        recs = parse_windows_netstat_ano(netstat_out)
        self.assertEqual(len(recs), 3)
        self.assertTrue(recs[0].is_listening)
        self.assertEqual(recs[0].local_port, 135)
        self.assertEqual(recs[0].pid, 912)
        self.assertFalse(recs[1].is_listening)
        self.assertEqual(recs[1].state, "ESTABLISHED")
        self.assertTrue(recs[2].is_listening)
        self.assertEqual(recs[2].protocol, "UDP")

    def test_collect_network_and_processes_with_mock_psutil(self) -> None:
        mock_psutil = MagicMock()

        class FakeAccessDenied(Exception):
            pass

        class FakeNoSuchProcess(Exception):
            pass

        mock_psutil.AccessDenied = FakeAccessDenied
        mock_psutil.NoSuchProcess = FakeNoSuchProcess
        mock_psutil.ZombieProcess = FakeNoSuchProcess

        conn1 = SimpleNamespace(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="0.0.0.0", port=8080),
            raddr=None,
            status="LISTEN",
            pid=101,
        )
        mock_psutil.net_connections.return_value = [conn1]
        proc_obj = MagicMock()
        proc_obj.name.return_value = "python3"
        mock_psutil.Process.return_value = proc_obj

        p1 = MagicMock()
        p1.info = {
            "pid": 101,
            "name": "python3",
            "username": "analyst",
            "status": "running",
            "memory_info": SimpleNamespace(rss=20480 * 1024),
        }
        p1.exe.return_value = "/usr/bin/python3"

        p2 = MagicMock()
        p2.info = {
            "pid": 102,
            "name": "root_daemon",
            "username": "root",
            "status": "sleeping",
            "memory_info": SimpleNamespace(rss=4096 * 1024),
        }
        p2.exe.side_effect = FakeAccessDenied("denied")

        mock_psutil.process_iter.return_value = [p1, p2]

        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            net_recs, _ = collect_network_psutil()
            self.assertEqual(len(net_recs), 1)
            self.assertEqual(net_recs[0].local_port, 8080)
            self.assertEqual(net_recs[0].process_name, "python3")

            proc_recs, lims, restricted = collect_processes_psutil()
            self.assertEqual(len(proc_recs), 2)
            self.assertEqual(restricted, 1)
            self.assertEqual(proc_recs[1].exe_path, "<permission denied>")
            self.assertTrue(any("Command-line arguments" in lim for lim in lims))

    def test_linux_proc_process_collection_and_windows_tasklist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp)
            p_dir = proc_root / "4242"
            p_dir.mkdir()
            (p_dir / "comm").write_text("sentinel-worker\n", encoding="utf-8")
            (p_dir / "status").write_text(
                "Name:\tsentinel-worker\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nVmRSS:\t12345 kB\n",
                encoding="utf-8",
            )
            recs, lims, _ = collect_processes_linux_proc(proc_root)
            self.assertIsNotNone(recs)
            assert recs is not None
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].pid, 4242)
            self.assertEqual(recs[0].name, "sentinel-worker")
            self.assertEqual(recs[0].rss_kb, 12345)
            self.assertTrue(any("never read" in lim for lim in lims))

        tasklist_csv = (
            '"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"\n'
            '"powershell.exe","3100","Console","1","85,200 K","Running","WORKSTATION\\Alice","0:00:03","Windows PowerShell"\n'
        )
        win_procs = parse_windows_tasklist_csv(tasklist_csv)
        self.assertEqual(len(win_procs), 1)
        self.assertEqual(win_procs[0].pid, 3100)
        self.assertEqual(win_procs[0].name, "powershell.exe")
        self.assertEqual(win_procs[0].rss_kb, 85200)

    def test_render_network_and_processes_live_smoke(self) -> None:
        net_out, net_findings = render_network_command()
        self.assertIn("LOCAL NETWORK ENDPOINT", net_out)
        self.assertEqual(len(net_findings), 1)

        proc_out, proc_findings = render_processes_command()
        self.assertIn("PROCESS INSPECTION", proc_out)
        self.assertEqual(len(proc_findings), 1)


if __name__ == "__main__":
    unittest.main()
