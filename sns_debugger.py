#!/usr/bin/env python3
"""SNS Debugger - mini TUI da terminale per leggere i log del firewall via SSH.

Uso:
    python sns_debugger.py              # chiede IP e password
    python sns_debugger.py -u admin -p 22 10.0.0.254
    python sns_debugger.py --demo       # dati finti, per provare l'interfaccia
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import random
import re
import shlex
import socket
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from itertools import count
from pathlib import Path
from typing import Callable, Iterator

import paramiko
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    RichLog,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)
from textual.widgets.selection_list import Selection

LOG_DIR = "/log"
MAX_ENTRIES = 20000   # righe tenute in memoria
MAX_ROWS = 5000       # righe mostrate in tabella

LOG_DESCRIPTIONS = {
    "l_filter": "Regole di filtraggio",
    "l_alarm": "Allarmi IPS / protezioni",
    "l_connection": "Connessioni chiuse",
    "l_system": "Eventi di sistema",
    "l_server": "Amministrazione",
    "l_auth": "Autenticazione",
    "l_vpn": "VPN IPsec",
    "l_xvpn": "VPN SSL",
    "l_web": "Proxy HTTP / URL",
    "l_ssl": "Proxy SSL",
    "l_smtp": "Proxy SMTP",
    "l_pop3": "Proxy POP3",
    "l_ftp": "Proxy FTP",
    "l_plugin": "Plugin applicativi",
    "l_routing": "Routing",
    "l_sandboxing": "Sandboxing",
    "l_pvm": "Vulnerability mgr",
    "l_monitor": "Monitoraggio",
    "l_count": "Contatori",
}
DEFAULT_SELECTED = {"l_filter", "l_alarm"}

PRESET_COMMANDS = [
    "ls -lh /log",
    "uptime",
    "ifconfig",
    "netstat -rn",
    "top -b -o cpu 25",
    "df -h",
    "tail -n 100 /log/l_system",
    "grep -i -e error -e fail /log/l_system | tail -n 50",
    "sfctl -h",
    "tcpdump -n -c 50 -i <interfaccia> host <ip>",
]


# --------------------------------------------------------------------------- connessione


class SSHConnection:
    """Connessione SSH al firewall (utente admin, accesso SSH abilitato)."""

    def __init__(self, host: str, port: int, user: str, password: str):
        self.host, self.port, self.user = host, port, user
        sock = socket.create_connection((host, port), timeout=10)
        self.transport = paramiko.Transport(sock)
        self.transport.start_client(timeout=15)
        key = self.transport.get_remote_server_key()
        self.fingerprint = f"{key.get_name()} {key.fingerprint}"
        try:
            self.transport.auth_password(user, password)
        except paramiko.BadAuthenticationType as e:
            if "keyboard-interactive" not in e.allowed_types:
                raise
            self.transport.auth_interactive(user, lambda _t, _i, prompts: [password] * len(prompts))
        if not self.transport.is_authenticated():
            raise paramiko.AuthenticationException("autenticazione fallita")
        self.transport.set_keepalive(30)

    @property
    def label(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"

    @staticmethod
    def _wrap(cmd: str) -> str:
        # la shell di login dell'admin potrebbe non essere sh: forziamo /bin/sh
        return "/bin/sh -c " + shlex.quote(cmd)

    def run(self, cmd: str, timeout: float = 120) -> str:
        chan = self.transport.open_session()
        chan.settimeout(timeout)
        chan.exec_command(self._wrap(cmd + " 2>&1"))
        chunks = []
        while True:
            data = chan.recv(65536)
            if not data:
                break
            chunks.append(data)
        chan.close()
        return b"".join(chunks).decode("utf-8", "replace")

    def stream(self, cmd: str, stop: threading.Event) -> Iterator[str]:
        """Esegue un comando lungo (tail -F, tcpdump...) e restituisce le righe man mano."""
        chan = self.transport.open_session()
        chan.get_pty(width=500)  # alla chiusura il processo remoto riceve SIGHUP
        chan.settimeout(0.3)
        chan.exec_command(self._wrap(cmd))
        buf = b""
        try:
            while not stop.is_set():
                try:
                    data = chan.recv(65536)
                except socket.timeout:
                    if chan.exit_status_ready() and not chan.recv_ready():
                        break
                    yield ""  # heartbeat: permette al chiamante di svuotare il buffer
                    continue
                if not data:
                    break
                buf += data
                *lines, buf = buf.split(b"\n")
                for line in lines:
                    yield line.decode("utf-8", "replace").rstrip("\r")
            if buf and not stop.is_set():
                yield buf.decode("utf-8", "replace").rstrip("\r")
        finally:
            chan.close()

    def list_logs(self) -> list[str]:
        out = self.run(f"ls -1 {LOG_DIR}")
        return [n for n in out.split() if re.fullmatch(r"l_\w+", n)]

    def close(self) -> None:
        self.transport.close()


class DemoConnection:
    """Connessione finta che genera log plausibili, per provare l'interfaccia."""

    label = "demo@firewall"
    fingerprint = "demo"
    LOGS = ["l_filter", "l_alarm", "l_connection", "l_system", "l_web", "l_vpn"]

    def __init__(self):
        self.rnd = random.Random()

    def _line(self, log: str, ts: datetime | None = None) -> str:
        r = self.rnd
        ts = (ts or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        src = f"192.168.{r.choice([1, 10])}.{r.randint(2, 60)}"
        dst = r.choice(["8.8.8.8", "1.1.1.1", "10.0.0.5", "172.16.3.20", "93.184.216.34"])
        dport = r.choice([53, 80, 443, 443, 443, 22, 3389, 445])
        proto = {53: "dns", 80: "http", 443: "ssl", 22: "ssh", 3389: "rdp", 445: "smb"}[dport]
        head = (f'id=firewall time="{ts}" fw="SN310A00000000" tz=+0200 startime="{ts}" '
                f'pri={r.choice([1, 4, 5, 5, 5])} confid=01 slotlevel=2 ruleid={r.randint(1, 30)} '
                f'srcif="Ethernet1" srcifname="in" ipproto={"udp" if dport == 53 else "tcp"} '
                f'dstif="Ethernet0" dstifname="out" proto={proto} src={src} '
                f'srcport={r.randint(1024, 65000)} srcportname=ephemeral_fw srcmac=00:0c:29:aa:bb:cc '
                f'dst={dst} dstport={dport} dstportname={proto}')
        if log == "l_filter":
            return f'{head} action={r.choice(["pass", "pass", "block"])} logtype="filter"'
        if log == "l_alarm":
            msg = r.choice(["Port probe", "Possible SYN flooding", "Invalid TCP protocol",
                            "IP address spoofing (type=1)", "Bad DNS protocol"])
            return (f'{head} action={r.choice(["block", "pass"])} classification=0 '
                    f'alarmid={r.randint(1, 300)} msg="{msg}" class=protocol logtype="alarm"')
        if log == "l_connection":
            return (f'{head} sent={r.randint(100, 90000)} rcvd={r.randint(100, 900000)} '
                    f'duration={r.random() * 60:.2f} action=pass logtype="connection"')
        if log == "l_web":
            return (f'{head} user="jdoe" op=GET result=200 arg="/index.html" '
                    f'dstname=www.example.com action={r.choice(["pass", "block"])} logtype="web"')
        if log == "l_vpn":
            return (f'id=firewall time="{ts}" fw="SN310A00000000" tz=+0200 pri=5 '
                    f'src=203.0.113.7 dst=198.51.100.1 msg="Phase 2 established" '
                    f'phase=2 remoteid=site-b logtype="vpn"')
        return (f'id=firewall time="{ts}" fw="SN310A00000000" tz=+0200 pri=5 service=serverd '
                f'msg="{r.choice(["Configuration saved", "HA sync done", "Interface link up"])}" '
                f'logtype="system"')

    def list_logs(self) -> list[str]:
        return list(self.LOGS)

    def run(self, cmd: str, timeout: float = 120) -> str:
        m = re.search(r"tail -n (\d+) /log/(l_\w+)", cmd)
        if m:
            n, log = int(m.group(1)), m.group(2)
            now = time.time()
            return "\n".join(self._line(log, datetime.fromtimestamp(now - (n - i) * 7)) for i in range(n))
        return f"[demo] output simulato di: {cmd}\n"

    def stream(self, cmd: str, stop: threading.Event) -> Iterator[str]:
        logs = re.findall(r"/log/(l_\w+)", cmd)
        if not logs:
            for i in range(20):
                if stop.is_set():
                    return
                time.sleep(0.2)
                yield f"[demo] riga {i} di: {cmd}"
            return
        current = None
        while not stop.is_set():
            time.sleep(self.rnd.uniform(0.05, 0.4))
            log = self.rnd.choice(logs)
            if len(logs) > 1 and log != current:
                current = log
                yield f"==> /log/{log} <=="
            yield self._line(log)

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- parsing / filtri

KV_RE = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')
TAIL_HEADER_RE = re.compile(r"^==> .*/(l_\w+) <==$")


@dataclass
class Entry:
    id: int
    log: str
    raw: str
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def lower(self) -> str:
        return self.raw.lower()


_ids = count(1)


def parse_line(log: str, line: str) -> Entry:
    fields = {}
    for m in KV_RE.finditer(line):
        v = m.group(2)
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1]
        fields[m.group(1)] = v
    return Entry(next(_ids), log, line, fields)


class LogFilter:
    """Sintassi:  testo  -testo  campo=valore  campo!=valore  campo~regex
    Campi speciali: ip (src o dst), port (srcport o dstport), log (nome file).
    I valori IP accettano CIDR (src=10.0.0.0/24); i numeri sono confrontati esattamente."""

    ALIASES = {"ip": ("src", "dst"), "port": ("srcport", "dstport")}
    TERM_RE = re.compile(r"^([A-Za-z_][\w.-]*)(!=|=|~)(.*)$")

    def __init__(self, text: str):
        self.text = text.strip()
        self.preds: list[Callable[[Entry], bool]] = []
        self.grep_hint: str | None = None
        try:
            tokens = shlex.split(self.text)
        except ValueError:
            tokens = self.text.split()
        for tok in tokens:
            self.preds.append(self._compile(tok))

    def _compile(self, tok: str) -> Callable[[Entry], bool]:
        m = self.TERM_RE.match(tok)
        if not m:
            neg = tok[0] in "-!" and len(tok) > 1
            needle = (tok[1:] if neg else tok).lower()
            if not neg and self.grep_hint is None:
                self.grep_hint = needle
            return (lambda e: needle not in e.lower) if neg else (lambda e: needle in e.lower)

        key, op, value = m.group(1).lower(), m.group(2), m.group(3)
        keys = self.ALIASES.get(key, (key,))
        if op == "~":
            try:
                rx = re.compile(value, re.I)
            except re.error:
                rx = re.compile(re.escape(value), re.I)
            return lambda e: any(rx.search(self._get(e, k)) for k in keys)

        match = self._value_matcher(value)
        if op == "=" and self.grep_hint is None and "/" not in value and value:
            self.grep_hint = value.lower()
        if op == "=":
            return lambda e: any(match(self._get(e, k)) for k in keys)
        return lambda e: not any(match(self._get(e, k)) for k in keys)

    @staticmethod
    def _get(e: Entry, key: str) -> str:
        return e.log if key == "log" else e.fields.get(key, "")

    @staticmethod
    def _value_matcher(value: str) -> Callable[[str], bool]:
        try:
            net = ipaddress.ip_network(value, strict=False)

            def ip_match(v: str) -> bool:
                try:
                    return ipaddress.ip_address(v) in net
                except ValueError:
                    return False
            return ip_match
        except ValueError:
            pass
        if value.isdigit():
            return lambda v: v == value
        low = value.lower()
        return lambda v: low in v.lower()

    def __call__(self, e: Entry) -> bool:
        return all(p(e) for p in self.preds)


# --------------------------------------------------------------------------- rendering

COLUMNS = ("Ora", "Log", "Pri", "Azione", "Sorgente", "Destinazione", "Proto", "Regola", "Info")
ACTION_STYLE = {"block": "bold red", "drop": "bold red", "reset": "red",
                "pass": "green", "log": "yellow"}
INFO_KEYS = ("msg", "classification", "user", "dstname", "op", "arg", "result",
             "service", "error", "phase", "remoteid", "sent", "rcvd", "duration")


def endpoint(f: dict, ip: str, port: str) -> str:
    if ip not in f:
        return ""
    return f"{f[ip]}:{f[port]}" if f.get(port) else f[ip]


def row_for(e: Entry) -> tuple:
    f = e.fields
    ts = f.get("time", "")
    ora = ts.split(" ")[-1] if ts else ""
    pri = f.get("pri", "")
    pri_txt = Text(pri, style="bold red" if pri in {"0", "1", "2", "3"} else
                   "yellow" if pri == "4" else "")
    action = f.get("action", "")
    act_txt = Text(action, style=ACTION_STYLE.get(action.lower(), ""))
    info = " | ".join(f"{k}={f[k]}" if k not in ("msg",) else f[k]
                      for k in INFO_KEYS if f.get(k))
    if not f:
        info = e.raw
    return (ora, e.log.removeprefix("l_"), pri_txt, act_txt,
            endpoint(f, "src", "srcport"), endpoint(f, "dst", "dstport"),
            f.get("proto") or f.get("ipproto", ""), f.get("ruleid", ""),
            info[:160])


# --------------------------------------------------------------------------- schermate


class StatsScreen(ModalScreen):
    BINDINGS = [Binding("escape,q,s", "app.pop_screen", "Chiudi")]
    DEFAULT_CSS = """
    StatsScreen { align: center middle; }
    #stats-box { width: 90%; height: 85%; border: thick $accent; background: $surface; padding: 1 2; }
    """

    def __init__(self, entries: list[Entry]):
        super().__init__()
        self.entries = entries

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="stats-box"):
            yield Static(self._render_stats())

    def _render_stats(self) -> Table:
        outer = Table.grid(padding=(0, 3))
        n = len(self.entries)
        blocked = [e for e in self.entries if e.fields.get("action") in ("block", "drop")]
        outer.add_row(Text(f"Statistiche su {n} righe filtrate  -  "
                           f"block/drop: {len(blocked)}   (ESC per chiudere)", style="bold"))
        grid = Table.grid(padding=(1, 3))
        cells = []
        for title, key, src in (
            ("Top sorgenti", "src", self.entries),
            ("Top destinazioni", "dst", self.entries),
            ("Top porte dst", "dstport", self.entries),
            ("Top regole", "ruleid", self.entries),
            ("Sorgenti bloccate", "src", blocked),
            ("Messaggi", "msg", self.entries),
        ):
            c = Counter(e.fields[key] for e in src if e.fields.get(key))
            t = Table(title=title, title_style="bold cyan", show_header=False, box=None)
            t.add_column(justify="right", style="bold", min_width=5)
            t.add_column(min_width=18)
            for val, cnt in c.most_common(12):
                t.add_row(str(cnt), val[:50])
            cells.append(t)
        grid.add_row(*cells[:3])
        grid.add_row(*cells[3:])
        outer.add_row(grid)
        return outer


# --------------------------------------------------------------------------- app


class DebuggerApp(App):
    TITLE = "SNS Debugger"
    CSS = """
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; padding: 0; }
    #sidebar { width: 48; padding: 0 1; border-right: solid $primary; }
    #logs { height: 1fr; }
    #sidebar Button { width: 100%; margin-top: 1; }
    #sidebar Input { width: 100%; }
    #filter { margin: 0 0 0 0; }
    #table { height: 1fr; }
    #detail-wrap { height: 11; border-top: solid $primary; }
    #status { height: 1; background: $boost; padding: 0 1; }
    #cmdbar { height: auto; }
    #cmd { width: 1fr; }
    #presets { width: 50; height: 1fr; border-right: solid $primary; }
    #cmdout { height: 1fr; }
    .hint { color: $text-muted; }
    """
    BINDINGS = [
        Binding("t", "toggle_tail", "Tail on/off"),
        Binding("h", "history", "Storico"),
        Binding("p", "pause", "Pausa"),
        Binding("a", "autoscroll", "Autoscroll"),
        Binding("f,slash", "focus_filter", "Filtro"),
        Binding("c", "clear", "Pulisci"),
        Binding("s", "stats", "Statistiche"),
        Binding("e", "export", "Esporta"),
        Binding("escape", "focus_table", "Tabella", show=False),
        Binding("q", "quit", "Esci"),
    ]

    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        self.entries: deque[Entry] = deque(maxlen=MAX_ENTRIES)
        self.by_id: dict[str, Entry] = {}
        self.shown: deque[str] = deque()
        self.filter = LogFilter("")
        self.tail_stop: threading.Event | None = None
        self.cmd_stop: threading.Event | None = None
        self.paused = False
        self.pending = 0
        self.follow = True
        self.received = 0

    # ---------------------------------------------------------------- layout
    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Log", id="tab-log"):
                with Horizontal():
                    with Vertical(id="sidebar"):
                        yield Label("[b]File di log[/b] [dim](spazio)[/dim]")
                        yield SelectionList[str](id="logs")
                        yield Label("Righe storico (per file):")
                        yield Input("500", id="histn", type="integer")
                        yield Button("Avvia tail  [t]", id="btn-tail", variant="success")
                        yield Button("Carica storico  [h]", id="btn-hist", variant="primary")
                    with Vertical():
                        yield Input(placeholder="Filtro: testo  -escludi  src=10.0.0.0/24  "
                                                "ip=1.2.3.4  port=443  action=block  ruleid!=5  msg~regex",
                                    id="filter")
                        yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
                        with VerticalScroll(id="detail-wrap"):
                            yield Static("Seleziona una riga per vedere tutti i campi.",
                                         id="detail", classes="hint")
            with TabPane("Comandi", id="tab-cmd"):
                with Vertical():
                    with Horizontal(id="cmdbar"):
                        yield Input(placeholder="Comando da eseguire sul firewall (Invio)", id="cmd")
                        yield Button("Esegui", id="btn-run", variant="primary")
                        yield Button("Stop", id="btn-stop", variant="error")
                    with Horizontal():
                        yield OptionList(*PRESET_COMMANDS, id="presets")
                        yield RichLog(id="cmdout", wrap=False, max_lines=20000)
        yield Static(id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"{self.conn.label}"
        self.query_one("#table", DataTable).add_columns(*COLUMNS)
        self.query_one("#cmdout", RichLog).write(Text(
            "Seleziona un preset a sinistra (Invio) per copiarlo nella riga di comando, "
            "modificalo e premi Invio. 'Stop' interrompe i comandi lunghi (es. tcpdump).",
            style="dim"))
        self.load_log_list()
        self.update_status()

    @work(thread=True)
    def load_log_list(self) -> None:
        try:
            logs = self.conn.list_logs()
        except Exception as ex:  # noqa: BLE001
            self.call_from_thread(self.notify, f"Impossibile leggere {LOG_DIR}: {ex}", severity="error")
            logs = sorted(DEFAULT_SELECTED)
        order = list(LOG_DESCRIPTIONS)
        logs.sort(key=lambda n: (order.index(n) if n in order else len(order), n))
        self.call_from_thread(self._fill_log_list, logs)

    def _fill_log_list(self, logs: list[str]) -> None:
        sl = self.query_one("#logs", SelectionList)
        sl.clear_options()
        for n in logs:
            desc = LOG_DESCRIPTIONS.get(n, "")
            sl.add_option(Selection(f"{n.removeprefix('l_'):<11} [dim]{desc}[/dim]", n,
                                    n in DEFAULT_SELECTED))

    def selected_logs(self) -> list[str]:
        return list(self.query_one("#logs", SelectionList).selected)

    # ---------------------------------------------------------------- dati -> tabella
    def add_entries(self, new: list[Entry]) -> None:
        for e in new:
            self.entries.append(e)
        self.received += len(new)
        if self.paused:
            self.pending += len(new)
        else:
            self._append_rows([e for e in new if self.filter(e)])
        self.update_status()

    def _append_rows(self, items: list[Entry]) -> None:
        if not items:
            return
        table = self.query_one("#table", DataTable)
        for e in items:
            key = str(e.id)
            table.add_row(*row_for(e), key=key)
            self.by_id[key] = e
            self.shown.append(key)
        while len(self.shown) > MAX_ROWS:
            old = self.shown.popleft()
            self.by_id.pop(old, None)
            table.remove_row(old)
        if self.follow:
            table.scroll_end(animate=False)

    def rebuild(self) -> None:
        table = self.query_one("#table", DataTable)
        table.clear()
        self.by_id.clear()
        self.shown.clear()
        matching = [e for e in self.entries if self.filter(e)][-MAX_ROWS:]
        self._append_rows(matching)
        self.update_status()

    def update_status(self) -> None:
        tail = "[b green]TAIL ON[/]" if self.tail_stop else "[dim]tail off[/]"
        pause = f"  [b yellow]IN PAUSA (+{self.pending})[/]" if self.paused else ""
        follow = "" if self.follow else "  [yellow]autoscroll off[/]"
        flt = f"  filtro: [cyan]{self.filter.text}[/]" if self.filter.text else ""
        self.query_one("#status", Static).update(
            f"{self.conn.label}  |  {tail}{pause}{follow}  |  ricevute {self.received}  "
            f"in memoria {len(self.entries)}  mostrate {len(self.shown)}{flt}")

    # ---------------------------------------------------------------- tail
    def action_toggle_tail(self) -> None:
        if self.tail_stop:
            self.stop_tail()
            return
        logs = self.selected_logs()
        if not logs:
            self.notify("Seleziona almeno un file di log", severity="warning")
            return
        self.tail_stop = threading.Event()
        self.query_one("#btn-tail", Button).label = "Ferma tail  [t]"
        self.notify(f"Tail su: {', '.join(logs)}")
        self.tail_worker(logs, self.tail_stop)
        self.update_status()

    def stop_tail(self) -> None:
        if self.tail_stop:
            self.tail_stop.set()
        self.tail_stop = None
        self.query_one("#btn-tail", Button).label = "Avvia tail  [t]"
        self.update_status()

    @work(thread=True)
    def tail_worker(self, logs: list[str], stop: threading.Event) -> None:
        files = " ".join(f"{LOG_DIR}/{n}" for n in logs)
        current = logs[0]
        batch: list[Entry] = []
        last_flush = time.monotonic()
        try:
            for line in self.conn.stream(f"tail -n 0 -F {files}", stop):
                if line:
                    m = TAIL_HEADER_RE.match(line.strip())
                    if m:
                        current = m.group(1)
                    elif line.strip() and not line.startswith("tail:"):
                        batch.append(parse_line(current, line))
                    elif line.startswith("tail:"):
                        self.call_from_thread(self.notify, line, severity="warning")
                if batch and (time.monotonic() - last_flush > 0.25 or len(batch) > 500):
                    self.call_from_thread(self.add_entries, batch)
                    batch, last_flush = [], time.monotonic()
            if batch:
                self.call_from_thread(self.add_entries, batch)
        except Exception as ex:  # noqa: BLE001
            self.call_from_thread(self.notify, f"Errore tail: {ex}", severity="error")
        if not stop.is_set():
            self.call_from_thread(self.notify, "Tail terminato", severity="warning")
            self.call_from_thread(self.stop_tail)

    # ---------------------------------------------------------------- storico
    def action_history(self) -> None:
        logs = self.selected_logs()
        if not logs:
            self.notify("Seleziona almeno un file di log", severity="warning")
            return
        try:
            n = max(1, int(self.query_one("#histn", Input).value or 500))
        except ValueError:
            n = 500
        self.notify(f"Carico ultime {n} righe da {', '.join(logs)}"
                    + (f" (grep remoto: {self.filter.grep_hint!r})" if self.filter.grep_hint else ""))
        self.history_worker(logs, n, self.filter.grep_hint)

    @work(thread=True, exclusive=True, group="history")
    def history_worker(self, logs: list[str], n: int, grep: str | None) -> None:
        loaded: list[Entry] = []
        for log in logs:
            path = f"{LOG_DIR}/{log}"
            cmd = (f"grep -i -F -e {shlex.quote(grep)} {path} | tail -n {n}" if grep
                   else f"tail -n {n} {path}")
            try:
                out = self.conn.run(cmd)
            except Exception as ex:  # noqa: BLE001
                self.call_from_thread(self.notify, f"{log}: {ex}", severity="error")
                continue
            loaded += [parse_line(log, ln) for ln in out.splitlines() if ln.strip()]
        loaded.sort(key=lambda e: e.fields.get("time", ""))
        self.call_from_thread(self._set_history, loaded)

    def _set_history(self, loaded: list[Entry]) -> None:
        self.entries.clear()
        self.entries.extend(loaded)
        self.received += len(loaded)
        self.rebuild()
        self.notify(f"Caricate {len(loaded)} righe")

    # ---------------------------------------------------------------- azioni varie
    def action_pause(self) -> None:
        self.paused = not self.paused
        if not self.paused:
            self.pending = 0
            self.rebuild()
        self.update_status()

    def action_autoscroll(self) -> None:
        self.follow = not self.follow
        if self.follow:
            self.query_one("#table", DataTable).scroll_end(animate=False)
        self.update_status()

    def action_focus_filter(self) -> None:
        self.query_one(TabbedContent).active = "tab-log"
        self.query_one("#filter", Input).focus()

    def action_focus_table(self) -> None:
        self.query_one("#table", DataTable).focus()

    def action_clear(self) -> None:
        self.entries.clear()
        self.pending = 0
        self.rebuild()

    def action_stats(self) -> None:
        self.push_screen(StatsScreen([e for e in self.entries if self.filter(e)]))

    def action_export(self) -> None:
        items = [e for e in self.entries if self.filter(e)]
        if not items:
            self.notify("Niente da esportare", severity="warning")
            return
        path = Path(f"export_{datetime.now():%Y%m%d_%H%M%S}.log")
        path.write_text("".join(f"[{e.log}] {e.raw}\n" for e in items), encoding="utf-8")
        self.notify(f"Esportate {len(items)} righe in {path.resolve()}")

    # ---------------------------------------------------------------- eventi UI
    @on(Input.Changed, "#filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self.filter = LogFilter(event.value)
        self.rebuild()

    @on(Input.Submitted, "#filter")
    def filter_submitted(self) -> None:
        self.action_focus_table()

    @on(Button.Pressed, "#btn-tail")
    def _btn_tail(self) -> None:
        self.action_toggle_tail()

    @on(Button.Pressed, "#btn-hist")
    def _btn_hist(self) -> None:
        self.action_history()

    @on(DataTable.RowHighlighted, "#table")
    def show_detail(self, event: DataTable.RowHighlighted) -> None:
        e = self.by_id.get(event.row_key.value) if event.row_key else None
        detail = self.query_one("#detail", Static)
        if not e:
            return
        detail.remove_class("hint")
        t = Table.grid(padding=(0, 2))
        cols = 3
        for _ in range(cols):
            t.add_column(style="bold cyan", justify="right")
            t.add_column()
        items = [("log", e.log)] + list(e.fields.items())
        for i in range(0, len(items), cols):
            row = []
            for k, v in items[i:i + cols]:
                row += [k, Text(v, style=ACTION_STYLE.get(v, "") if k == "action" else "")]
            t.add_row(*row)
        if not e.fields:
            t.add_row("raw", e.raw)
        detail.update(t)

    # ---------------------------------------------------------------- tab comandi
    @on(OptionList.OptionSelected, "#presets")
    def preset_selected(self, event: OptionList.OptionSelected) -> None:
        inp = self.query_one("#cmd", Input)
        inp.value = PRESET_COMMANDS[event.option_index]
        inp.focus()

    @on(Input.Submitted, "#cmd")
    @on(Button.Pressed, "#btn-run")
    def run_command(self) -> None:
        cmd = self.query_one("#cmd", Input).value.strip()
        if not cmd:
            return
        if self.cmd_stop:
            self.cmd_stop.set()
        self.cmd_stop = threading.Event()
        out = self.query_one("#cmdout", RichLog)
        out.write(Text(f"\n$ {cmd}", style="bold green"))
        self.cmd_worker(cmd, self.cmd_stop)

    @on(Button.Pressed, "#btn-stop")
    def stop_command(self) -> None:
        if self.cmd_stop:
            self.cmd_stop.set()
            self.cmd_stop = None
            self.query_one("#cmdout", RichLog).write(Text("[interrotto]", style="yellow"))

    @work(thread=True)
    def cmd_worker(self, cmd: str, stop: threading.Event) -> None:
        batch: list[str] = []
        last = time.monotonic()

        def flush():
            nonlocal batch, last
            if batch:
                self.call_from_thread(self._cmd_write, Text("\n".join(batch)))
            batch, last = [], time.monotonic()

        try:
            for line in self.conn.stream(cmd + " 2>&1", stop):
                if line:
                    batch.append(line)
                if batch and time.monotonic() - last > 0.2:
                    flush()
            flush()
        except Exception as ex:  # noqa: BLE001
            flush()
            self.call_from_thread(self._cmd_write, Text(f"Errore: {ex}", style="bold red"))

    def _cmd_write(self, text: Text) -> None:
        self.query_one("#cmdout", RichLog).write(text)

    def on_unmount(self) -> None:
        for ev in (self.tail_stop, self.cmd_stop):
            if ev:
                ev.set()


# --------------------------------------------------------------------------- avvio


def connect_interactive(args) -> SSHConnection:
    host = args.host
    for attempt in range(3):
        while not host:
            host = input("IP del firewall: ").strip()
        password = getpass.getpass(f"Password per {args.user}@{host}: ")
        print(f"Connessione a {host}:{args.port} ...", flush=True)
        try:
            conn = SSHConnection(host, args.port, args.user, password)
            print(f"Connesso. Chiave host: {conn.fingerprint}")
            return conn
        except paramiko.AuthenticationException:
            print("Autenticazione fallita, riprova.")
        except (OSError, paramiko.SSHException) as ex:
            print(f"Connessione fallita: {ex}")
            print("Verifica che l'accesso SSH sia abilitato sul firewall "
                  "(Configurazione > Sistema > Configurazione > Amministrazione firewall).")
            host = None
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description="SNS Debugger - lettura log firewall via SSH")
    ap.add_argument("host", nargs="?", help="IP del firewall (se omesso viene chiesto)")
    ap.add_argument("-u", "--user", default="admin", help="utente SSH (default: admin)")
    ap.add_argument("-p", "--port", type=int, default=22, help="porta SSH (default: 22)")
    ap.add_argument("--demo", action="store_true", help="usa dati finti, senza firewall")
    args = ap.parse_args()

    try:
        conn = DemoConnection() if args.demo else connect_interactive(args)
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(130)
    try:
        DebuggerApp(conn).run()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
