"""connectfolder — основная логика без GTK.

Здесь всё, что не зависит от интерфейса:

* модель сетевого каталога (Share) и сборка/разбор строки карты autofs;
* чтение и запись карты с сохранением чужих строк и комментариев;
* формат файла учётных данных mount.cifs;
* состояние системы (autofs, cifs-utils, домен, старая конфигурация);
* операции записи (сохранить, удалить, перенести старую конфигурацию),
  которые вызывает привилегированный помощник;
* клиент помощника для интерфейса.

Все пути считаются относительно Paths.root, поэтому тесты и демо-режим
работают в отдельном каталоге и систему не трогают.
"""

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional, Tuple

VERSION = "2.0.0"

# --------------------------------------------------------------------------
# Пути
# --------------------------------------------------------------------------

MOUNT_ROOT = "/media/share"
MAP_FILE = "/etc/auto.connectfolder"
MASTER_FILE = "/etc/auto.master"
MASTER_D_DIR = "/etc/auto.master.d"
MASTER_D_FILE = "/etc/auto.master.d/connectfolder.autofs"
CRED_DIR = "/etc/connectfolder/credentials"
OLD_MAP_FILE = "/etc/auto.samba"
OLD_CRED_DIR = "/root/.auth_smb"

MASTER_OPTIONS = "--ghost --timeout=300"
MASTER_INCLUDE = "+dir:" + MASTER_D_DIR
BACKUP_SUFFIX = ".connectfolder.bak"
MIGRATED_SUFFIX = ".connectfolder-migrated"


class Paths:
    """Набор путей с общим корнем (``/`` в системе, временный каталог в тестах)."""

    def __init__(self, root: str = "/"):
        self.root = os.path.abspath(root)

    def __call__(self, path: str) -> str:
        """Перевести системный путь в путь внутри корня."""
        if self.root == "/":
            return path
        return os.path.join(self.root, path.lstrip("/"))

    @property
    def is_real(self) -> bool:
        return self.root == "/"

    @property
    def map_file(self) -> str:
        return self(MAP_FILE)

    @property
    def master_file(self) -> str:
        return self(MASTER_FILE)

    @property
    def master_d_dir(self) -> str:
        return self(MASTER_D_DIR)

    @property
    def master_d_file(self) -> str:
        return self(MASTER_D_FILE)

    @property
    def cred_dir(self) -> str:
        return self(CRED_DIR)

    @property
    def old_map_file(self) -> str:
        return self(OLD_MAP_FILE)

    @property
    def old_cred_dir(self) -> str:
        return self(OLD_CRED_DIR)

    @property
    def mount_root(self) -> str:
        return self(MOUNT_ROOT)

    def cred_file(self, key: str) -> str:
        """Путь к файлу учётных данных внутри корня."""
        return os.path.join(self.cred_dir, key)

    def mount_point(self, key: str) -> str:
        return os.path.join(self.mount_root, key)


def system_cred_file(key: str) -> str:
    """Путь к файлу учётных данных так, как он записывается в карту autofs."""
    return CRED_DIR + "/" + key


# --------------------------------------------------------------------------
# Модель
# --------------------------------------------------------------------------

AUTH_PASSWORD = "password"
AUTH_KERBEROS = "kerberos"

ACCESS_OWNER = "owner"      # uid=$UID,gid=$GID — владелец тот, кто открыл каталог
ACCESS_SHARED = "shared"    # noperm — доступ у всех локальных пользователей
ACCESS_NONE = "none"        # без настройки: владелец root (как задано вручную)

# (значение, подпись). Пустая строка — согласование версии клиентом.
SMB_VERSIONS = [
    ("", "Автоматически"),
    ("3.1.1", "SMB 3.1.1"),
    ("3.0", "SMB 3.0"),
    ("2.1", "SMB 2.1"),
    ("2.0", "SMB 2.0"),
    ("1.0", "SMB 1.0 (небезопасно)"),
]
SMB_VERSION_VALUES = [v for v, _ in SMB_VERSIONS]

# Права по умолчанию в режиме «владелец»: файлы видит только он.
OWNER_MODES = ["file_mode=0600", "dir_mode=0700"]

ACCESS_MODES = [
    (ACCESS_OWNER, "Только пользователь, открывший каталог"),
    (ACCESS_SHARED, "Все локальные пользователи (noperm)"),
    (ACCESS_NONE, "Без настройки (владелец root)"),
]

# Опции, которыми управляет программа. Остальные сохраняются как есть.
_MANAGED_FLAGS = {"rw", "ro", "noperm", "multiuser"}
_MANAGED_KEYS = {"fstype", "vers", "credentials", "cruid", "sec"}

KEY_RE = re.compile(r"^\w[\w.-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*\.?$")
# Символы, которые нельзя пропускать в имени шары: ломают карту autofs или UNC.
_BAD_SHARE_CHARS = set('"\\#*?<>|:\n\r\t\x00')
# Символы, которые autofs раскрывает сам ($VAR, & — ключ). Их экранируем.
_AUTOFS_ESCAPE = {"$", "&"}


class ValidationError(ValueError):
    """Ошибка во входных данных. Текст показывается пользователю."""


@dataclass
class Share:
    key: str                        # имя каталога в /media/share
    server: str                     # имя или IP сервера
    share_path: str                 # share или share/подкаталог
    auth: str = AUTH_PASSWORD
    smb_version: str = ""
    access: str = ACCESS_OWNER
    read_only: bool = False
    extra: List[str] = field(default_factory=list)   # прочие опции mount.cifs
    credentials_path: str = ""      # как записано в карте (для миграции)

    @property
    def unc(self) -> str:
        return "//{}/{}".format(self.server, self.share_path)

    @property
    def mount_point(self) -> str:
        return MOUNT_ROOT + "/" + self.key

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "server": self.server,
            "share_path": self.share_path,
            "auth": self.auth,
            "smb_version": self.smb_version,
            "access": self.access,
            "read_only": self.read_only,
            "extra": list(self.extra),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Share":
        if not isinstance(d, dict):
            raise ValidationError("Неверные данные каталога")
        try:
            return cls(
                key=str(d["key"]),
                server=str(d["server"]),
                share_path=str(d["share_path"]),
                auth=str(d.get("auth", AUTH_PASSWORD)),
                smb_version=str(d.get("smb_version", "")),
                access=str(d.get("access", ACCESS_OWNER)),
                read_only=bool(d.get("read_only", False)),
                extra=[str(x) for x in d.get("extra", [])],
            )
        except KeyError as e:
            raise ValidationError("Не хватает поля {}".format(e))


def parse_network_path(text: str) -> Tuple[str, str]:
    """Разобрать сетевой путь в (сервер, путь_шары).

    Принимает ``server/share``, ``//server/share/dir``, ``\\\\server\\share``
    и ``smb://server/share``.
    """
    s = (text or "").strip()
    if s.lower().startswith("smb:"):
        s = s[4:]
    s = s.replace("\\", "/")
    parts = [p for p in s.split("/") if p]
    if len(parts) < 2:
        raise ValidationError(
            "Укажите сетевой путь в виде сервер/шара, например fileserver/docs")
    server, share_parts = parts[0], parts[1:]
    validate_server(server)
    share_path = "/".join(share_parts)
    validate_share_path(share_path)
    return server, share_path


def validate_key(key: str) -> None:
    if not key:
        raise ValidationError("Укажите имя каталога")
    if not KEY_RE.match(key):
        raise ValidationError(
            "Имя каталога: буквы, цифры, «_», «.» и «-», до 64 символов, "
            "первый символ — буква или цифра")


def validate_server(server: str) -> None:
    if not server or not HOST_RE.match(server) or len(server) > 253:
        raise ValidationError("Неверное имя сервера: «{}»".format(server))


def validate_share_path(path: str) -> None:
    if not path:
        raise ValidationError("Не указано имя шары")
    bad = sorted(set(path) & _BAD_SHARE_CHARS)
    if bad:
        shown = " ".join(repr(c)[1:-1] for c in bad)
        raise ValidationError("Недопустимые символы в пути шары: {}".format(shown))
    if any(p in (".", "..") for p in path.split("/")):
        raise ValidationError("Путь шары не может содержать «.» или «..»")
    if any(ord(c) < 32 for c in path):
        raise ValidationError("Путь шары содержит управляющие символы")


def validate_extra_option(opt: str) -> None:
    if not opt or any(c in opt for c in ",\n\r\t \"\\#") or opt.startswith("-"):
        raise ValidationError("Недопустимая опция монтирования: «{}»".format(opt))
    name = opt.split("=", 1)[0]
    if name in _MANAGED_FLAGS or name in _MANAGED_KEYS or name in (
            "domain", "username", "user", "password", "pass"):
        raise ValidationError(
            "Опцию «{}» программа задаёт сама, уберите её из дополнительных"
            .format(name))


def validate_share(share: Share) -> None:
    validate_key(share.key)
    validate_server(share.server)
    validate_share_path(share.share_path)
    if share.auth not in (AUTH_PASSWORD, AUTH_KERBEROS):
        raise ValidationError("Неизвестный способ входа: {}".format(share.auth))
    if share.smb_version and not re.match(r"^\d+(\.\d+){0,2}$", share.smb_version):
        raise ValidationError("Неверная версия SMB: {}".format(share.smb_version))
    if share.access not in (ACCESS_OWNER, ACCESS_SHARED, ACCESS_NONE):
        raise ValidationError("Неизвестный режим доступа: {}".format(share.access))
    for opt in share.extra:
        validate_extra_option(opt)
        if opt.split("=", 1)[0] in ("uid", "gid") and (
                share.auth == AUTH_KERBEROS or share.access != ACCESS_NONE):
            raise ValidationError(
                "uid/gid в дополнительных опциях допустимы только в режиме "
                "доступа «Без настройки»")


def suggest_key(share_path: str) -> str:
    """Предложить имя каталога по последней части пути шары."""
    last = share_path.rstrip("/").split("/")[-1] if share_path else ""
    key = re.sub(r"[^\w.-]+", "_", last).strip("._-")
    return key[:64]


# --------------------------------------------------------------------------
# Строка карты autofs
# --------------------------------------------------------------------------

def build_options(share: Share) -> List[str]:
    opts = ["fstype=cifs", "ro" if share.read_only else "rw"]
    if share.smb_version:
        opts.append("vers=" + share.smb_version)
    if share.auth == AUTH_KERBEROS:
        # multiuser: каждый пользователь ходит на сервер со своим билетом.
        opts += ["multiuser", "cruid=$UID", "sec=krb5"]
    else:
        opts.append("credentials=" + system_cred_file(share.key))
        if share.access == ACCESS_OWNER:
            opts += ["uid=$UID", "gid=$GID"]
            # Другие локальные пользователи не должны читать чужую шару.
            set_by_user = {o.split("=", 1)[0] for o in share.extra}
            opts += [o for o in OWNER_MODES if o.split("=", 1)[0] not in set_by_user]
        elif share.access == ACCESS_SHARED:
            opts.append("noperm")
    opts += share.extra
    return opts


def _escape_location(loc: str) -> str:
    out = []
    for c in loc:
        if c in _AUTOFS_ESCAPE:
            out.append("\\" + c)
        else:
            out.append(c)
    s = "".join(out)
    if " " in s:
        s = '"' + s + '"'
    return s


def build_location(share: Share) -> str:
    return _escape_location("://{}/{}".format(share.server, share.share_path))


def build_map_line(share: Share) -> str:
    return "{}\t-{}\t{}".format(share.key, ",".join(build_options(share)),
                               build_location(share))


def _split_map_tokens(line: str) -> List[str]:
    """Разбить строку карты на поля с учётом кавычек и экранирования."""
    tokens: List[str] = []
    cur: List[str] = []
    in_token = False
    quoted = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            in_token = True
            i += 2
            continue
        if c == '"':
            quoted = not quoted
            in_token = True
        elif c in " \t" and not quoted:
            if in_token:
                tokens.append("".join(cur))
                cur, in_token = [], False
        else:
            cur.append(c)
            in_token = True
        i += 1
    if in_token:
        tokens.append("".join(cur))
    return tokens


def parse_map_line(line: str) -> Optional[Share]:
    """Разобрать строку карты. None — строка не похожа на CIFS-каталог."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    tokens = _split_map_tokens(stripped)
    if len(tokens) != 3 or not tokens[1].startswith("-"):
        return None
    key, opt_str, loc = tokens
    if not KEY_RE.match(key) or not loc.startswith("://"):
        return None
    opts = [o for o in opt_str[1:].split(",") if o]
    kv: Dict[str, str] = {}
    flags = set()
    extra: List[str] = []
    for o in opts:
        if "=" in o:
            k, v = o.split("=", 1)
            kv.setdefault(k, v)
        else:
            flags.add(o)
    if kv.get("fstype") != "cifs":
        return None
    try:
        server, share_path = parse_network_path(loc[3:])
    except ValidationError:
        return None

    if kv.get("sec") == "krb5":
        auth = AUTH_KERBEROS
    elif "credentials" in kv:
        auth = AUTH_PASSWORD
    else:
        return None     # гостевые и прочие варианты не трогаем

    access = ACCESS_NONE
    uid, gid = kv.get("uid"), kv.get("gid")
    if auth == AUTH_PASSWORD:
        if "noperm" in flags:
            access = ACCESS_SHARED
        elif uid == "$UID":
            access = ACCESS_OWNER

    for o in opts:
        name = o.split("=", 1)[0]
        if name in _MANAGED_FLAGS or name in _MANAGED_KEYS:
            continue
        if auth == AUTH_KERBEROS and name == "domain":
            continue    # старые версии дописывали domain= к sec=krb5, он не нужен
        if auth == AUTH_PASSWORD and access == ACCESS_OWNER and (
                (name == "uid" and uid == "$UID") or (name == "gid" and gid == "$GID")
                or o in OWNER_MODES):
            continue
        extra.append(o)

    vers = kv.get("vers", "")

    return Share(
        key=key, server=server, share_path=share_path, auth=auth,
        smb_version=vers, access=access, read_only="ro" in flags,
        extra=extra, credentials_path=kv.get("credentials", ""),
    )


@dataclass
class MapEntry:
    raw: str                        # строка(и) как в файле, без последнего \n
    share: Optional[Share] = None
    dirty: bool = False

    def render(self) -> str:
        if self.share is not None and self.dirty:
            return build_map_line(self.share)
        return self.raw


class MapFile:
    """Карта autofs: CIFS-строки разбираются, всё остальное хранится как есть."""

    def __init__(self, entries: Optional[List[MapEntry]] = None):
        self.entries: List[MapEntry] = entries or []

    @classmethod
    def parse(cls, text: str) -> "MapFile":
        entries: List[MapEntry] = []
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.rstrip().endswith("\\"):
                # Многострочная запись: храним как есть, не разбираем.
                block = [line]
                while block[-1].rstrip().endswith("\\") and i + 1 < len(lines):
                    i += 1
                    block.append(lines[i])
                entries.append(MapEntry("\n".join(block)))
            else:
                entries.append(MapEntry(line, parse_map_line(line)))
            i += 1
        return cls(entries)

    @classmethod
    def load(cls, path: str) -> "MapFile":
        try:
            with open(path, encoding="utf-8", errors="surrogateescape") as f:
                return cls.parse(f.read())
        except FileNotFoundError:
            return cls()

    def render(self) -> str:
        if not self.entries:
            return ""
        return "\n".join(e.render() for e in self.entries) + "\n"

    @property
    def shares(self) -> List[Share]:
        return [e.share for e in self.entries if e.share is not None]

    def find(self, key: str) -> Optional[MapEntry]:
        for e in self.entries:
            if e.share is not None and e.share.key == key:
                return e
        return None

    def has_key(self, key: str) -> bool:
        """Есть ли ключ в карте, включая строки, которые программа не разбирает."""
        if self.find(key):
            return True
        for e in self.entries:
            s = e.raw.strip()
            if s and not s.startswith("#"):
                toks = _split_map_tokens(s.split("\n")[0])
                if toks and toks[0] == key:
                    return True
        return False

    def add(self, share: Share) -> None:
        self.entries.append(MapEntry("", share, dirty=True))

    def replace(self, key: str, share: Share) -> None:
        e = self.find(key)
        if e is None:
            raise KeyError(key)
        e.share, e.dirty = share, True

    def remove(self, key: str) -> None:
        e = self.find(key)
        if e is None:
            raise KeyError(key)
        self.entries.remove(e)


# --------------------------------------------------------------------------
# Учётные данные mount.cifs
# --------------------------------------------------------------------------

def format_credentials(username: str, password: str, domain: str = "") -> str:
    for name, val in (("Имя пользователя", username), ("Пароль", password),
                      ("Домен", domain)):
        if any(c in val for c in "\n\r\x00"):
            raise ValidationError("{} содержит перевод строки".format(name))
    if not username:
        raise ValidationError("Укажите имя пользователя")
    text = "username={}\npassword={}\n".format(username, password)
    if domain:
        text += "domain={}\n".format(domain)
    return text


def parse_credentials(text: str) -> Dict[str, str]:
    """Разобрать файл учётных данных — новый формат и старый (с секцией [smb])."""
    out = {"username": "", "password": "", "domain": ""}
    aliases = {"username": "username", "user": "username",
               "password": "password", "pass": "password",
               "domain": "domain", "dom": "domain", "workgroup": "domain"}
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;[" or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = aliases.get(k.strip().lower())
        if k:
            out[k] = v.strip()
    return out


# --------------------------------------------------------------------------
# auto.master
# --------------------------------------------------------------------------

def _master_entries(text: str) -> List[Tuple[int, List[str]]]:
    out = []
    for n, line in enumerate(text.splitlines()):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append((n, s.split()))
    return out


def master_has_include(text: str) -> bool:
    for _, toks in _master_entries(text):
        if toks[0].rstrip("/") == MASTER_INCLUDE.rstrip("/"):
            return True
    return False


def master_old_lines(text: str) -> List[int]:
    """Номера строк auto.master, подключающих старую карту /etc/auto.samba."""
    return [n for n, toks in _master_entries(text)
            if len(toks) >= 2 and toks[1] == OLD_MAP_FILE]


def master_conflicts(text: str, ignore_old: bool = True) -> List[str]:
    """Чужие строки, которые тоже монтируют что-то в /media/share."""
    out = []
    for _, toks in _master_entries(text):
        if toks[0].rstrip("/") != MOUNT_ROOT:
            continue
        if len(toks) >= 2 and toks[1] == MAP_FILE:
            continue
        if ignore_old and len(toks) >= 2 and toks[1] == OLD_MAP_FILE:
            continue
        out.append(" ".join(toks))
    return out


def master_d_content() -> str:
    return ("# Создано connectfolder. Изменения вносите через программу.\n"
            "{}\t{}\t{}\n".format(MOUNT_ROOT, MAP_FILE, MASTER_OPTIONS))


# --------------------------------------------------------------------------
# Состояние системы (читается без прав root)
# --------------------------------------------------------------------------

def _read(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            return f.read()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def _run(cmd: List[str], timeout: float = 10) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return 127, "{}: команда не найдена".format(cmd[0])
    except subprocess.TimeoutExpired:
        return 124, "{}: превышено время ожидания".format(cmd[0])


@dataclass
class SystemState:
    shares: List[Share]
    map_exists: bool
    autofs_installed: bool
    cifs_installed: bool
    service_active: bool
    master_configured: bool
    old_config: bool               # есть /etc/auto.samba или строка в auto.master
    old_shares: int
    conflicts: List[str]
    realm: str                     # домен, если ПК в домене (realm list)
    demo: bool = False


def _find_binary(paths: Paths, names: List[str]) -> bool:
    for n in names:
        if os.path.exists(paths(n)):
            return True
    return False


def realm_domain(demo_value: Optional[str] = None) -> str:
    if demo_value is not None:
        return demo_value
    rc, out = _run(["realm", "list", "--name-only"], timeout=5)
    if rc != 0:
        return ""
    for line in out.splitlines():
        if line.strip():
            return line.strip()
    return ""


def read_state(paths: Paths, demo: bool = False) -> SystemState:
    mf = MapFile.load(paths.map_file)
    master = _read(paths.master_file) or ""
    master_d = _read(paths.master_d_file) or ""
    old_map_text = _read(paths.old_map_file)
    old_shares = len(MapFile.parse(old_map_text).shares) if old_map_text else 0
    old_master = bool(master_old_lines(master))

    if demo:
        service = True
        realm = os.environ.get("CONNECTFOLDER_DEMO_REALM", "")
    else:
        rc, _ = _run(["systemctl", "is-active", "--quiet", "autofs"], timeout=5)
        service = rc == 0
        realm = realm_domain()

    master_configured = (MAP_FILE in master_d and master_has_include(master))
    return SystemState(
        shares=mf.shares,
        map_exists=os.path.exists(paths.map_file),
        autofs_installed=_find_binary(paths, ["/usr/sbin/automount", "/sbin/automount"]),
        cifs_installed=_find_binary(paths, ["/usr/sbin/mount.cifs", "/sbin/mount.cifs"]),
        service_active=service,
        master_configured=master_configured,
        old_config=bool(old_map_text and old_map_text.strip()) or old_master,
        old_shares=old_shares,
        conflicts=master_conflicts(master),
        realm=realm,
        demo=demo,
    )


# --------------------------------------------------------------------------
# Проверка доступности (выполняется от пользователя, не от root)
# --------------------------------------------------------------------------

def tcp_check(host: str, port: int = 445, timeout: float = 3.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "порт {} открыт".format(port)
    except socket.gaierror:
        return False, "имя «{}» не найдено в DNS".format(host)
    except socket.timeout:
        return False, "нет ответа на порту {}".format(port)
    except OSError as e:
        return False, e.strerror or str(e)


def has_kerberos_ticket() -> bool:
    rc, _ = _run(["klist", "-s"], timeout=5)
    return rc == 0


def _unescape_mountinfo(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def is_mounted(path: str, mountinfo: Optional[str] = None) -> bool:
    """Смонтирован ли каталог (сам autofs-триггер не считается)."""
    text = _read("/proc/self/mountinfo") if mountinfo is None else mountinfo
    target = path.rstrip("/")
    for line in (text or "").splitlines():
        left, sep, right = line.partition(" - ")
        parts = left.split()
        if not sep or len(parts) < 5:
            continue
        fstype = right.split()[0] if right.split() else ""
        if _unescape_mountinfo(parts[4]) == target and fstype != "autofs":
            return True
    return False


STATUS_CHECKING = "checking"
STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_UNKNOWN = "unknown"


def check_share(share: Share, paths: Paths, demo: bool = False,
                list_timeout: float = 10.0) -> Tuple[str, str]:
    """Проверить каталог от имени текущего пользователя.

    Возвращает (статус, пояснение). Обращение к каталогу заставляет autofs
    смонтировать его — так проверяется вся цепочка, включая пароль и билет.
    """
    if demo:
        return STATUS_UNKNOWN, "демо-режим: сеть не проверяется"
    ok, msg = tcp_check(share.server)
    if not ok:
        return STATUS_FAIL, "Сервер недоступен: " + msg
    if share.auth == AUTH_KERBEROS and not has_kerberos_ticket():
        return STATUS_WARN, "Нет билета Kerberos (выполните kinit или войдите заново)"

    mp = paths.mount_point(share.key)
    result: Dict[str, object] = {}

    def probe():
        try:
            result["n"] = len(os.listdir(mp))
        except Exception as e:          # noqa: BLE001 — показываем любую причину
            result["err"] = e

    t = threading.Thread(target=probe, daemon=True)
    t.start()
    t.join(list_timeout)
    if t.is_alive():
        return STATUS_WARN, "Сервер отвечает, но каталог не открылся за {} с".format(
            int(list_timeout))
    err = result.get("err")
    if err is None:
        return STATUS_OK, "Доступен, объектов: {}".format(result["n"])
    if isinstance(err, FileNotFoundError):
        return STATUS_FAIL, "Нет точки монтирования — autofs не подхватил карту"
    if isinstance(err, PermissionError):
        return STATUS_FAIL, "Нет доступа: проверьте имя пользователя и пароль"
    if isinstance(err, OSError):
        return STATUS_FAIL, "Не смонтирован: {}".format(err.strerror or err)
    return STATUS_FAIL, str(err)


# --------------------------------------------------------------------------
# Операции записи (вызываются помощником от root)
# --------------------------------------------------------------------------

class OperationError(Exception):
    """Ошибка операции. Текст показывается пользователю."""


@dataclass
class CommandLog:
    cmd: str
    rc: int
    out: str = ""

    def to_dict(self) -> dict:
        return {"cmd": self.cmd, "rc": self.rc, "out": self.out}


class System:
    """Запись файлов и запуск системных команд с журналом и откатом.

    Каждая операция идёт как транзакция: перед изменением файла его прежнее
    содержимое запоминается, при ошибке всё возвращается обратно.
    """

    def __init__(self, paths: Paths, run_commands: bool = True):
        self.paths = paths
        self.run_commands = run_commands
        self.log: List[CommandLog] = []
        self._undo: List[Callable[[], None]] = []

    # ---- транзакция ----

    def begin(self) -> None:
        self._undo = []
        self.log = []

    def rollback(self) -> None:
        while self._undo:
            fn = self._undo.pop()
            try:
                fn()
            except OSError:
                pass

    def commit(self) -> None:
        self._undo = []

    def _remember(self, path: str) -> None:
        if os.path.lexists(path):
            with open(path, "rb") as f:
                data = f.read()
            st = os.stat(path)

            def restore(path=path, data=data, mode=stat.S_IMODE(st.st_mode)):
                self._write_raw(path, data, mode)
        else:
            def restore(path=path):
                if os.path.lexists(path):
                    os.unlink(path)
        self._undo.append(restore)

    # ---- файлы ----

    @staticmethod
    def _write_raw(path: str, data: bytes, mode: int) -> None:
        d = os.path.dirname(path)
        tmp = os.path.join(d, ".{}.tmp{}".format(os.path.basename(path), os.getpid()))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd, mode)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    def makedirs(self, path: str, mode: int, enforce: bool = False) -> None:
        """Создать недостающие каталоги. enforce — выставить права и существующему."""
        missing = []
        p = path
        while not os.path.isdir(p):
            missing.append(p)
            p = os.path.dirname(p)
        for d in reversed(missing):
            os.mkdir(d, mode)
            os.chmod(d, mode)
            self._undo.append(lambda d=d: os.rmdir(d))
        if enforce:
            os.chmod(path, mode)

    def write(self, path: str, text: str, mode: int = 0o644,
              backup: bool = False) -> None:
        self.makedirs(os.path.dirname(path), 0o755 if mode & 0o044 else 0o700)
        if backup and os.path.isfile(path):
            bak = path + BACKUP_SUFFIX
            self._remember(bak)
            shutil.copy2(path, bak)
            self.log.append(CommandLog("cp {} {}".format(self._sys(path), self._sys(bak)), 0))
        self._remember(path)
        self._write_raw(path, text.encode("utf-8", errors="surrogateescape"), mode)
        self._restorecon(path)

    def remove(self, path: str) -> None:
        if os.path.lexists(path):
            self._remember(path)
            os.unlink(path)
            self.log.append(CommandLog("rm {}".format(self._sys(path)), 0))

    def rename(self, src: str, dst: str) -> None:
        os.rename(src, dst)
        self._undo.append(lambda: os.rename(dst, src))
        self.log.append(CommandLog("mv {} {}".format(self._sys(src), self._sys(dst)), 0))

    def _sys(self, path: str) -> str:
        """Путь для журнала — системный, без корня демо."""
        root = self.paths.root
        if root != "/" and path.startswith(root):
            return "/" + os.path.relpath(path, root)
        return path

    # ---- команды ----

    def run(self, cmd: List[str], check: bool = True) -> CommandLog:
        if not self.run_commands:
            entry = CommandLog(" ".join(cmd), 0, "[демо] команда не выполнялась")
            self.log.append(entry)
            return entry
        rc, out = _run(cmd, timeout=60)
        entry = CommandLog(" ".join(cmd), rc, out.strip())
        self.log.append(entry)
        if check and rc != 0:
            raise OperationError("Команда «{}» завершилась с кодом {}:\n{}".format(
                entry.cmd, rc, entry.out))
        return entry

    def _restorecon(self, path: str) -> None:
        if self.run_commands and shutil.which("restorecon") and os.path.isdir("/sys/fs/selinux"):
            _run(["restorecon", "-F", path], timeout=20)


def _ensure_autofs_installed(paths: Paths) -> None:
    if not _find_binary(paths, ["/usr/sbin/automount", "/sbin/automount"]):
        raise OperationError(
            "Не установлен autofs. Выполните: sudo dnf install autofs cifs-utils")


def ensure_master(sysops: System) -> None:
    """Подключить карту к autofs через /etc/auto.master.d."""
    p = sysops.paths
    _ensure_autofs_installed(p)
    master = _read(p.master_file)
    if master is None:
        raise OperationError("Не найден {} — переустановите autofs".format(MASTER_FILE))
    others = master_conflicts(master)
    if others:
        raise OperationError(
            "Каталог {} уже занят другой строкой в {}:\n{}\n"
            "Уберите её или перенесите свои каталоги в другую точку."
            .format(MOUNT_ROOT, MASTER_FILE, "\n".join(others)))
    if (_read(p.master_d_file) or "") != master_d_content():
        sysops.write(p.master_d_file, master_d_content(), 0o644)
    if not master_has_include(master):
        text = master if master.endswith("\n") or not master else master + "\n"
        text += "# Добавлено connectfolder: подключение файлов из {}\n{}\n".format(
            MASTER_D_DIR, MASTER_INCLUDE)
        sysops.write(p.master_file, text, 0o644, backup=True)
    if not os.path.exists(p.map_file):
        sysops.write(p.map_file, "# Сетевые каталоги connectfolder\n", 0o644)


def reload_autofs(sysops: System) -> None:
    rc, _ = (0, "") if not sysops.run_commands else _run(
        ["systemctl", "is-active", "--quiet", "autofs"], timeout=5)
    if rc == 0:
        sysops.run(["systemctl", "reload", "autofs"])
    else:
        sysops.run(["systemctl", "enable", "--now", "autofs"])


def _write_credentials(sysops: System, key: str, text: str) -> None:
    sysops.makedirs(sysops.paths.cred_dir, 0o700, enforce=True)
    sysops.write(sysops.paths.cred_file(key), text, 0o600)


def get_credentials(paths: Paths, key: str) -> Dict[str, str]:
    """Имя и домен (без пароля) для формы редактирования."""
    validate_key(key)
    text = _read(paths.cred_file(key))
    if text is None:
        return {"username": "", "domain": "", "has_password": False}
    c = parse_credentials(text)
    return {"username": c["username"], "domain": c["domain"],
            "has_password": bool(c["password"])}


def save_share(sysops: System, share: Share, creds: Optional[dict],
               original_key: Optional[str]) -> Share:
    """Добавить (original_key=None) или изменить каталог."""
    validate_share(share)
    p = sysops.paths
    ensure_master(sysops)
    mf = MapFile.load(p.map_file)

    old: Optional[Share] = None
    if original_key:
        validate_key(original_key)
        entry = mf.find(original_key)
        if entry is None or entry.share is None:
            raise OperationError("Каталог «{}» не найден в {}".format(original_key, MAP_FILE))
        old = entry.share
        if share.key != original_key and mf.has_key(share.key):
            raise OperationError("Каталог «{}» уже существует".format(share.key))
    elif mf.has_key(share.key):
        raise OperationError("Каталог «{}» уже существует".format(share.key))

    old_cred = p.cred_file(original_key) if original_key else None
    if share.auth == AUTH_PASSWORD:
        creds = creds or {}
        password = creds.get("password")
        if password is None:
            prev = _read(old_cred) if old_cred else None
            if prev is None:
                raise OperationError("Введите пароль")
            password = parse_credentials(prev)["password"]
        text = format_credentials(str(creds.get("username", "")).strip(),
                                  str(password), str(creds.get("domain", "")).strip())
        _write_credentials(sysops, share.key, text)

    share = replace(share, credentials_path="")
    if old is not None:
        mf.replace(original_key, share)
    else:
        mf.add(share)
    sysops.write(p.map_file, mf.render(), 0o644, backup=True)

    if old_cred and (share.key != original_key or share.auth != AUTH_PASSWORD):
        sysops.remove(old_cred)
    if old is not None and share.key != original_key:
        _try_umount(sysops, original_key)
    reload_autofs(sysops)
    return share


def _try_umount(sysops: System, key: str) -> None:
    mp = sysops.paths.mount_point(key)
    if sysops.run_commands and is_mounted(mp):
        sysops.run(["umount", mp], check=False)


def remove_share(sysops: System, key: str) -> None:
    validate_key(key)
    p = sysops.paths
    mf = MapFile.load(p.map_file)
    if mf.find(key) is None:
        raise OperationError("Каталог «{}» не найден в {}".format(key, MAP_FILE))
    mf.remove(key)
    sysops.write(p.map_file, mf.render(), 0o644, backup=True)
    sysops.remove(p.cred_file(key))
    _try_umount(sysops, key)
    reload_autofs(sysops)


# --------------------------------------------------------------------------
# Перенос со старых путей (/etc/auto.samba, /root/.auth_smb)
# --------------------------------------------------------------------------

@dataclass
class MigrationReport:
    migrated: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    nothing_to_do: bool = False

    def to_dict(self) -> dict:
        return {"migrated": self.migrated, "skipped": self.skipped,
                "warnings": self.warnings, "nothing_to_do": self.nothing_to_do}

    def summary(self) -> str:
        if self.nothing_to_do:
            return "Старой конфигурации нет, переносить нечего."
        lines = ["Перенесено каталогов: {}".format(len(self.migrated))]
        if self.migrated:
            lines.append("  " + ", ".join(self.migrated))
        if self.skipped:
            lines.append("Пропущено (уже есть с таким именем): " + ", ".join(self.skipped))
        lines += ["Внимание: " + w for w in self.warnings]
        return "\n".join(lines)


def _free_name(path: str) -> str:
    if not os.path.lexists(path):
        return path
    return "{}-{}".format(path, time.strftime("%Y%m%d-%H%M%S"))


def migrate_old_config(sysops: System) -> MigrationReport:
    p = sysops.paths
    rep = MigrationReport()
    old_text = _read(p.old_map_file)
    master = _read(p.master_file) or ""
    old_master = master_old_lines(master)
    if old_text is None and not old_master:
        rep.nothing_to_do = True
        return rep

    ensure_master(sysops)
    # ensure_master мог изменить auto.master — перечитаем.
    master = _read(p.master_file) or ""
    old_master = master_old_lines(master)

    new_map = MapFile.load(p.map_file)
    old_map = MapFile.parse(old_text or "")
    raw_lines: List[str] = []

    for e in old_map.entries:
        sh = e.share
        if sh is None:
            if e.raw.strip() and not e.raw.strip().startswith("#"):
                raw_lines.append(e.raw)
            continue
        if new_map.has_key(sh.key):
            rep.skipped.append(sh.key)
            continue
        if sh.auth == AUTH_PASSWORD:
            src = sh.credentials_path or (OLD_CRED_DIR + "/" + sh.key)
            text = _read(p(src))
            if text is None:
                rep.warnings.append(
                    "для «{}» не найден файл учётных данных {}: задайте пароль заново"
                    .format(sh.key, src))
                c = {"username": "", "password": "", "domain": ""}
            else:
                c = parse_credentials(text)
            cred_text = "username={}\npassword={}\n".format(c["username"], c["password"])
            if c["domain"]:
                cred_text += "domain={}\n".format(c["domain"])
            _write_credentials(sysops, sh.key, cred_text)
        new_map.add(replace(sh, credentials_path=""))
        rep.migrated.append(sh.key)

    if raw_lines:
        new_map.entries.append(MapEntry(
            "# Строки из {}, которые connectfolder не разобрал:".format(OLD_MAP_FILE)))
        new_map.entries += [MapEntry(r) for r in raw_lines]
        rep.warnings.append("{} строк(и) перенесены без изменений, проверьте их в {}"
                            .format(len(raw_lines), MAP_FILE))

    sysops.write(p.map_file, new_map.render(), 0o644, backup=True)

    if old_master:
        lines = master.splitlines(True)
        for n in old_master:
            old_line = lines[n].rstrip("\n")
            lines[n] = "# Отключено connectfolder, см. {}\n# {}\n".format(
                MASTER_D_FILE, old_line)
        sysops.write(p.master_file, "".join(lines), 0o644, backup=True)

    if old_text is not None:
        sysops.rename(p.old_map_file, _free_name(p.old_map_file + MIGRATED_SUFFIX))
    if os.path.isdir(p.old_cred_dir):
        # В старом каталоге пароли лежали с правами 0644 — закрываем перед архивом.
        os.chmod(p.old_cred_dir, 0o700)
        for name in os.listdir(p.old_cred_dir):
            fp = os.path.join(p.old_cred_dir, name)
            if os.path.isfile(fp) and not os.path.islink(fp):
                os.chmod(fp, 0o600)
        sysops.rename(p.old_cred_dir, _free_name(p.old_cred_dir + MIGRATED_SUFFIX))

    reload_autofs(sysops)
    return rep


# --------------------------------------------------------------------------
# Клиент помощника (для интерфейса)
# --------------------------------------------------------------------------

class HelperError(Exception):
    def __init__(self, message: str, log: Optional[List[dict]] = None):
        super().__init__(message)
        self.log = log or []


def default_helper_path() -> str:
    env = os.environ.get("CONNECTFOLDER_HELPER")
    if env:
        return env
    installed = "/usr/libexec/connectfolder/connectfolder-helper"
    if os.path.exists(installed):
        return installed
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "connectfolder-helper")


class HelperClient:
    """Связь с помощником: один процесс pkexec на сеанс, JSON построчно."""

    def __init__(self, demo_root: Optional[str] = None, helper: Optional[str] = None):
        self.demo_root = demo_root
        self.helper = helper or default_helper_path()
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._next_id = 0

    def _start(self) -> None:
        if self.demo_root:
            cmd = [sys.executable, "-I", self.helper]
            env = dict(os.environ, CONNECTFOLDER_ROOT=self.demo_root)
        else:
            cmd = ["pkexec", self.helper]
            env = None
        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, bufsize=1, env=env)

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def call(self, action: str, **params) -> Tuple[dict, List[dict]]:
        with self._lock:
            if not self.running:
                self._start()
            assert self._proc and self._proc.stdin and self._proc.stdout
            self._next_id += 1
            req = {"id": self._next_id, "action": action, "params": params}
            try:
                self._proc.stdin.write(json.dumps(req, ensure_ascii=False) + "\n")
                self._proc.stdin.flush()
                line = self._proc.stdout.readline()
            except (BrokenPipeError, OSError):
                line = ""
            if not line:
                err = ""
                if self._proc.poll() is not None and self._proc.stderr:
                    err = self._proc.stderr.read().strip()
                rc = self._proc.poll()
                self._proc = None
                if rc in (126, 127) and not err:
                    raise HelperError("Действие отменено: права администратора не получены")
                raise HelperError("Помощник завершился (код {}). {}".format(rc, err).strip())
            resp = json.loads(line)
        log = resp.get("log", [])
        if not resp.get("ok"):
            raise HelperError(resp.get("error", "неизвестная ошибка"), log)
        return resp.get("result", {}), log

    def close(self) -> None:
        if self.running:
            try:
                assert self._proc and self._proc.stdin
                self._proc.stdin.close()
                self._proc.wait(timeout=3)
            except Exception:       # noqa: BLE001
                self._proc.kill()
        self._proc = None
