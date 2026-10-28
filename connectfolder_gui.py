#!/usr/bin/env python3
"""connectfolder — подключение сетевых каталогов SMB через autofs. Интерфейс GTK 4.

Интерфейс работает от обычного пользователя: список каталогов и их статус
читаются без прав root. Права нужны только для изменений — тогда через
pkexec поднимается помощник connectfolder-helper (пароль спрашивается один
раз за сеанс).

Демо-режим без изменений в системе: CONNECTFOLDER_DEMO=1 или --demo.
"""

import os
import sys
import threading
import traceback

sys.path.insert(0, "/usr/share/connectfolder")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango  # noqa: E402

import connectfolder_core as core  # noqa: E402

APP_ID = "io.github.lazermin.ConnectFolder"
DEMO_ROOT = os.path.join(GLib.get_user_cache_dir(), "connectfolder-demo-root")

CSS = """
.banner { padding: 8px 12px; border-radius: 6px; margin: 6px 12px 0 12px; }
.banner-warn { background-color: alpha(#e5a50a, 0.22); }
.banner-error { background-color: alpha(#e01b24, 0.20); }
.banner-info { background-color: alpha(#3584e4, 0.18); }
.share-list { margin: 12px; }
.share-row { padding: 10px 8px; }
.share-title { font-weight: bold; font-size: 1.08em; }
.tag { font-size: 0.85em; padding: 1px 6px; border-radius: 4px;
       background-color: alpha(currentColor, 0.10); }
.tag-warn { background-color: alpha(#e5a50a, 0.30); }
.status-ok { color: #26a269; }
.status-warn { color: #c64600; }
.status-fail { color: #e01b24; }
.share-list { border: 1px solid alpha(currentColor, 0.15); border-radius: 8px; }
.share-list > row:not(:last-child) { border-bottom: 1px solid alpha(currentColor, 0.10); }
.cf-title { font-size: 1.25em; font-weight: bold; }
.cf-caption { font-size: 0.88em; }
.mono { font-family: monospace; }
.form-error { color: #e01b24; }
.log-view { font-family: monospace; font-size: 0.9em; }
"""

STATUS_ICONS = {
    core.STATUS_OK: ("emblem-ok-symbolic", "status-ok"),
    core.STATUS_WARN: ("dialog-warning-symbolic", "status-warn"),
    core.STATUS_FAIL: ("dialog-error-symbolic", "status-fail"),
    core.STATUS_UNKNOWN: ("dialog-question-symbolic", None),
}

AUTH_ITEMS = [(core.AUTH_PASSWORD, "По имени и паролю"),
              (core.AUTH_KERBEROS, "Доменная учётная запись (Kerberos)")]


def use_csd() -> bool:
    """Заголовок GTK (CSD) в GNOME-подобных средах, рамка оконного менеджера — в остальных."""
    forced = os.environ.get("CONNECTFOLDER_CSD")
    if forced in ("0", "1"):
        return forced == "1"
    desk = os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
    return any(d in desk for d in ("GNOME", "UNITY", "PANTHEON", "BUDGIE"))


def load_css() -> None:
    provider = Gtk.CssProvider()
    if hasattr(provider, "load_from_string"):          # GTK 4.12+
        provider.load_from_string(CSS)
    else:
        try:
            provider.load_from_data(CSS, -1)           # GTK 4.10
        except TypeError:
            provider.load_from_data(CSS.encode())      # GTK 4.0–4.8
    display = Gdk.Display.get_default()
    if display is not None:
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)


def run_async(fn, on_done, *args):
    """Выполнить fn(*args) в потоке, результат передать on_done(result, error) в главном."""
    def worker():
        try:
            res, err = fn(*args), None
        except Exception as e:      # noqa: BLE001
            res, err = None, e
            if not isinstance(e, (core.HelperError, core.ValidationError)):
                traceback.print_exc()
        GLib.idle_add(lambda: (on_done(res, err), False)[1])
    threading.Thread(target=worker, daemon=True).start()


def label(text="", css=None, xalign=0.0, wrap=False, selectable=False):
    lb = Gtk.Label(label=text, xalign=xalign)
    if wrap:
        lb.set_wrap(True)
        lb.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if selectable:
        lb.set_selectable(True)
    for c in (css or "").split():
        lb.add_css_class(c)
    return lb


def close_on_escape(win: Gtk.Window) -> None:
    ctl = Gtk.EventControllerKey()

    def on_key(_c, keyval, _code, _state):
        if keyval == Gdk.KEY_Escape:
            win.close()
            return True
        return False
    ctl.connect("key-pressed", on_key)
    win.add_controller(ctl)


def message_dialog(parent, title, text, buttons, on_response, destructive=None):
    """Простой модальный диалог, работает на GTK 4.6+ (без Gtk.AlertDialog).

    buttons — список (id, подпись); последняя кнопка — основная.
    """
    win = Gtk.Window(transient_for=parent, modal=True, title=title, resizable=False)
    win.set_default_size(420, -1)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                  margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
    box.append(label(title, "cf-title", wrap=True))
    body = label(text, wrap=True, selectable=True)
    body.set_max_width_chars(60)
    box.append(body)
    row = Gtk.Box(spacing=8, halign=Gtk.Align.END, margin_top=6)
    answered = {"done": False}

    def respond(rid):
        if not answered["done"]:
            answered["done"] = True
            win.close()
            on_response(rid)

    for i, (rid, text_) in enumerate(buttons):
        b = Gtk.Button(label=text_)
        if rid == destructive:
            b.add_css_class("destructive-action")
        elif i == len(buttons) - 1:
            b.add_css_class("suggested-action")
        b.connect("clicked", lambda _b, r=rid: respond(r))
        row.append(b)
    box.append(row)
    win.set_child(box)
    win.connect("close-request", lambda _w: (respond(None), False)[1])
    close_on_escape(win)
    win.present()


# --------------------------------------------------------------------------
# Строка списка
# --------------------------------------------------------------------------

class ShareRow(Gtk.ListBoxRow):
    def __init__(self, app_win, share: core.Share):
        super().__init__(activatable=False, selectable=False)
        self.win = app_win
        self.share = share
        self.add_css_class("share-row")

        grid = Gtk.Grid(column_spacing=12, row_spacing=2)
        self.status_stack = Gtk.Stack()
        self.spinner = Gtk.Spinner()
        self.status_icon = Gtk.Image(pixel_size=20)
        self.status_stack.add_named(self.spinner, "spin")
        self.status_stack.add_named(self.status_icon, "icon")
        self.status_stack.set_valign(Gtk.Align.CENTER)
        grid.attach(self.status_stack, 0, 0, 1, 3)

        grid.attach(label(share.key, "share-title"), 1, 0, 1, 1)
        path = label("{}  →  {}".format(share.unc, share.mount_point), "dim-label")
        path.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        path.set_tooltip_text(path.get_text())
        grid.attach(path, 1, 1, 1, 1)

        tags = Gtk.Box(spacing=6, margin_top=3)
        for text, warn in self._tags():
            t = label(text, "tag tag-warn" if warn else "tag")
            tags.append(t)
        self.status_label = label("", "dim-label", wrap=True)
        tags.append(self.status_label)
        self.why_btn = Gtk.Button(label="Узнать причину",
                                  tooltip_text="Проверить подключение с сохранённым паролем "
                                               "(нужны права администратора)")
        self.why_btn.add_css_class("flat")
        self.why_btn.set_visible(False)
        self.why_btn.connect("clicked", lambda _b: self.win.diagnose_row(self))
        tags.append(self.why_btn)
        grid.attach(tags, 1, 2, 1, 1)

        buttons = Gtk.Box(spacing=4, valign=Gtk.Align.CENTER, hexpand=True,
                          halign=Gtk.Align.END)
        for icon, tip, cb in (
                ("folder-open-symbolic", "Открыть каталог", self.on_open),
                ("view-refresh-symbolic", "Проверить доступность", self.on_check),
                ("document-edit-symbolic", "Изменить", self.on_edit),
                ("user-trash-symbolic", "Отключить и удалить", self.on_delete)):
            b = Gtk.Button(icon_name=icon, tooltip_text=tip)
            b.add_css_class("flat")
            b.connect("clicked", lambda _b, f=cb: f())
            buttons.append(b)
        grid.attach(buttons, 2, 0, 1, 3)
        self.set_child(grid)
        self.set_status(core.STATUS_UNKNOWN, "")

    def _tags(self):
        s = self.share
        out = []
        if s.auth == core.AUTH_KERBEROS:
            out.append(("Kerberos", False))
        else:
            out.append(("Пароль", False))
            out.append(({core.ACCESS_OWNER: "владелец — пользователь",
                         core.ACCESS_SHARED: "доступ у всех",
                         core.ACCESS_NONE: "владелец root"}[s.access],
                        s.access == core.ACCESS_SHARED))
        if s.smb_version:
            out.append(("SMB " + s.smb_version, s.smb_version == "1.0"))
        if s.read_only:
            out.append(("только чтение", False))
        return out

    def set_status(self, status, text, offer_diagnosis=False):
        self.why_btn.set_visible(offer_diagnosis)
        if status == core.STATUS_CHECKING:
            self.status_stack.set_visible_child_name("spin")
            self.spinner.start()
            self.status_label.set_text("проверка…")
            return
        self.spinner.stop()
        icon, css = STATUS_ICONS.get(status, STATUS_ICONS[core.STATUS_UNKNOWN])
        self.status_icon.set_from_icon_name(icon)
        for c in ("status-ok", "status-warn", "status-fail"):
            self.status_icon.remove_css_class(c)
        if css:
            self.status_icon.add_css_class(css)
        self.status_stack.set_visible_child_name("icon")
        self.status_label.set_text(text)
        self.status_icon.set_tooltip_text(text or None)

    def on_open(self):
        self.win.open_folder(self.share)

    def on_check(self):
        self.win.check_row(self)

    def on_edit(self):
        self.win.edit_share(self.share)

    def on_delete(self):
        self.win.delete_share(self.share)


# --------------------------------------------------------------------------
# Обзор сервера: выбор шары и подкаталога
# --------------------------------------------------------------------------

class BrowseRow(Gtk.ListBoxRow):
    def __init__(self, entry_name):
        super().__init__()
        self.entry_name = entry_name


class BrowseDialog(Gtk.Window):
    """Обзор шар и каталогов сервера.

    fetch(path, callback) получает содержимое: path == "" — список шар,
    "шара/подкаталог" — подкаталоги; callback(status, text, entries).
    on_choose(path) вызывается с выбранным путём «шара/подкаталог».
    """

    def __init__(self, parent, server, start_path, fetch, on_choose):
        super().__init__(transient_for=parent, modal=True,
                         title="Обзор //{}".format(server))
        self.server = server
        self.fetch = fetch
        self.on_choose = on_choose
        self.path = ""
        self.request = 0
        self.set_default_size(520, 460)
        close_on_escape(self)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10,
                      margin_top=14, margin_bottom=14, margin_start=14, margin_end=14)

        top = Gtk.Box(spacing=8)
        self.up_btn = Gtk.Button(icon_name="go-up-symbolic", tooltip_text="На уровень выше")
        self.up_btn.connect("clicked", lambda _b: self.go_up())
        top.append(self.up_btn)
        self.location = label("", "mono")
        self.location.set_ellipsize(Pango.EllipsizeMode.START)
        self.location.set_hexpand(True)
        top.append(self.location)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Обновить")
        refresh.add_css_class("flat")
        refresh.connect("clicked", lambda _b: self.load(self.path))
        top.append(refresh)
        box.append(top)

        self.stack = Gtk.Stack(vexpand=True)
        spin_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                           valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
        self.spinner = Gtk.Spinner(width_request=32, height_request=32)
        spin_box.append(self.spinner)
        spin_box.append(label("Загрузка…", "dim-label", xalign=0.5))
        self.stack.add_named(spin_box, "loading")

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.listbox.add_css_class("share-list")
        self.listbox.connect("row-activated", self.on_row_activated)
        self.listbox.connect("selected-rows-changed", lambda _l: self.update_choose())
        sw = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        sw.set_child(self.listbox)
        self.stack.add_named(sw, "list")

        self.message = label("", wrap=True, xalign=0.5)
        self.message.set_valign(Gtk.Align.CENTER)
        self.message.set_justify(Gtk.Justification.CENTER)
        self.stack.add_named(self.message, "message")
        box.append(self.stack)

        box.append(label("Двойной щелчок или Enter — открыть каталог", "dim-label cf-caption"))

        btns = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        cancel = Gtk.Button(label="Отмена")
        cancel.connect("clicked", lambda _b: self.close())
        btns.append(cancel)
        self.choose_btn = Gtk.Button(label="Подключить")
        self.choose_btn.add_css_class("suggested-action")
        self.choose_btn.connect("clicked", lambda _b: self.choose())
        btns.append(self.choose_btn)
        box.append(btns)
        self.set_child(box)
        self.load(start_path.strip("/"))

    # ---- навигация ----

    def load(self, path):
        self.request += 1
        req = self.request
        self.path = path
        self.location.set_text("//{}/{}".format(self.server, path) if path
                               else "//{}  (общие папки)".format(self.server))
        self.up_btn.set_sensitive(bool(path))
        self.choose_btn.set_sensitive(False)
        self.spinner.start()
        self.stack.set_visible_child_name("loading")

        def done(status, text, entries):
            if req != self.request:
                return              # пользователь уже ушёл в другой каталог
            self.spinner.stop()
            self.show_entries(status, text, entries)
        self.fetch(path, done)

    def show_entries(self, status, text, entries):
        child = self.listbox.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt
        if status != core.STATUS_OK:
            self.message.set_text(text)
            self.stack.set_visible_child_name("message")
        elif not entries:
            self.message.set_text(text or ("Подкаталогов нет. Можно выбрать этот каталог."
                                           if self.path else "Общих папок не найдено."))
            self.stack.set_visible_child_name("message")
        else:
            for e in entries:
                self.listbox.append(self.make_row(e))
            self.stack.set_visible_child_name("list")
        self.update_choose()

    def make_row(self, entry):
        row = BrowseRow(entry["name"])
        hb = Gtk.Box(spacing=10, margin_top=6, margin_bottom=6, margin_start=8, margin_end=8)
        icon = "folder-remote-symbolic" if entry.get("kind") == "share" else "folder-symbolic"
        hb.append(Gtk.Image(icon_name=icon))
        name = label(entry["name"], "dim-label" if entry.get("hidden") else None)
        name.set_ellipsize(Pango.EllipsizeMode.END)
        name.set_hexpand(True)
        hb.append(name)
        if entry.get("comment"):
            c = label(entry["comment"], "dim-label cf-caption")
            c.set_ellipsize(Pango.EllipsizeMode.END)
            hb.append(c)
        row.set_child(hb)
        return row

    def child_path(self, name):
        return "{}/{}".format(self.path, name) if self.path else name

    def on_row_activated(self, _lb, row):
        if isinstance(row, BrowseRow):
            self.load(self.child_path(row.entry_name))

    def go_up(self):
        if self.path:
            self.load(self.path.rpartition("/")[0])

    # ---- выбор ----

    def selected_path(self):
        row = self.listbox.get_selected_row()
        if isinstance(row, BrowseRow) and self.stack.get_visible_child_name() == "list":
            return self.child_path(row.entry_name)
        return self.path

    def update_choose(self):
        target = self.selected_path()
        loaded = self.stack.get_visible_child_name() != "loading"
        self.choose_btn.set_sensitive(bool(target) and loaded)
        # Подпись постоянная, чтобы кнопка не растягивалась под длинные имена;
        # какой каталог будет подключён, видно в подсказке.
        self.choose_btn.set_tooltip_text(
            "//{}/{}".format(self.server, target) if target else None)

    def choose(self):
        target = self.selected_path()
        if target:
            self.close()
            self.on_choose(target)


# --------------------------------------------------------------------------
# Форма добавления/изменения
# --------------------------------------------------------------------------

class ShareDialog(Gtk.Window):
    def __init__(self, app_win, share=None, realm=""):
        title = "Изменить сетевой каталог" if share else "Подключить сетевой каталог"
        super().__init__(transient_for=app_win, modal=True, title=title)
        self.win = app_win
        self.original = share
        self.key_touched = share is not None
        # True, пока форма сама меняет поля: сигналы «changed» от этих
        # изменений не должны снова запускать обработчик.
        self._updating = False
        self.set_default_size(560, -1)
        close_on_escape(self)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                        margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        row = 0

        def add(caption, widget, hint=None):
            nonlocal row
            grid.attach(label(caption, xalign=1.0), 0, row, 1, 1)
            widget.set_hexpand(True)
            grid.attach(widget, 1, row, 1, 1)
            row += 1
            if hint is not None:
                grid.attach(hint, 1, row, 1, 1)
                row += 1

        self.path = Gtk.Entry(placeholder_text="fileserver/docs  или  \\\\fileserver\\docs")
        self.path.set_hexpand(True)
        path_box = Gtk.Box(spacing=6)
        path_box.append(self.path)
        browse_btn = Gtk.Button(label="Обзор…",
                                tooltip_text="Выбрать шару и каталог на сервере. "
                                             "Используются способ входа и учётные данные из формы")
        browse_btn.connect("clicked", self.on_browse)
        path_box.append(browse_btn)
        add("Сетевой путь", path_box)

        self.key = Gtk.Entry(placeholder_text="docs", max_length=64)
        self.key_hint = label("", "dim-label cf-caption")
        add("Имя каталога", self.key, self.key_hint)

        self.auth = Gtk.DropDown.new_from_strings([t for _, t in AUTH_ITEMS])
        add("Вход", self.auth)

        self.user = Gtk.Entry()
        self.pass_ = Gtk.PasswordEntry(show_peek_icon=True)
        self.domain = Gtk.Entry(placeholder_text="DOMAIN или WORKGROUP (необязательно)")
        self.access = Gtk.DropDown.new_from_strings([t for _, t in core.ACCESS_MODES])
        self.cred_rows = []
        for caption, w in (("Пользователь", self.user), ("Пароль", self.pass_),
                           ("Домен", self.domain), ("Доступ к файлам", self.access)):
            r0 = row
            add(caption, w)
            self.cred_rows.append([grid.get_child_at(0, r0), w])
        self.krb_hint = label(
            "Каждый пользователь подключается со своим билетом Kerberos. "
            "Пароль не хранится.", "dim-label cf-caption", wrap=True)
        grid.attach(self.krb_hint, 1, row, 1, 1)
        row += 1

        self.versions = [v for v, _ in core.SMB_VERSIONS]
        names = [t for _, t in core.SMB_VERSIONS]
        if share and share.smb_version and share.smb_version not in self.versions:
            self.versions.append(share.smb_version)
            names.append("SMB " + share.smb_version)
        self.vers = Gtk.DropDown.new_from_strings(names)
        add("Версия протокола", self.vers)

        self.ro = Gtk.CheckButton(label="Только чтение")
        add("", self.ro)

        self.extra = Gtk.Entry(placeholder_text="например: iocharset=utf8,nobrl")
        add("Доп. опции", self.extra)

        outer.append(grid)

        exp = Gtk.Expander(label="Строка карты autofs")
        self.preview = label("", "mono dim-label", wrap=True, selectable=True)
        exp.set_child(self.preview)
        outer.append(exp)

        self.error = label("", "form-error", wrap=True)
        self.error.set_visible(False)
        outer.append(self.error)

        btns = Gtk.Box(spacing=8)
        self.test_btn = Gtk.Button(label="Проверить подключение",
                                   tooltip_text="Подключиться к шаре с этими настройками "
                                                "и прочитать каталог")
        self.test_btn.connect("clicked", self.on_test)
        btns.append(self.test_btn)
        self.test_label = label("", "dim-label", wrap=True)
        self.test_label.set_hexpand(True)
        btns.append(self.test_label)
        cancel = Gtk.Button(label="Отмена")
        cancel.connect("clicked", lambda _b: self.close())
        btns.append(cancel)
        self.save_btn = Gtk.Button(label="Сохранить" if share else "Подключить")
        self.save_btn.add_css_class("suggested-action")
        self.save_btn.connect("clicked", self.on_save)
        btns.append(self.save_btn)
        outer.append(btns)
        self.set_child(outer)
        self.set_default_widget(self.save_btn)

        # Начальные значения
        if share:
            self.path.set_text("{}/{}".format(share.server, share.share_path))
            self.key.set_text(share.key)
            self.auth.set_selected(0 if share.auth == core.AUTH_PASSWORD else 1)
            self.access.set_selected([a for a, _ in core.ACCESS_MODES].index(share.access))
            self.vers.set_selected(self.versions.index(share.smb_version))
            self.ro.set_active(share.read_only)
            self.extra.set_text(",".join(share.extra))
            if share.auth == core.AUTH_PASSWORD:
                self.pass_.set_property("placeholder-text", "не менять")
                self.user.set_placeholder_text("загрузка…")
        else:
            self.auth.set_selected(1 if realm else 0)
            # Кириллица в именах файлов на Windows-серверах.
            self.extra.set_text("iocharset=utf8")
            if realm:
                self.domain.set_text(realm.split(".")[0].upper())

        for w in (self.path, self.key, self.extra):
            w.connect("changed", self.on_changed)
        for dd in (self.auth, self.access, self.vers):
            dd.connect("notify::selected", self.on_changed)
        self.ro.connect("toggled", self.on_changed)
        self.on_changed()

    # ---- данные ----

    def fill_credentials(self, creds):
        self.user.set_placeholder_text("")
        if creds:
            self.user.set_text(creds.get("username", ""))
            self.domain.set_text(creds.get("domain", ""))
            if not creds.get("has_password"):
                self.pass_.set_property("placeholder-text", "")

    def collect(self) -> core.Share:
        server, share_path = core.parse_network_path(self.path.get_text())
        key = self.key.get_text().strip()
        extra = [o.strip() for o in self.extra.get_text().split(",") if o.strip()]
        sh = core.Share(
            key=key, server=server, share_path=share_path,
            auth=AUTH_ITEMS[self.auth.get_selected()][0],
            smb_version=self.versions[self.vers.get_selected()],
            access=core.ACCESS_MODES[self.access.get_selected()][0],
            read_only=self.ro.get_active(), extra=extra)
        if sh.auth == core.AUTH_KERBEROS:
            sh.access = core.ACCESS_NONE
        core.validate_share(sh)
        return sh

    # ---- события ----

    def on_changed(self, *args):
        if self._updating:
            return
        if args and args[0] is self.key:
            # Пользователь сам правит имя — больше не подставляем его из пути.
            self.key_touched = True
        self._updating = True
        try:
            self._update_form()
        finally:
            self._updating = False

    def _update_form(self):
        is_pw = self.auth.get_selected() == 0
        for cap, w in self.cred_rows:
            if cap is not None:
                cap.set_visible(is_pw)
            w.set_visible(is_pw)
        self.krb_hint.set_visible(not is_pw)

        if not self.key_touched:
            try:
                _s, sp = core.parse_network_path(self.path.get_text())
                suggested = core.suggest_key(sp)
                if self.key.get_text() != suggested:
                    self.key.set_text(suggested)
            except core.ValidationError:
                pass
        self.key_hint.set_text("Будет доступен как {}/{}".format(
            core.MOUNT_ROOT, self.key.get_text().strip() or "…"))

        try:
            sh = self.collect()
        except core.ValidationError as e:
            self.preview.set_text("—")
            self.show_error(str(e) if self.path.get_text().strip() else "")
            self.save_btn.set_sensitive(False)
            return
        self.preview.set_text(core.build_map_line(sh))
        warn = ""
        if sh.smb_version == "1.0":
            warn = "SMB 1.0 устарел и небезопасен. Используйте его только для старых устройств."
        elif sh.auth == core.AUTH_PASSWORD and sh.access == core.ACCESS_SHARED:
            warn = ("Файлы будут доступны всем пользователям этого компьютера "
                    "под учётной записью, указанной здесь.")
        self.show_error(warn)
        self.save_btn.set_sensitive(True)

    def show_error(self, text):
        self.error.set_text(text)
        self.error.set_visible(bool(text))

    def connection_mode(self):
        """Чем подключаться к серверу для проверки и обзора.

        ("local", creds) — от имени пользователя (Kerberos: creds = None);
        ("helper", params) — пароль не меняли, его знает только помощник;
        ("error", текст).
        """
        if AUTH_ITEMS[self.auth.get_selected()][0] == core.AUTH_KERBEROS:
            return "local", None
        user = self.user.get_text().strip()
        domain = self.domain.get_text().strip()
        pw = self.pass_.get_text()
        if (pw == "" and self.original is not None
                and self.original.auth == core.AUTH_PASSWORD):
            return "helper", {"key": self.original.key, "username": user, "domain": domain}
        if not user:
            return "error", "Укажите имя пользователя"
        return "local", {"username": user, "password": pw, "domain": domain}

    def on_test(self, _b):
        try:
            sh = self.collect()
        except core.ValidationError as e:
            self.test_label.set_text("✘ " + str(e))
            return
        mode, data = self.connection_mode()
        if mode == "error":
            self.test_label.set_text("✘ " + data)
            return
        self.test_btn.set_sensitive(False)
        self.test_label.set_text("проверка {}…".format(sh.unc))

        def show(status, text):
            self.test_btn.set_sensitive(True)
            mark = {core.STATUS_OK: "✔ ", core.STATUS_FAIL: "✘ "}.get(status, "⚠ ")
            self.test_label.set_text(mark + text)

        if mode == "helper":
            def done_helper(res, err):
                if err is not None:
                    show(core.STATUS_FAIL, str(err))
                else:
                    show(res["status"], res["text"])
            self.win.helper_call("probe", done_helper, share=sh.to_dict(), **data)
            return

        def done_local(res, err):
            if err is not None:
                show(core.STATUS_FAIL, str(err))
            else:
                show(*res)
        run_async(core.probe_share, done_local, sh, data, self.win.demo)

    def on_browse(self, _b):
        try:
            server = core.parse_server(self.path.get_text())
        except core.ValidationError as e:
            self.test_label.set_text("✘ " + str(e))
            return
        try:
            _s, start = core.parse_network_path(self.path.get_text())
        except core.ValidationError:
            start = ""
        mode, data = self.connection_mode()
        if mode == "error":
            self.test_label.set_text("✘ " + data + " — без него сервер не покажет папки")
            return
        auth = AUTH_ITEMS[self.auth.get_selected()][0]
        vers = self.versions[self.vers.get_selected()]
        demo = self.win.demo

        def fetch(path, callback):
            if mode == "helper":
                def done_helper(res, err):
                    if err is not None:
                        callback(core.STATUS_FAIL, str(err), [])
                    else:
                        callback(res["status"], res["text"], res.get("entries", []))
                self.win.helper_call("browse", done_helper, server=server, path=path,
                                     smb_version=vers, **data)
                return

            def done_local(res, err):
                if err is not None:
                    callback(core.STATUS_FAIL, str(err), [])
                else:
                    callback(*res)
            run_async(core.smb_browse, done_local, server, path, auth, vers, data, None, demo)

        def chosen(path):
            self.path.set_text("{}/{}".format(server, path))
            self.test_label.set_text("")

        BrowseDialog(self, server, start, fetch, chosen).present()

    def on_save(self, _b):
        try:
            sh = self.collect()
        except core.ValidationError as e:
            self.show_error(str(e))
            return
        creds = None
        if sh.auth == core.AUTH_PASSWORD:
            pw = self.pass_.get_text()
            if not self.user.get_text().strip():
                self.show_error("Укажите имя пользователя")
                return
            creds = {"username": self.user.get_text().strip(),
                     "domain": self.domain.get_text().strip(),
                     "password": None if (pw == "" and self.original is not None
                                         and self.original.auth == core.AUTH_PASSWORD)
                     else pw}
        self.save_btn.set_sensitive(False)
        self.win.save_share(self, sh, creds,
                            self.original.key if self.original else None)

    def save_failed(self, msg):
        self.save_btn.set_sensitive(True)
        self.show_error(msg)


# --------------------------------------------------------------------------
# Главное окно
# --------------------------------------------------------------------------

class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app, demo):
        super().__init__(application=app, title="Сетевые каталоги")
        self.demo = demo
        self.paths = core.Paths(DEMO_ROOT if demo else "/")
        self.client = core.HelperClient(demo_root=DEMO_ROOT if demo else None)
        self.state = None
        self.rows = []
        self.check_gen = 0
        self.check_sem = threading.Semaphore(4)
        self.set_default_size(760, 560)

        self.add_action_simple("migrate", self.on_migrate)
        self.add_action_simple("setup", self.on_setup)
        self.add_action_simple("about", self.on_about)

        menu = Gio.Menu()
        menu.append("Перенести старую конфигурацию…", "win.migrate")
        menu.append("Подключить карту к autofs и запустить службу", "win.setup")
        menu.append("О программе", "win.about")

        self.spinner = Gtk.Spinner()
        add_b = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Подключить каталог")
        add_b.connect("clicked", lambda _b: self.edit_share(None))
        ref_b = Gtk.Button(icon_name="view-refresh-symbolic",
                           tooltip_text="Обновить список и проверить доступность")
        ref_b.connect("clicked", lambda _b: self.refresh())
        self.log_b = Gtk.ToggleButton(icon_name="utilities-terminal-symbolic",
                                      tooltip_text="Журнал действий")
        self.log_b.connect("toggled", lambda b: self.log_rev.set_reveal_child(b.get_active()))
        menu_b = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        if use_csd():
            hb = Gtk.HeaderBar()
            hb.pack_start(add_b)
            hb.pack_start(ref_b)
            hb.pack_end(menu_b)
            hb.pack_end(self.log_b)
            hb.pack_end(self.spinner)
            self.set_titlebar(hb)
        else:
            bar = Gtk.Box(spacing=6, margin_top=6, margin_bottom=6,
                          margin_start=8, margin_end=8)
            add_b.set_label("Подключить")
            ref_b.set_label("Обновить")
            for w in (add_b, ref_b, Gtk.Box(hexpand=True), self.spinner, self.log_b, menu_b):
                bar.append(w)
            root.append(bar)
            root.append(Gtk.Separator())
        if demo:
            self.set_title("Сетевые каталоги — демо")

        self.banners = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        root.append(self.banners)

        self.stack = Gtk.Stack(vexpand=True)
        empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                        valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
        empty.append(Gtk.Image(icon_name="folder-remote-symbolic", pixel_size=64,
                               css_classes=["dim-label"]))
        empty.append(label("Сетевые каталоги не подключены", "cf-title", xalign=0.5))
        empty_b = Gtk.Button(label="Подключить каталог…", halign=Gtk.Align.CENTER)
        empty_b.add_css_class("suggested-action")
        empty_b.connect("clicked", lambda _b: self.edit_share(None))
        empty.append(empty_b)
        self.stack.add_named(empty, "empty")

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("share-list")
        sw = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        sw.set_child(self.listbox)
        self.stack.add_named(sw, "list")
        root.append(self.stack)

        self.log_rev = Gtk.Revealer(transition_type=Gtk.RevealerTransitionType.SLIDE_UP)
        self.log_view = Gtk.TextView(editable=False, cursor_visible=False,
                                     wrap_mode=Gtk.WrapMode.WORD_CHAR,
                                     left_margin=8, right_margin=8,
                                     top_margin=6, bottom_margin=6)
        self.log_view.add_css_class("log-view")
        lsw = Gtk.ScrolledWindow(min_content_height=160)
        lsw.set_child(self.log_view)
        log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        log_box.append(Gtk.Separator())
        log_box.append(lsw)
        self.log_rev.set_child(log_box)
        root.append(self.log_rev)

        self.set_child(root)
        self.connect("close-request", self.on_close)
        self.log("connectfolder {}{}".format(core.VERSION, " (демо-режим)" if demo else ""))
        self.refresh()

    # ---- служебное ----

    def add_action_simple(self, name, cb):
        a = Gio.SimpleAction.new(name, None)
        a.connect("activate", lambda *_a: cb())
        self.add_action(a)

    def log(self, text):
        buf = self.log_view.get_buffer()
        buf.insert(buf.get_end_iter(), text.rstrip() + "\n")
        mark = buf.create_mark(None, buf.get_end_iter(), False)
        self.log_view.scroll_mark_onscreen(mark)
        buf.delete_mark(mark)

    def log_commands(self, entries):
        for e in entries or []:
            self.log("$ {}  [код {}]".format(e.get("cmd"), e.get("rc")))
            if e.get("out"):
                self.log("  " + e["out"].replace("\n", "\n  "))

    def busy(self, on):
        if on:
            self.spinner.start()
        else:
            self.spinner.stop()

    def helper_call(self, action, on_done, **params):
        """Вызов помощника в потоке. on_done(result) только при успехе."""
        self.busy(True)
        self.log("> {}".format(action))

        def done(res, err):
            self.busy(False)
            if err is not None:
                self.log_commands(getattr(err, "log", []))
                self.log("ошибка: {}".format(err))
                on_done(None, err)
                return
            result, log = res
            self.log_commands(log)
            on_done(result, None)
        run_async(lambda: self.client.call(action, **params), done)

    def on_close(self, _w):
        self.client.close()
        return False

    # ---- состояние ----

    def refresh(self):
        self.busy(True)

        def done(state, err):
            self.busy(False)
            if err is not None:
                self.log("не удалось прочитать состояние: {}".format(err))
                return
            self.state = state
            self.rebuild()
        run_async(core.read_state, done, self.paths, self.demo)

    def rebuild(self):
        st = self.state
        if st is None:
            return
        child = self.banners.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.banners.remove(child)
            child = nxt

        if not st.autofs_installed or not st.cifs_installed:
            missing = [n for n, ok in (("autofs", st.autofs_installed),
                                       ("cifs-utils", st.cifs_installed)) if not ok]
            self.banner("error", "Не установлено: {}. Выполните: sudo dnf install {}".format(
                ", ".join(missing), " ".join(missing)))
        if st.conflicts:
            self.banner("error", "Каталог {} занят другой строкой в {}:\n{}".format(
                core.MOUNT_ROOT, core.MASTER_FILE, "\n".join(st.conflicts)))
        if st.old_config:
            self.banner("warn",
                        "Найдена конфигурация старой версии ({}, каталогов: {}). "
                        "Перенесите её, чтобы управлять каталогами здесь."
                        .format(core.OLD_MAP_FILE, st.old_shares),
                        "Перенести…", self.on_migrate)
        elif st.shares and st.autofs_installed and (
                not st.master_configured or not st.service_active):
            what = ("карта не подключена к autofs" if not st.master_configured
                    else "служба autofs не запущена")
            self.banner("warn", "Каталоги не будут монтироваться: {}.".format(what),
                        "Исправить", self.on_setup)

        child = self.listbox.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt
        self.rows = [ShareRow(self, s) for s in st.shares]
        for r in self.rows:
            self.listbox.append(r)
        self.stack.set_visible_child_name("list" if self.rows else "empty")
        self.check_all()

    def banner(self, kind, text, button=None, cb=None):
        box = Gtk.Box(spacing=12)
        box.add_css_class("banner")
        box.add_css_class("banner-" + kind)
        icon = {"warn": "dialog-warning-symbolic", "error": "dialog-error-symbolic"}.get(
            kind, "dialog-information-symbolic")
        box.append(Gtk.Image(icon_name=icon, valign=Gtk.Align.START))
        lb = label(text, wrap=True, selectable=True)
        lb.set_hexpand(True)
        box.append(lb)
        if button:
            b = Gtk.Button(label=button, valign=Gtk.Align.CENTER)
            b.connect("clicked", lambda _b: cb())
            box.append(b)
        self.banners.append(box)

    # ---- проверка доступности ----

    def check_all(self):
        self.check_gen += 1
        for r in self.rows:
            self.check_row(r)

    def check_row(self, row):
        gen = self.check_gen
        row.set_status(core.STATUS_CHECKING, "")

        def work():
            with self.check_sem:
                return core.check_share(row.share, self.paths, self.demo)

        def done(res, err):
            if gen != self.check_gen or row.get_parent() is None:
                return
            if err is not None:
                row.set_status(core.STATUS_FAIL, str(err))
                return
            status, text = res
            # Для входа по паролю причину сбоя монтирования знает только
            # помощник: файл учётных данных доступен лишь root.
            offer = (status == core.STATUS_FAIL and not self.demo
                     and row.share.auth == core.AUTH_PASSWORD
                     and text.startswith("Не смонтирован"))
            row.set_status(status, text, offer_diagnosis=offer)
        run_async(work, done)

    def diagnose_row(self, row):
        row.set_status(core.STATUS_CHECKING, "")

        def done(res, err):
            if row.get_parent() is None:
                return
            if err is not None:
                row.set_status(core.STATUS_FAIL, "Проверка не выполнена: {}".format(err),
                               offer_diagnosis=True)
            else:
                st = res["status"]
                text = res["text"]
                if st == core.STATUS_OK:
                    st, text = core.STATUS_WARN, ("Сервер пускает с этим паролем, но autofs "
                                                  "не смонтировал каталог (см. journalctl -u autofs)")
                row.set_status(st, text)
        self.helper_call("probe", done, key=row.share.key, share=row.share.to_dict())

    def open_folder(self, share):
        path = self.paths.mount_point(share.key)
        try:
            Gio.AppInfo.launch_default_for_uri(Gio.File.new_for_path(path).get_uri(), None)
        except GLib.Error as e:
            message_dialog(self, "Не удалось открыть каталог", e.message,
                           [("ok", "Закрыть")], lambda _r: None)

    # ---- действия ----

    def edit_share(self, share):
        dlg = ShareDialog(self, share, self.state.realm if self.state else "")
        dlg.present()
        if share is not None and share.auth == core.AUTH_PASSWORD:
            def done(res, err):
                if err is not None:
                    dlg.fill_credentials(None)
                    dlg.show_error("Не удалось прочитать учётные данные: {}".format(err))
                else:
                    dlg.fill_credentials(res)
            self.helper_call("get_credentials", done, key=share.key)

    def save_share(self, dlg, share, creds, original_key):
        def done(res, err):
            if err is not None:
                dlg.save_failed(str(err))
                return
            dlg.close()
            self.log("сохранено: {}".format(share.key))
            self.refresh()
        self.helper_call("save", done, share=share.to_dict(), credentials=creds,
                         original_key=original_key)

    def delete_share(self, share):
        def answer(rid):
            if rid != "delete":
                return

            def done(_res, err):
                if err is not None:
                    self.error_dialog("Не удалось удалить каталог", err)
                self.refresh()
            self.helper_call("remove", done, key=share.key)
        message_dialog(
            self, "Отключить «{}»?".format(share.key),
            "Строка будет удалена из {}, файл учётных данных — тоже. "
            "Данные на сервере {} не затрагиваются.".format(core.MAP_FILE, share.unc),
            [("cancel", "Отмена"), ("delete", "Отключить")], answer, destructive="delete")

    def on_migrate(self):
        st = self.state
        if st and not st.old_config:
            message_dialog(self, "Перенос не нужен",
                           "Конфигурации старой версии ({}) не найдено."
                           .format(core.OLD_MAP_FILE), [("ok", "Закрыть")], lambda _r: None)
            return
        text = (
            "Каталоги из {old_map} будут перенесены в {map}, пароли из {old_cred} — в "
            "{cred} (права 0600). Строка в {master} будет закомментирована, карта "
            "подключится через {master_d}.\n\nСтарые файлы сохранятся с суффиксом "
            "{suf}. Права на файлы у перенесённых каталогов останутся прежними "
            "(доступ у всех), их можно поменять в настройках каталога."
        ).format(old_map=core.OLD_MAP_FILE, map=core.MAP_FILE, old_cred=core.OLD_CRED_DIR,
                 cred=core.CRED_DIR, master=core.MASTER_FILE, master_d=core.MASTER_D_FILE,
                 suf=core.MIGRATED_SUFFIX)

        def answer(rid):
            if rid != "go":
                return

            def done(res, err):
                if err is not None:
                    self.error_dialog("Перенос не выполнен", err)
                else:
                    rep = core.MigrationReport(**res)
                    message_dialog(self, "Перенос выполнен", rep.summary(),
                                   [("ok", "Закрыть")], lambda _r: None)
                self.refresh()
            self.helper_call("migrate", done)
        message_dialog(self, "Перенести старую конфигурацию?", text,
                       [("cancel", "Отмена"), ("go", "Перенести")], answer)

    def on_setup(self):
        def done(_res, err):
            if err is not None:
                self.error_dialog("Не удалось настроить autofs", err)
            self.refresh()
        self.helper_call("setup", done)

    def error_dialog(self, title, err):
        message_dialog(self, title, str(err), [("ok", "Закрыть")], lambda _r: None)

    def on_about(self):
        about = Gtk.AboutDialog(
            transient_for=self, modal=True, program_name="connectfolder",
            version=core.VERSION, logo_icon_name="folder-remote",
            comments="Подключение сетевых каталогов SMB через autofs",
            website="https://github.com/lazermin/connectfolder")
        about.present()


class App(Gtk.Application):
    def __init__(self, demo):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.demo = demo

    def do_startup(self):
        Gtk.Application.do_startup(self)
        load_css()

    def do_activate(self):
        win = self.get_active_window() or MainWindow(self, self.demo)
        win.present()


def main(argv):
    demo = "--demo" in argv or os.environ.get("CONNECTFOLDER_DEMO") == "1"
    if demo and not os.path.isdir(DEMO_ROOT):
        sys.stderr.write("Демо-корень не найден. Выполните: make demo-reset\n")
        return 1
    if os.geteuid() == 0 and not demo:
        sys.stderr.write("Запускайте программу от обычного пользователя: права root "
                         "запрашиваются через pkexec только для изменений.\n")
    argv = [a for a in argv if a != "--demo"]
    return App(demo).run(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
