Name:           connectfolder
Version:        3.1.1
Release:        1%{?dist}
Summary:        Connect SMB network folders via autofs (GTK 4)
Summary(ru):    Подключение сетевых каталогов SMB через autofs (GTK 4)

# Лицензия в репозитории не указана — замените на выбранную.
License:        GPL-3.0-or-later
URL:            https://github.com/lazermin/connectfolder
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  make
BuildRequires:  python3
Requires:       python3
Requires:       python3-gobject
Requires:       gtk4 >= 4.6
Requires:       autofs
Requires:       cifs-utils
Requires:       samba-client
Requires:       polkit

%description
Graphical tool for RED OS 8 and other rpm-based systems: adds, edits and
removes SMB/CIFS network folders mounted on demand by autofs into
/media/share. Supports password and Kerberos (domain) authentication.
Migrates configuration of version 0.1.x (/etc/auto.samba, /root/.auth_smb).

%description -l ru
Программа для РЕД ОС 8 и других rpm-дистрибутивов: добавление, изменение и
удаление сетевых каталогов SMB/CIFS, которые autofs монтирует по обращению
в /media/share. Вход по паролю или по Kerberos (домен). Переносит настройки
версии 0.1.x (/etc/auto.samba, /root/.auth_smb).

%prep
%autosetup

%build

%install
%make_install PREFIX=%{_prefix}

%check
%{__python3} tests/test_core.py

%post
# Перенос настроек старой версии. Повторный запуск ничего не делает.
%{_libexecdir}/%{name}/connectfolder-helper --migrate --quiet || :

%files
%doc README.md
%{_bindir}/connectfolder
%{_datadir}/%{name}/
%{_libexecdir}/%{name}/
%{_datadir}/applications/io.github.lazermin.ConnectFolder.desktop
%{_datadir}/polkit-1/actions/io.github.lazermin.connectfolder.policy

%changelog
* Wed Oct 28 2026 lazermin <itvolna@gmail.com> - 3.1.1-1
- Server browser: fixed "Connect" button label, so long folder names
  no longer stretch the button; the full path is shown in its tooltip

* Wed Oct 28 2026 lazermin <itvolna@gmail.com> - 3.1.0-1
- Server browser: pick a share and folder instead of typing the path
  (smbclient -L / ls), with the form's credentials or Kerberos ticket
- "Check connection" tests the share itself via smbclient, not only port 445:
  missing share or folder, wrong password, locked account, SMB version
- Mount failures in the list: real cause instead of a misleading hint
- Fix: folder name was inserted repeatedly while typing the network path
- Fix: false NT_STATUS_NO_SUCH_FILE error when checking a share root
- Requires samba-client

* Tue Oct 27 2026 lazermin <itvolna@gmail.com> - 3.0.0-1
- Rewrite: GTK 4 UI running as normal user, pkexec helper with whitelisted actions
- New paths: /etc/auto.connectfolder, /etc/auto.master.d/connectfolder.autofs,
  /etc/connectfolder/credentials (0600); automatic migration from 0.1.x
- Fix shell injection, credentials permissions, line-index based edits,
  autofs restart on every refresh, '%' in passwords
