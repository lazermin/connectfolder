#!/usr/bin/env python3
"""Подготовить демо-корень: система «как после старой версии 0.1.x».

Создаёт /etc/auto.master со старой строкой, /etc/auto.samba с двумя
каталогами и /root/.auth_smb с паролями в старом формате.
Использование: demo_seed.py <каталог-корень>
"""

import os
import shutil
import sys

OLD_MASTER = """#
# Sample auto.master file
#
/misc\t/etc/auto.misc
+dir:/etc/auto.master.d
+auto.master
/media/share    /etc/auto.samba    --ghost
"""

OLD_MAP = """docs  -fstype=cifs,rw,noperm,credentials=/root/.auth_smb/docs  ://fileserver/docs
archive  -fstype=cifs,vers=1.0,rw,noperm,credentials=/root/.auth_smb/archive  ://nas01/archive/2020
otdel  -fstype=cifs,multiuser,cruid=$UID,sec=krb5,domain=corp.local  ://dc1.corp.local/otdel
"""

OLD_CREDS = {
    "docs": "[smb]\nusername=ivanov\npassword=Pa%ss 1\ndomain=CORP\n",
    "archive": "[smb]\nusername = guest\npassword = \ndomain = WORKGROUP\n",
}


def seed(root):
    if os.path.isdir(root):
        shutil.rmtree(root)
    for d in ("etc/auto.master.d", "root/.auth_smb", "usr/sbin", "media/share"):
        os.makedirs(os.path.join(root, d))
    for b in ("automount", "mount.cifs"):
        with open(os.path.join(root, "usr/sbin", b), "w") as f:
            f.write("#!/bin/sh\n")
    with open(os.path.join(root, "etc/auto.master"), "w") as f:
        f.write(OLD_MASTER)
    with open(os.path.join(root, "etc/auto.samba"), "w") as f:
        f.write(OLD_MAP)
    for k, v in OLD_CREDS.items():
        with open(os.path.join(root, "root/.auth_smb", k), "w") as f:
            f.write(v)
    print("Демо-корень подготовлен: " + root)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    seed(os.path.abspath(sys.argv[1]))
