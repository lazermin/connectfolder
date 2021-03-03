#!/usr/bin/env python3

# Version 0.1
# Last update: 03-03-2021


import configparser
# yum install python3-tkinter python3-pillow-tk python3-pillow
import os
import subprocess
from io import open
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk

config = configparser.ConfigParser()

p_folder = '/root/.auth_smb'
p_autosamba = '/etc/auto.samba'
p_automaster = '/etc/auto.master'
parm_smbver1 = 'vers=1.0,'
lab_mark = ''
var_edit = 0
params_automaster = '/mnt/share    /etc/auto.samba    --ghost'
status_folder = 'Статус'
path_icon = '/usr/share/icons/Adwaita/22x22/emblems/emblem-default.png'

# Функция поиска в файле p_automaster
def write_auto_master():
    global param
    param = 0
    f = open(p_automaster, "r")
    text = f.readlines()
    f.close()
    for line in range(len(text)):
        if text[line] == params_automaster + '\n':
            param = 1
    if param == 0:
        f = open(p_automaster, "a")  # добавить в конец файла
        f.write(params_automaster + '\n')
        f.close()


def create_folder():
    # Определим имя директории, которую создаём
    access_rights = 0o755
    try:
        os.mkdir(p_folder, access_rights)
    except OSError:
        pass
    else:
        pass


def file_smbuser(name_folder):
    file_smbuser_path = p_folder + '/' + name_folder
    return file_smbuser_path


# функция парсинга конфига и записи
def write_smbuser(auth_path, user_n, pass_w, domain_n):
    config_auth = configparser.ConfigParser()  # Создаём объекта парсера
    config_auth.read(auth_path)  # Читаем конфиг
    sector_smb = config_auth['smb']  # Обращаемся к секции smb
    sector_smb['username'] = user_n
    sector_smb['password'] = pass_w
    sector_smb['domain'] = domain_n
    with open(auth_path, 'w') as configfile:
        config_auth.write(configfile, space_around_delimiters=False)  # space_around_delimiters=False - запись без пробелов


def get_smbuser(auth_path):
    config_smb = configparser.ConfigParser()  # Создаём объекта парсера
    config_smb.read(auth_path)  # Читаем конфиг
    get_user = config_smb.get("smb", "username")
    get_password = config_smb.get("smb", "password")
    get_domain = config_smb.get("smb", "domain")
    return get_user, get_password, get_domain


def clear_edit():
    editFolder.delete(0, END)
    editPath.delete(0, END)
    editPassword.delete(0, END)
    editName.delete(0, END)
    editDomain.delete(0, END)


#  Функци обрезки последнего Slash / в конце каталога
def slash(str_Path_D = '', str_Folder_F = ''):
    if ', '.join(re.findall(r'(^.*)\/$', str_Path_D)):  # если в конце найден символ / то
        str_Path_D = ', '.join(re.findall(r'(^.*)\/$', str_Path_D))  # удаляем /
    else:
        str_Path_D = str_Path_D  # оставляем как есть

    if ', '.join(re.findall(r'(^.*)\/$', str_Folder_F)):  # если в конце найден символ / то
        str_Folder_F = ', '.join(re.findall(r'(^.*)\/$', str_Folder_F))  # удаляем /
    else:
        str_Folder_F = str_Folder_F  # оставляем как есть
    return str_Path_D, str_Folder_F


def get_params():
    p_domain = ''
    if var1.get() == True:
        p_domain = parm_smbver1
    params_autosamba = '-fstype=cifs,' + p_domain + 'rw,noperm,'
    str_PF = slash(editPath.get(), editFolder.get())
    str_credentials = str_PF[1] + '  ' + params_autosamba + 'credentials=' + p_folder + '/' \
                      + str_PF[1] + '  ' + '://' + str_PF[0] + '\n'
    return str_credentials


def params_domain():
    global params_domain_autosamba
    p_domain = ''
    str_domain = os.popen('domainname -d')
    str_domain = ', '.join(str_domain)
    str_PF = slash(editPath.get(), editFolder.get())
    if var1.get() == True:
        p_domain = parm_smbver1
    params_domain_autosamba = '-fstype=cifs,' + p_domain + 'multiuser,cruid=$UID,sec=krb5,'
    result_params_domain = str_PF[1] + '  ' + params_domain_autosamba + 'domain=' + str_domain.rstrip() + '  ' + '://' + str_PF[0] + '\n'
    return result_params_domain


def get_folder_in_autosamba(editFolder):
    global result
    File = open_auto_samba()  # читаем файл '/etc/auto.samba'
    if os.stat(p_autosamba).st_size == 0:  # если файл пустой
        result = 'False'
    for elem in File:
        if editFolder == re.findall(r'^\w+', elem)[0]:
            result = 'True'
            break
        else:
            result = 'False'
    return result


def edit_auto_samba():
    str_credentials = get_params()  # Забираем данные из edits (вариант с паролем)
    str_domain_params = params_domain()  # Забираем данные для домена
    f = open(p_autosamba, "r")
    contents = f.readlines()
    f.close()
    if var2.get() == True:
        contents.insert(list_number, str_domain_params)  # Вставляем новую строку в позицию
        del contents[list_number + 1]  # Удаление заменяемой строки
        f = open(p_autosamba, "w")
        contents = "".join(contents)
        f.write(contents)
        f.close()
    else:
        contents.insert(list_number, str_credentials)  # Вставляем новую строку в позицию
        del contents[list_number + 1]  # Удаление заменяемой строки
        f = open(p_autosamba, "w")
        contents = "".join(contents)
        f.write(contents)
        f.close()


def add_point_mount_edit():
    str_PF = slash(editPath.get(), editFolder.get())
    auth_path1 = file_smbuser(str_PF[1])  # Полный путь до файла авторизации
    auth_path2 = file_smbuser(g_edit_folder)  # полный путь до файла авторизации
    if auth_path1 == auth_path2:
        write_smbuser(file_smbuser(str_PF[1]), editName.get(), editPassword.get(),
                  editDomain.get())  # Вызов функции замены параметров в файле авторизации
        edit_auto_samba()
        update_listbox()

    if auth_path1 != auth_path2:  # Если файл авторизации существует то
        if os.path.isfile(auth_path1):  # если файл авторизации существует то
            messagebox.showinfo('Connect folder', 'Присвойте другое имя')
            clear_edit()
            return
        os.rename(auth_path2, file_smbuser(str_PF[1]))
        write_smbuser(file_smbuser(str_PF[1]), editName.get(), editPassword.get(),
                      editDomain.get())  # Вызов функции замены параметров в файле авторизации
        edit_auto_samba()
        update_listbox()


# Общая функция добавления
def add_point_mount():
    # Условие проверки Slash / в конце каталога
    if ', '.join(re.findall(r'(^.*)\/$', editFolder.get())):  # Если в конце найден символ / то
        str_folder = ', '.join(re.findall(r'(^.*)\/$', editFolder.get()))  # удаляем /
        auth_path = file_smbuser(str_folder)
    else:
        auth_path = file_smbuser(editFolder.get())  # Оставляем как есть
      # полный путь до файла авторизации
    new_file_smbuser = open(auth_path, 'w')
    new_file_smbuser.write('[smb]\nusername = \npassword = \ndomain = ')
    new_file_smbuser.close()
    write_smbuser(auth_path, editName.get(), editPassword.get(),
                  editDomain.get())  # Вызов функции замены параметров в файле авторизации

    if var2.get() == True:
        str_domain = params_domain()
        f = open(p_autosamba, "a")  # Добавить в конец файла
        f.write(str_domain)
        f.close()
        clear_edit()
        update_listbox()
    else:
        str_credentials = get_params()
        f = open(p_autosamba, "a")  # Добавить в конец файла
        f.write(str_credentials)
        f.close()
        clear_edit()
        update_listbox()
    label_mark.config(text=None, bg=None)
    update_listbox()
    subprocess.call(['systemctl', 'enable', 'autofs'])
    subprocess.call(['systemctl', 'restart', 'autofs'])


# Подключение сетевого каталога
def attach_folder():
    write_auto_master()
    create_folder()
    if editPath.get() == '':
        messagebox.showinfo('Connect folder', 'Заполните поле "сетевой путь"')
        return
    if editFolder.get() == '':
        messagebox.showinfo('Connect folder', '       Заполните поле\n "Каталог монтирования"')
        return

    if lab_mark == 'Редактирование списка!':
        add_point_mount_edit()

    if lab_mark != 'Редактирование списка!':
        if get_folder_in_autosamba(editFolder.get()) == 'True':  # поиск точки монтирования в auto.samba
            messagebox.showinfo('Connect folder', 'Точка монтирования с таким именем уже существует!')
        else:
            pass
            add_point_mount()
    c1.deselect()  # Снимаем флажок checkbox

def del_mount():
    if lab_mark == 'Редактирование списка!':
        select = list(listB.curselection())
        select.reverse()
        for item_List in select:
            listB.delete(item_List)
            # Удаление строки в файле см. переменная p_autosamba
            del_line = item_List
            with open(p_autosamba, 'r') as textobj:
                listFile = list(textobj)
                del listFile[del_line]
            with open(p_autosamba, 'w') as textobj:
                for n in listFile:
                    textobj.write(n)
        update_listbox()
        path = p_folder + '/' + name_Folder_File
        os.remove(path)
        subprocess.call(['systemctl', 'restart', 'autofs'])
        clear_edit()
        c1.deselect()  # Снимаем флажок checkbox
    else:
        pass


def number_list():
    try:
        select = list(listB.curselection())
        select.reverse()
        number = int(''.join(map(str, select)))  # Перевод списка чисел в число
    except:
        pass
    return number

# Функция вызывается при клике в listbox и заполняет поля
def get_params_in_to_edit():
    global g_edit_folder
    # Код заполнения полей edits
    editPath.config(state="normal")
    global name_Folder_File  # для передачи имени файла в функцию удаления
    clear_edit()
    lineFile = open_auto_samba()  # читаем номер строки из файла '/etc/auto.samba'
    str_domain = os.popen('domainname -d')
    str_domain = ', '.join(str_domain)
    str_domain = 'domain=' + str_domain.rstrip()

    if re.findall(r'(vers=1.0)', lineFile[number_list()]):
        c1.select()
    else:
        c1.deselect()

    if re.findall(r'\b' + str_domain, lineFile[number_list()]):
        c2.select()
        chek_status_domain()
        lineFolder = re.findall(r'\w+', lineFile[number_list()])[0]  # Парсинг каталога
        name_Folder_File = lineFolder
        linePath = re.findall(r'(//.+)$', lineFile[number_list()])[0]  # Парсинг сетевого пути
        linePath_split = linePath.split('//')[1]  # Парсинг сетевого пути
        editFolder.insert(0, lineFolder)  # Вставить в поле значение
        editPath.insert(0, linePath_split)
        str_PF = slash(editPath.get(), editFolder.get())
        g_edit_folder = str_PF[1]
    else:
        c2.deselect()
        chek_status_domain()
        lineFolder = re.findall(r'\w+', lineFile[number_list()])[0]  # Парсинг каталога
        name_Folder_File = lineFolder
        linePath = re.findall(r'(//.+)$', lineFile[number_list()])[0]  # Парсинг сетевого пути
        linePath_split = linePath.split('//')[1]  # Парсинг сетевого пути
        editFolder.insert(0, lineFolder)  # Вставить в поле значение
        editPath.insert(0, linePath_split)
        # Заполняем поля имя пользователя, пароль, домен из конфига
        get_user_pass = get_smbuser(file_smbuser(lineFolder))
        editName.insert(0, get_user_pass[0])
        editPassword.insert(0, get_user_pass[1])
        editDomain.insert(0, get_user_pass[2])
        g_edit_folder = editFolder.get()


def clear_focus_listbox():
    for i in reversed(listB.curselection()):
        listB.selection_clear(i)
    listB.select_set(0)
    listB.activate(0)


def edit_mount():
    clear_edit()  # Очиска полей
    clear_focus_listbox()
    delButton.pack(side=RIGHT)
    # глобальные маркеры переключения
    global var_edit
    global lab_mark
    # Переключатель кнопки редактирования/отмена
    if var_edit == 0:
        editButton.config(text='Отмена')
        lab_mark = 'Редактирование списка!'
        label_mark.config(text=lab_mark, bg='green')
        var_edit = 1
        on_select()
        delButton.pack(side=RIGHT)
        c2.config(state='disabled')  # Блокируем checkbox
        connect_Button.config(text='Записать изменения')
    # Переключаем кнопку обратно на "Редактировать"
    elif var_edit == 1:
        c2.config(state='normal')  # Активируем checkbox
        c2.deselect()
        c1.deselect()  # Снимаем флажок checkbox
        connect_Button.config(text='Подключить')
        editPath.config(state="normal")
        editFolder.config(state="normal")
        editName.config(state="normal")
        editPassword.config(state="normal")
        editDomain.config(state="normal")
        clear_edit()
        lab_mark = ''
        label_mark.config(text='', bg='#708090')
        editButton.config(text='Редактировать список')
        var_edit = 0
        delButton.pack_forget()



def open_auto_samba():
    f = open(p_autosamba, 'r')
    lineFile = f.readlines()  # Читаем номер строки из файла
    f.close()
    return lineFile


def on_select(*self):
    global list_number
    global status_folder
    try:
        list_number = number_list()
        find_folder_name = re.findall(r'share\/(.*)', listB.get(list_number))  # Регулярка поиска каталога
        if os.path.exists('/mnt/share/' + find_folder_name[0] + '/'):  # Проверка существования каталога (возвращает True/False)
           lable_status_folder.config(text='Доступен ;)')
           lable_status_folder.config(bg='green')
        else:
            lable_status_folder.config(text='Не доступен :(')
            lable_status_folder.config(bg='#708090')
        # Вызов функции заполнения полей
        if lab_mark == 'Редактирование списка!':
            get_params_in_to_edit()
    except:
          pass


''''
    -------Создаем фреймы--------
'''
root = Tk()
# Настройки главного окна
# Указываем фоновый цвет
root['bg'] = '#fafafa'
# Указываем название окна
root.title('Подключение сетевого каталога')
# Указываем размеры окна и положение в центре
# root.eval('tk::PlaceWindow %s center' % root.winfo_pathname(root.winfo_id()))
root.geometry("550x450+300+300")
# Делаем невозможным менять размеры окна
root.resizable(width=False, height=False)

root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)


def chek_status_domain():
    if var2.get() == True:
        clear_edit()
        editName.config(state="readonly")
        editPassword.config(state="readonly")
        editDomain.config(state="readonly")
    else:
        clear_edit()
        editName.config(state="normal")
        editPassword.config(state="normal")
        editDomain.config(state="normal")


# Фрейм переключателей
var1 = BooleanVar()
var2 = BooleanVar()

frame_lable = Frame(root, bd=5)
frame_lable.grid(row=0, sticky="we")

c1 = Checkbutton(frame_lable, text="smb v1", variable=var1, onvalue=1, offvalue=0)
c1.place(relx=0, rely=0.5)
c1.grid(row=0, column=0, sticky="e")

# Переключатель домена
c2 = Checkbutton(frame_lable, text="Если ПК в домене", variable=var2, onvalue=1, offvalue=0, command=chek_status_domain)
c2.place(relx=0, rely=0.5)
c2.grid(row=0, column=0, sticky="w")


# Label path
Label(frame_lable, text="Укажите сетевой путь в формате: ServerName/share/myfolder").grid(row=1)
# Создаем текстовое поле "сетевой путь"
editPath = Entry(frame_lable, bg='white', bd=2, font=25, width=53)
editPath.grid(row=2, column=0)


# --------Фрейм c grid--------
frame_top = Frame(root, bd=4)
frame_top.grid(row=1, sticky="nswe")

# name mount path
lableFolder = Label(frame_top, text="        Каталог монтирования /mnt/share/").grid(row=2, column=0, padx=15)
# Name folder
editFolder = Entry(frame_top, bg='white', bd=2, font=25, width=20)
editFolder.grid(row=2, column=1, sticky="e")

# Label name
labelName = Label(frame_top, text="Имя пользователя: ").grid(row=3, column=0, sticky="e", padx=10)
# Edit name
editName = Entry(frame_top, bg='white', bd=2, font=25, width=20)
editName.grid(row=3, column=1)

# Label password
labelPassword = Label(frame_top, text="Пароль пользователя: ").grid(row=4, column=0, sticky="e", padx=10)


# Edit password
editPassword = Entry(frame_top, bg='white', bd=2, font=25, width=20)
editPassword.config(show='*')
editPassword.grid(row=4, column=1)


# label domain
a = StringVar()
labelDomain = Label(frame_top, textvariable=a).grid(row=5, column=0, sticky="e", padx=10)
a.set('Имя домена или рабочей группы : ')
# Edit domain
editDomain = Entry(frame_top, bg='white', bd=2, font=25, width=20)
editDomain.grid(row=5, column=1)

# Проверка существования иконки
if os.path.isfile(path_icon):
    photo = ImageTk.PhotoImage(Image.open(path_icon))
    size_button = 180
else:
    photo = None
    size_button = 22

# Создаём кнопку "Подключить"
Label(frame_top, text='').grid(row=6, column=1)
connect_Button = Button(frame_top, bd=2, bg='#F0F8FF', image=photo,  text='Подключить', command=attach_folder,
       compound=LEFT, width=size_button)
connect_Button.grid(row=6, column=1, pady=4)

# -------Фрейм Listbox--------
frame_list = Frame(root, bd=8)
frame_list.place(relx=0, rely=0.51, relwidth=1, height=150)
labelB = Label(frame_list, text="Список подключенных сетевых каталогов:").pack()

listB = Listbox(frame_list, bg='white', width=70, height=7, bd=2)
scroll = Scrollbar(frame_list, orient="vertical")
scroll.config(command=listB.yview)
listB.config(yscrollcommand=scroll.set)

scroll.pack(side=RIGHT, fill='y')
listB.pack()
listB.bind('<<ListboxSelect>>', on_select)  # Событие когда выбран элемент listbox

# --------Фрейм list--------
frame_list = Frame(root, bd=4, bg='#708090')
frame_list.place(relx=0, rely=0.84, relwidth=1, height=50)

label_mark = Label(frame_list, text=lab_mark, bg='#708090')
label_mark.pack(side=LEFT, padx=6)

# Кнопка редактирования
editButton = Button(frame_list, text='Редактировать список', command=edit_mount)
editButton.pack(side=RIGHT, padx=6)

# Кнопка удаления
delButton = Button(frame_list, text='Отключить сетевой каталог', command=del_mount)
delButton.pack(side=RIGHT)
delButton.pack_forget()  # скрываем кнопку

# --------Фрейм lable статус--------
lable_status_folder = Frame(root, bd=2)
lable_status_folder.place(relx=0, rely=0.95, relwidth=1, height=22)
lable_status_folder = Label(lable_status_folder, text=status_folder, bg='#708090')
lable_status_folder.pack(side=RIGHT, padx=6)


# Парсинг конфига
def update_listbox():
    if os.path.isfile(p_autosamba):  # Если конфиг существует
        listB.configure(state='normal')
        listB.delete(0, END)
        #   listB.configure(state='disabled')

        str_file = open_auto_samba()
        i = 0
        try:
            for item in str_file:
                m_folder = re.findall(r'\w+', str_file[i])  # Поиск первого слова(имя каталога)
                str_path = re.findall(r'(:.+)$', str_file[i])
                str_list = ', '.join(map(str, str_path)) + '    ->    /mnt/share/' + m_folder[0]
                listB.insert(END, str_list)
                i += 1
        except:
            pass

    else:
        f = open(p_autosamba, "w")
        f.write('')
        f.close()
        clear_edit()


if os.geteuid() == 0:
    update_listbox()
    root.mainloop()  # Запускаем постоянный цикл
if not os.geteuid() == 0:
    root.withdraw()
    messagebox.showinfo('Error', 'Запустите программу от пользователя root')
