#!/usr/bin/python
# -*- coding: utf-8 -*-

from tkinter import *
from tkinter import messagebox
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import hashlib
import sqlite3


programm_password = 0

class Main:
    URL_list = []
    login_list = []
    password_list = []
    copy_button1 =[]
    copy_button2 = []
    show_button = []
    delete_button = []
    y = 2
    index = 0

    def __init__(self, master):
        self.master = master
        self.master.title('Password manager')
        self.master.geometry('700x450')

        self.canvas = Canvas(self.master)
        self.scroll_y = Scrollbar(self.master, orient="vertical", command=self.canvas.yview)
        self.frame = Frame(self.canvas)

        self.img_eye = PhotoImage(file="eye.png")
        self.img_del = PhotoImage(file='del.png')
        self.img_copy = PhotoImage(file='copy.png')

        self.url_entry = Entry(self.frame, width=20)
        self.url_entry.grid(row=1,column=1, padx=5, pady=7)
        self.url_entry.insert(0, "to enter a URL")

        self.login_entry = Entry(self.frame, width=30)
        self.login_entry.grid(row=1,column=2, padx=5, pady=7)
        self.login_entry.insert(0, "to enter a login")

        self.password_entry = Entry(self.frame, width=30)
        self.password_entry.grid(row=1, column=4, padx=5, pady=7)
        self.password_entry.insert(0, "to enter a password")

        self.button = Button(self.frame, text = 'add', command = self.save)
        self.button.grid(row=1, column=6)
       
        self.display_data()

        self.canvas.create_window(0, 0, anchor='nw', window=self.frame)
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox('all'), 
                         yscrollcommand=self.scroll_y.set)
                         
        self.canvas.pack(fill='both', expand=True, side='left')
        self.scroll_y.pack(fill='y', side='right')

        GetPassword(self.master)
        self.master.mainloop()


    def save(self):
        if programm_password == 0:
            messagebox.showerror("Error!", "to enter a password!")
            GetPassword(self.master)
            return
        url = self.url_entry.get()
        login = self.login_entry.get()
        password = self.password_entry.get()
        login, password, salt = Crypto.encrypt(login, password)
        SaveData(url, login, password, salt)
        conn = sqlite3.connect('mybd.db')
        c = conn.cursor()
        data = c.execute("SELECT MAX(id), website FROM keys LIMIT 1")

        self.drawing(data)

        conn.commit()
        conn.close()
        if self.y > 16:
            self.canvas.update_idletasks()
            self.canvas.configure(scrollregion=self.canvas.bbox('all'), 
                             yscrollcommand=self.scroll_y.set)
                             
            self.canvas.pack(fill='both', expand=True, side='left')
            self.scroll_y.pack(fill='y', side='right')


    def show(self, idstr):
        ids=int(idstr[0])
        if programm_password == 0:
            messagebox.showerror("Error!", "to enter a password!")
            GetPassword(self.master)
            return
        conn = sqlite3.connect('mybd.db')
        c = conn.cursor()
        data = c.execute("SELECT login, passwords, salt FROM keys WHERE id=?", ([ids]))
        for x in data:
            login = x[0]
            password = x[1]
            salt = x[2]
            log, pas = Crypto.decrypt(login, password, salt)

            login_entry = self.login_list[idstr[1]]
            password_entry = self.password_list[idstr[1]]
            login_entry.delete(0, END)
            password_entry.delete(0, END)
            login_entry.insert(0, log)
            password_entry.insert(0,pas)

        conn.commit()
        conn.close()


    def delete_entry(self, idstr):
        ids=int(idstr[0])
        if programm_password == 0:
            messagebox.showerror("Error!", "to enter a password!")
            GetPassword(self.master)
            return

        conn = sqlite3.connect('mybd.db')
        c = conn.cursor()
        data = c.execute("DELETE FROM keys WHERE id = ?", ([ids]))
        conn.commit()
        conn.close()

        URL_entry = self.URL_list[idstr[1]]
        login_entry = self.login_list[idstr[1]]
        password_entry = self.password_list[idstr[1]]
        copy1 = self.copy_button1[idstr[1]]
        copy2 = self.copy_button2[idstr[1]]
        show = self.show_button[idstr[1]]
        delete = self.delete_button[idstr[1]]
        URL_entry.grid_remove()
        login_entry.grid_remove()
        password_entry.grid_remove()
        copy1.grid_remove()
        copy2.grid_remove()
        show.grid_remove()
        delete.grid_remove()


    def copy_login(self, idstr):
        login_entry = self.login_list[idstr[1]]
        login_entry.clipboard_clear()       
        log = login_entry.get()
        login_entry.clipboard_append(log)


    def copy_password(self, idstr):
        password_entry = self.password_list[idstr[1]]
        password_entry.clipboard_clear()
        pas = password_entry.get()
        password_entry.clipboard_append(pas)


    def display_data(self):
        conn = sqlite3.connect('mybd.db')
        c = conn.cursor()
        try:
            data = c.execute("SELECT id, website FROM keys")
            self.drawing(data)

        except sqlite3.OperationalError:
            c.execute('''CREATE TABLE keys (id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT, login BLOB, passwords BLOB, salt BLOB)''')

        conn.commit()
        conn.close()

    def drawing(self, data):
        for x in data:
            idstr = x[0],self.index
            website = x[1]

            entry_URL = Entry(self.frame, width=20)
            entry_URL.grid(row=self.y,column=1, padx=5)
            entry_URL.insert(0, website)
            entry_URL.configure(state="disable")
            self.URL_list.append(entry_URL)

            entry_login = Entry(self.frame, width=30)
            entry_login.grid(row=self.y,column=2, padx=5)
            entry_login.insert(0, "*******")
            self.login_list.append(entry_login)

            entry_password = Entry(self.frame, width=30)
            entry_password.grid(row=self.y, column=4, padx=5)
            entry_password.insert(0,"*******")
            self.password_list.append(entry_password)

            button_copy_login = Button(self.frame, image=self.img_copy,
                             command=lambda idstr=idstr: self.copy_login(idstr))
            button_copy_login.grid(row=self.y, column=3,padx=5)
            self.copy_button1.append(button_copy_login)

            button_copy_password = Button(self.frame, image=self.img_copy,
                             command=lambda idstr=idstr: self.copy_password(idstr))
            button_copy_password.grid(row=self.y, column=5,padx=5)
            self.copy_button2.append(button_copy_password)

            button_show = Button(self.frame, image=self.img_eye,
                             command=lambda idstr=idstr: self.show(idstr))
            button_show.grid(row=self.y, column=6,padx=5)
            self.show_button.append(button_show)

            button_delete = Button(self.frame, image=self.img_del,
                             command=lambda idstr=idstr: self.delete_entry(idstr))
            button_delete.grid(row=self.y, column=7,padx=5)
            self.delete_button.append(button_delete)

            self.y+=1
            self.index+=1


class GetPassword:
    def __init__(self, master):
        self.slave = Toplevel()
        self.slave.grab_set()
        self.slave.title('Enter master password')
        self.slave.resizable(False, False)
        self.btn_cancel = Button(self.slave, text = 'OK', width = 10, command = self.cancel)
        self.password_entry = Entry(self.slave, width=45)
        self.password_entry.grid(row=0, column=1, padx=10, pady=10,columnspan=3)
        self.btn_cancel.grid(row=1, column=2, pady=10, padx=10)


    def cancel(self):
        global programm_password
        programm_password = self.password_entry.get()
        if 0 == len(programm_password):
            messagebox.showerror("Error!", "to enter a password!")
        else:
            self.slave.destroy()


class SaveData:
    url: str
    login: bytes
    password: bytes
    salt: bytes

    def __init__(self, url, login, password, salt):
        self.url = url
        self.login = login
        self.password = password
        self.salt = salt
        self.save()

    def save(self):
        conn = sqlite3.connect('mybd.db')
        c = conn.cursor()
        c.execute("INSERT INTO keys (website, login, passwords, salt) VALUES (?,?,?,?)",(self.url,self.login,self.password,self.salt))
        conn.commit()
        conn.close()


class Crypto:

    def encrypt(login, password):
        login = bytes(login, encoding = 'utf-8')
        password = bytes(password, encoding = 'utf-8')
        salt = get_random_bytes(AES.block_size)
        key = hashlib.scrypt(programm_password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(key, AES.MODE_CBC, salt)
        crypto_login = cipher.encrypt(pad(login, 32))
        crypto_password = cipher.encrypt(pad(password, 32))
        return crypto_login, crypto_password, salt

    def decrypt(login, password, salt):
        key = hashlib.scrypt(programm_password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(key, AES.MODE_CBC, salt)
        try:
            login = unpad(cipher.decrypt(login), 32)
            password = unpad(cipher.decrypt(password), 32)
            return str(login,encoding='utf-8'), str(password,encoding='utf-8')

        except ValueError:
            messagebox.showerror("Error!", "wrong password!")
            return "*******", "*******"


root = Tk()

Main(root) 
