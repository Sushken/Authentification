from tkinter import *
from tkinter import filedialog as fd
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from auth import Authentication

from tkinter import *
from tkinter import messagebox

root = Tk()
root.geometry('300x500')
root.title('Войти в систему')

auth = Authentication(len_key=448, file_name='Include/DB.json')

frame_start = Frame(root)

frame_start.pack()

text_start = Label(master=frame_start, text='Выберите действие')
Button_reg = Button(master=frame_start, text='Зарегистрироваться', command=lambda: registrarion())
Button_log = Button(master=frame_start, text='Войти', command=lambda: login())
text_start.pack()
Button_reg.pack()
Button_log.pack()

frame_reg = Frame(root)
text = Label(master=frame_reg, text='Для входа в систему - зарегистрируйтесь!')
text_log = Label(master=frame_reg, text='Введите логин :')
registr_login = Entry(master=frame_reg)
text_password1 = Label(master=frame_reg, text='Введите свой пароль :')
registr_password1 = Entry(master=frame_reg, show='*')
# text_password2 = Label(master=frame_reg, text='Еще раз пароль :')
# registr_password2 = Entry(master=frame_reg, show='*')
Button_registr = Button(master=frame_reg, text='Зарегистрироваться', command=lambda: save())
text.pack()
text_log.pack()
registr_login.pack()
text_password1.pack()
registr_password1.pack()
# text_password2.pack()
# registr_password2.pack()
Button_registr.pack()

frame_login = Frame(root)

text_login = Label(master=frame_login, text='Вы можете войти в систему')
text_enter_login = Label(master=frame_login, text='Введите свой логин:')
enter_login = Entry(master=frame_login)
text_enter_password = Label(master=frame_login, text='Введите ваш пароль:')
enter_password = Entry(master=frame_login, show='*')
Button_enter = Button(master=frame_login, text='Войти:', command=lambda: log_pass())
text_login.pack()
text_enter_login.pack()
enter_login.pack()
text_enter_password.pack()
enter_password.pack()
Button_enter.pack()


def registrarion():
    frame_start.forget()
    frame_reg.pack()
    frame_login.forget()


def login():
    frame_start.forget()
    frame_reg.forget()
    frame_login.pack()


def save():
    if auth.createUser(registr_login.get(),registr_password1.get()):
        messagebox.showerror('Ошибка', 'Пользователь существует')
    else:
        messagebox.showinfo('ОК', 'Пользователь создан')

    login()


def log_pass():
    if auth.check(enter_login.get(),enter_password.get()):
        messagebox.showinfo('вход выполнен', 'Привет')
    else:
        messagebox.showerror('Ошибка', 'Ввели неверный логин или пароль')


root.mainloop()