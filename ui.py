import ttkbootstrap as ttk
import tkinter as tk
from tkinter import *
from ttkbootstrap import StringVar
from aes import saes_encrypt
from aes import saes_decrypt
from ascii_aes import saes_encrypt_asc
from ascii_aes import saes_decrypt_asc
from multi_encryption import double_saes_encrypt
from multi_encryption import double_saes_decrypt
from multi_encryption import treble_saes_encrypt
from multi_encryption import treble_saes_decrypt

key = []
plaintext = []
ciphertext = []


# button1 得到第一次输入，并对不符合输入规范的操作进行提示
def getText1(input1, l_text, fn):
    if (fn == 0 or fn == 1 or fn == 3 or fn == 4):
        if (len(input1.get()) != 16):
            text = '输入密钥不符合16位规范'
            l_text.set(text)
            return
    elif(fn==5 or fn==6):
        if(len(input1.get())!=32):
            text = '输入密钥不符合32位规范'
            l_text.set(text)
            return
    elif (fn == 7 or fn == 8):
        if (len(input1.get()) != 48):
            text = '输入密钥不符合48位规范'
            l_text.set(text)
            return
    global key
    key = str(input1.get())
    input1.delete(0, "end")
    if (fn == 0 or fn==5 or fn ==7):
        text = '请输入16位明文。'
    elif (fn == 1 or fn==6 or fn==8):
        text = '请输入16位密文。'
    elif (fn == 3 or fn == 4):
        text = '请输入字符串'
        l_text.set(text)
        return


# button2 得到第二次输入，调用函数实现最终功能，并展现结果
def getText2(input1, l_text, fn):
    if (fn == 0):
        if (len(input1.get()) != 16):
            text = '输入明文不符合16位规范'
            l_text.set(text)
            return
        global plaintext
        plaintext = str(input1.get())
        plaintext_new = plaintext
        num1 = int(plaintext[0:4],2)
        num2 = int(plaintext[4:8],2)
        num3 = int(plaintext[8:12], 2)
        num4 = int(plaintext[12:16], 2)
        plaintext=[[num1,num2],[num3,num4]]
        print(plaintext)
        ciphertext1 = saes_encrypt(plaintext, key)
        c1 = "{:0>4d}".format(int(bin(ciphertext1[0][0])[2:]))
        c2 = "{:0>4d}".format(int(bin(ciphertext1[0][1])[2:]))
        c3 = "{:0>4d}".format(int(bin(ciphertext1[1][0])[2:]))
        c4 = "{:0>4d}".format(int(bin(ciphertext1[1][1])[2:]))
        ciphertext1 = c1 + c2 + c3 + c4
        str1 = plaintext_new
        str2 = ciphertext1
        text = '明文为：' + str1 + ' 密文为' + str2
        print(text)
        l_text.set(text)
        input1.delete(0, "end")
        return
    elif (fn == 1):
        if (len(input1.get()) != 16):
            text = '输入密文不符合16位规范'
            l_text.set(text)
            return
        global ciphertext
        ciphertext = str(input1.get())
        ciphertext_new = ciphertext
        num1 = int(ciphertext[0:4], 2)
        num2 = int(ciphertext[4:8], 2)
        num3 = int(ciphertext[8:12], 2)
        num4 = int(ciphertext[12:16], 2)
        ciphertext = [[num1, num2], [num3, num4]]
        plaintext1 = saes_decrypt(ciphertext, key)
        c1 = "{:0>4d}".format(int(bin(plaintext1[0][0])[2:]))
        c2 = "{:0>4d}".format(int(bin(plaintext1[0][1])[2:]))
        c3 = "{:0>4d}".format(int(bin(plaintext1[1][0])[2:]))
        c4 = "{:0>4d}".format(int(bin(plaintext1[1][1])[2:]))
        str1 = c1 + c2 + c3 + c4
        str2 = ciphertext_new
        text = '明文为：' + str1 + ' 密文为' + str2
        l_text.set(text)
        print(text)
        input1.delete(0, "end")
        return
    elif (fn == 3):
        plaintext2 = input1.get()
        if (len(plaintext2) == 0):
            text = '输入不能为空'
            l_text.set(text)
            return
        plaintext_char = list(plaintext2)

        text = saes_encrypt_asc(plaintext_char, key)
        text = "".join(text)
        text = '明文为：' + plaintext2 + ' 密文为：' + text
        l_text.set(text)
    elif (fn == 4):
        ciphertext2 = input1.get()
        if (len(ciphertext2) == 0):
            text = '输入不能为空'
            l_text.set(text)
            return
        ciphertext_char=list(ciphertext2)
        text = saes_decrypt_asc(ciphertext_char, key)
        text = "".join(text)
        text = '密文为：' + text + ' 明文为：' + ciphertext2
        l_text.set(text)
    elif (fn == 5):
        if (len(input1.get()) != 16):
            text = '输入明文不符合16位规范'
            l_text.set(text)
            return
        plaintext = str(input1.get())
        plaintext_new = plaintext
        num1 = int(plaintext[0:4],2)
        num2 = int(plaintext[4:8],2)
        num3 = int(plaintext[8:12], 2)
        num4 = int(plaintext[12:16], 2)
        plaintext=[[num1,num2],[num3,num4]]
        print(plaintext)
        ciphertext1 = double_saes_encrypt(plaintext, key)
        c1 = "{:0>4d}".format(int(bin(ciphertext1[0][0])[2:]))
        c2 = "{:0>4d}".format(int(bin(ciphertext1[0][1])[2:]))
        c3 = "{:0>4d}".format(int(bin(ciphertext1[1][0])[2:]))
        c4 = "{:0>4d}".format(int(bin(ciphertext1[1][1])[2:]))
        ciphertext1 = c1 + c2 + c3 + c4
        str1 = plaintext_new
        str2 = ciphertext1
        text = '明文为：' + str1 + ' 密文为' + str2
        print(text)
        l_text.set(text)
        input1.delete(0, "end")
        return
    elif (fn == 6):
        if (len(input1.get()) != 16):
            text = '输入密文不符合16位规范'
            l_text.set(text)
            return
        ciphertext = str(input1.get())
        ciphertext_new = ciphertext
        num1 = int(ciphertext[0:4], 2)
        num2 = int(ciphertext[4:8], 2)
        num3 = int(ciphertext[8:12], 2)
        num4 = int(ciphertext[12:16], 2)
        ciphertext = [[num1, num2], [num3, num4]]
        plaintext1 = double_saes_decrypt(ciphertext, key)
        c1 = "{:0>4d}".format(int(bin(plaintext1[0][0])[2:]))
        c2 = "{:0>4d}".format(int(bin(plaintext1[0][1])[2:]))
        c3 = "{:0>4d}".format(int(bin(plaintext1[1][0])[2:]))
        c4 = "{:0>4d}".format(int(bin(plaintext1[1][1])[2:]))
        str1 = c1 + c2 + c3 + c4
        str2 = ciphertext_new
        text = '明文为：' + str1 + ' 密文为' + str2
        l_text.set(text)
        print(text)
        input1.delete(0, "end")
        return
    elif (fn == 7):
        if (len(input1.get()) != 16):
            text = '输入明文不符合16位规范'
            l_text.set(text)
            return
        plaintext = str(input1.get())
        plaintext_new = plaintext
        num1 = int(plaintext[0:4],2)
        num2 = int(plaintext[4:8],2)
        num3 = int(plaintext[8:12], 2)
        num4 = int(plaintext[12:16], 2)
        plaintext=[[num1,num2],[num3,num4]]
        print(plaintext)
        ciphertext1 = treble_saes_encrypt(plaintext, key)
        c1 = "{:0>4d}".format(int(bin(ciphertext1[0][0])[2:]))
        c2 = "{:0>4d}".format(int(bin(ciphertext1[0][1])[2:]))
        c3 = "{:0>4d}".format(int(bin(ciphertext1[1][0])[2:]))
        c4 = "{:0>4d}".format(int(bin(ciphertext1[1][1])[2:]))
        ciphertext1 = c1 + c2 + c3 + c4
        str1 = plaintext_new
        str2 = ciphertext1
        text = '明文为：' + str1 + ' 密文为' + str2
        print(text)
        l_text.set(text)
        input1.delete(0, "end")
        return
    elif (fn == 8):
        if (len(input1.get()) != 16):
            text = '输入密文不符合16位规范'
            l_text.set(text)
            return
        ciphertext = str(input1.get())
        ciphertext_new = ciphertext
        num1 = int(ciphertext[0:4], 2)
        num2 = int(ciphertext[4:8], 2)
        num3 = int(ciphertext[8:12], 2)
        num4 = int(ciphertext[12:16], 2)
        ciphertext = [[num1, num2], [num3, num4]]
        plaintext1 = treble_saes_decrypt(ciphertext, key)
        c1 = "{:0>4d}".format(int(bin(plaintext1[0][0])[2:]))
        c2 = "{:0>4d}".format(int(bin(plaintext1[0][1])[2:]))
        c3 = "{:0>4d}".format(int(bin(plaintext1[1][0])[2:]))
        c4 = "{:0>4d}".format(int(bin(plaintext1[1][1])[2:]))
        str1 = c1 + c2 + c3 + c4
        str2 = ciphertext_new
        text = '明文为：' + str1 + ' 密文为' + str2
        l_text.set(text)
        print(text)
        input1.delete(0, "end")
        return
# 跳转页面
def create(fun):
    # 定义StringVar
    l_text = StringVar()
    # 初始化数据
    childW1 = Toplevel(frame)  # 创建子窗口
    childW1.geometry("600x400")
    if (fun == 0):
        text = "请输入16位密钥"
        l_text.set(text)
        childW1.title('二进制加密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 0))
        b2 = ttk.Button(childW1, text="确认明文", command=lambda: getText2(input1, l_text, 0))
    elif (fun == 1):
        text = "请输入16位密钥"
        l_text.set(text)
        childW1.title('二进制解密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 1))
        b2 = ttk.Button(childW1, text="确认密文", command=lambda: getText2(input1, l_text, 1))
    elif (fun == 3):
        text = "请输入16位密钥"
        l_text.set(text)
        childW1.title('ascii加密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 3))
        b2 = ttk.Button(childW1, text="确认明文", command=lambda: getText2(input1, l_text, 3))
    elif (fun == 4):
        text = "请输入16位密钥"
        l_text.set(text)
        childW1.title('ascii解密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 4))
        b2 = ttk.Button(childW1, text="确认密文", command=lambda: getText2(input1, l_text, 4))
    elif (fun == 5):
        text = "请输入32位密钥"
        l_text.set(text)
        childW1.title('双重加密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 5))
        b2 = ttk.Button(childW1, text="确认明文", command=lambda: getText2(input1, l_text, 5))
    elif (fun == 6):
        text = "请输入32位密钥"
        l_text.set(text)
        childW1.title('双重解密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 6))
        b2 = ttk.Button(childW1, text="确认密文", command=lambda: getText2(input1, l_text, 6))
    elif (fun == 7):
        text = "请输入48位密钥"
        l_text.set(text)
        childW1.title('三重加密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 7))
        b2 = ttk.Button(childW1, text="确认明文", command=lambda: getText2(input1, l_text, 7))
    elif (fun == 8):
        text = "请输入48位密钥"
        l_text.set(text)
        childW1.title('三重解密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 8))
        b2 = ttk.Button(childW1, text="确认密文", command=lambda: getText2(input1, l_text, 8))

    input1 = ttk.Entry(childW1, bootstyle="info", font=("微软雅黑", 12))
    input1.place(x=100, y=100)
    label = ttk.Label(childW1, textvariable=l_text, font=("微软雅黑", 12))
    label.place(x=100, y=150)
    b1.place(x=90, y=200)
    b2.place(x=250, y=200)

# 创建窗体
win = tk.Tk()
win.title("S-AES")
win.geometry("900x330")
win.resizable(False, False)  # 不允许改变窗口大小

# 创建一个容器来包括其他控件
frame = ttk.Frame(win)

frame.pack()

# 标题
title = ttk.Label(frame, text='Encryption & Decryption', font=("bold", 20), bootstyle='primary')
title.pack(padx=10, pady=20)
# 关卡提示
info = ttk.Label(frame, text='请选择相应关卡', bootstyle='warning', font=15)
info.pack(padx=10, pady=10)
# 按钮
b1 = ttk.Button(frame, text="二进制加密", command=lambda: create(0))
b1.pack(padx=7,pady=10, side='left')

b2 = ttk.Button(frame, text="二进制解密", command=lambda: create(1))
b2.pack(padx=7,pady=10, side='left')

b4 = ttk.Button(frame, text="ASCII加密", command=lambda: create(3))
b4.pack(padx=7,pady=10, side='left')

b5 = ttk.Button(frame, text="ASCII解密", command=lambda: create(4))
b5.pack(padx=7,pady=10, side='left')

b4 = ttk.Button(frame, text="双重加密", command=lambda: create(5))
b4.pack(padx=7,pady=20, side='left')

b6 = ttk.Button(frame, text="双重解密", command=lambda: create(6))
b6.pack(padx=7,pady=20, side='left')

b7 = ttk.Button(frame, text="三重加密", command=lambda: create(7))
b7.pack(padx=7,pady=20, side='left')

b8 = ttk.Button(frame, text="三重解密", command=lambda: create(8))
b8.pack(padx=7,pady=20, side='left')

frame.mainloop()
