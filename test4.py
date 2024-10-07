import tkinter as tk
from tkinter import messagebox
from threading import Thread
import time

def permute(bits, perm):
    return [bits[i - 1] for i in perm]

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def key_expansion(key):
    p10_perm = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8_perm = [6, 3, 7, 4, 8, 5, 10, 9]
    key = permute(key, p10_perm)

    k1 = left_shift(key[:5], 1) + left_shift(key[5:], 1)
    k1 = permute(k1, p8_perm)

    k2 = left_shift(key[:5], 2) + left_shift(key[5:], 2)
    k2 = permute(k2, p8_perm)

    return k1, k2

def f_function(right, key):
    ep_box = [4, 1, 2, 3, 2, 3, 4, 1]
    sbox1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    sbox2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
    sp_box = [2, 4, 3, 1]

    expanded_right = permute(right, ep_box)
    xor_result = [expanded_right[i] ^ key[i] for i in range(8)]

    row1 = (xor_result[0] << 1) + xor_result[3]
    col1 = (xor_result[1] << 1) + xor_result[2]
    row2 = (xor_result[4] << 1) + xor_result[7]
    col2 = (xor_result[5] << 1) + xor_result[6]

    sbox_output = [sbox1[row1][col1], sbox2[row2][col2]]
    sbox_output = [int(b) for b in f'{sbox_output[0]:02b}' + f'{sbox_output[1]:02b}']

    return permute(sbox_output, sp_box)

def sdes_decrypt(ciphertext, key):
    k1, k2 = key_expansion(key)

    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    ciphertext = permute(ciphertext, ip)

    left, right = ciphertext[:4], ciphertext[4:]

    right_f1 = f_function(right, k2)
    left = [left[i] ^ right_f1[i] for i in range(4)]

    left, right = right, left

    right_f2 = f_function(right, k1)
    left = [left[i] ^ right_f2[i] for i in range(4)]

    combined = left + right

    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    plaintext = permute(combined, ip_inv)

    return ''.join(map(str, plaintext))

def generate_keys():
    for key in range(1024):  # 2^10 = 1024
        yield [int(bit) for bit in format(key, '010b')]

def brute_force_decrypt(ciphertext, plaintext):
    matching_keys = []
    for key in generate_keys():
        decrypted_text = sdes_decrypt(ciphertext, key)
        if decrypted_text == plaintext:
            matching_keys.append(key)
    return matching_keys

def start_brute_force():
    ciphertext = list(map(int, entry_ciphertext.get()))
    plaintext = entry_plaintext.get()

    start_time = time.time()
    result_keys = brute_force_decrypt(ciphertext, plaintext)
    elapsed_time = time.time() - start_time

    if result_keys:
        keys_str = ', '.join([''.join(map(str, key)) for key in result_keys])
        messagebox.showinfo("破解成功", f"找到密钥: {keys_str}，耗时: {elapsed_time:.2f}秒")
    else:
        messagebox.showinfo("破解失败", "未找到密钥。")

def threaded_brute_force():
    thread = Thread(target=start_brute_force)
    thread.start()

# 创建 GUI 界面
root = tk.Tk()
root.title("S-DES 暴力破解器")

# 输入密文
label_ciphertext = tk.Label(root, text="输入密文 (8位):")
label_ciphertext.pack()
entry_ciphertext = tk.Entry(root)
entry_ciphertext.pack()

# 输入明文
label_plaintext = tk.Label(root, text="输入已知明文:")
label_plaintext.pack()
entry_plaintext = tk.Entry(root)
entry_plaintext.pack()

# 开始破解按钮
button_break = tk.Button(root, text="开始暴力破解", command=threaded_brute_force)
button_break.pack()

# 运行主循环
root.mainloop()
