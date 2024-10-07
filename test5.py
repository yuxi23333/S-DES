import tkinter as tk
from tkinter import messagebox

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

def sdes_encrypt(plaintext, key):
    k1, k2 = key_expansion(key)

    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    plaintext = permute(plaintext, ip)

    left, right = plaintext[:4], plaintext[4:]

    right_f1 = f_function(right, k1)
    left = [left[i] ^ right_f1[i] for i in range(4)]

    left, right = right, left

    right_f2 = f_function(right, k2)
    left = [left[i] ^ right_f2[i] for i in range(4)]

    combined = left + right

    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    ciphertext = permute(combined, ip_inv)

    return ciphertext

def find_collisions(plaintext):
    seen_ciphertexts = {}
    collisions = []

    for key in range(1024):  # 2^10 = 1024
        key_bits = [int(bit) for bit in format(key, '010b')]
        ciphertext = sdes_encrypt(plaintext, key_bits)

        ciphertext_str = ''.join(map(str, ciphertext))

        if ciphertext_str in seen_ciphertexts:
            collisions.append((seen_ciphertexts[ciphertext_str], key_bits, ciphertext_str))
        else:
            seen_ciphertexts[ciphertext_str] = key_bits

    return collisions

def start_collision_check():
    plaintext = list(map(int, entry_plaintext.get()))
    collisions = find_collisions(plaintext)

    if collisions:
        results = "\n".join([f"密钥1: {''.join(map(str, k1))}, 密钥2: {''.join(map(str, k2))}, 密文: {c}"
                             for k1, k2, c in collisions])
        messagebox.showinfo("发现碰撞", results)
    else:
        messagebox.showinfo("结果", "未发现碰撞。")

# 创建 GUI 界面
root = tk.Tk()
root.title("S-DES 碰撞检测器")

# 输入明文
label_plaintext = tk.Label(root, text="输入明文 (8位):")
label_plaintext.pack()
entry_plaintext = tk.Entry(root)
entry_plaintext.pack()

# 开始检测按钮
button_check = tk.Button(root, text="开始检测碰撞", command=start_collision_check)
button_check.pack()

# 运行主循环
root.mainloop()
