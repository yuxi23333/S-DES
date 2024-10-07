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


def ascii_to_binary(ascii_string):
    return ''.join(format(ord(char), '08b') for char in ascii_string)


def binary_to_ascii(binary_string):
    chars = []
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i + 8]
        if len(byte) < 8:
            byte = byte.ljust(8, '0')  # 填充不足的部分
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)


def decrypt():
    try:
        ascii_ciphertext = entry_ciphertext.get()
        key = entry_key.get()

        if len(key) != 10:
            raise ValueError("请输入10位密钥")

        # 将ASCII字符串转为二进制
        ciphertext = ascii_to_binary(ascii_ciphertext)

        if len(ciphertext) == 0:
            raise ValueError("输入的ASCII密文不能为空")

        key_bits = list(map(int, key))

        # 每8位进行一次解密
        plaintext = []
        for i in range(0, len(ciphertext), 8):
            segment = ciphertext[i:i + 8]
            # 解密每个8位段
            if len(segment) < 8:
                segment = segment.ljust(8, '0')  # 填充不足的部分
            ciphertext_bits = list(map(int, segment))
            plaintext_bits = sdes_decrypt(ciphertext_bits, key_bits)
            plaintext.append(plaintext_bits)

        # 将解密结果转为ASCII
        plaintext_ascii = binary_to_ascii(''.join(plaintext))
        messagebox.showinfo("解密结果", f"明文: {plaintext_ascii}")

    except Exception as e:
        messagebox.showerror("错误", str(e))


# 创建 GUI 界面
root = tk.Tk()
root.title("S-DES 解密器")

# 输入密文
label_ciphertext = tk.Label(root, text="输入ASCII密文:")
label_ciphertext.pack()
entry_ciphertext = tk.Entry(root)
entry_ciphertext.pack()

# 输入密钥
label_key = tk.Label(root, text="输入密钥 (10位):")
label_key.pack()
entry_key = tk.Entry(root)
entry_key.pack()

# 解密按钮
button_decrypt = tk.Button(root, text="解密", command=decrypt)
button_decrypt.pack()

# 运行主循环
root.mainloop()
