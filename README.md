# S-DES 加密解密系统开发手册

## 项目概述
本系统基于 S-DES 算法，使用 C++/QT 语言开发加密模块，使用 Python 语言开发解密模块。系统支持用户图形界面（GUI）交互，通过加密和解密功能保障数据安全。

## 1. 系统架构
系统主要由两个部分组成：
- **加密模块**（C++/QT）
- **解密模块**（Python）

## 2. 开发手册

### 2.1 接口定义

#### 2.1.1 C++/QT 加密模块

##### 2.1.1.1 函数：

- **描述**：实现 S-DES 加密和解密的核心类。

1. **on_pushButton_clicked()**
   - **功能**：处理用户点击按钮后的操作。
   - **流程**：
     - 获取明文和密钥。
     - 验证输入的二进制格式和长度。
     - 若是 ASCII 字符串，自动转换成二进制进行分块加密。
     - 调用 `encrypt` 函数执行加密，最后输出结果。

2. **encrypt(const QString &plaintext, const QString &key)**
   - **功能**：执行加密操作。
   - **步骤**：
     - 生成两个 8 位密钥 k1 和 k2。
     - 执行初始置换，进行两轮加密运算。
     - 返回最终的密文。

3. **keyGeneration(const QString &key)**
   - **功能**：根据 10 位密钥生成两个 8 位的密钥。
   - **步骤**：
     - 执行 P10 置换。
     - 左移操作生成 K1 和 K2。
     - 执行 P8 置换得到最终密钥。

4. **applyInitialPermutation(const QString &input)**
   - **功能**：进行初始置换操作。

5. **fFunction(const QString &right, const QString &key)**
   - **功能**：执行轮函数，包含扩展、异或、S-Box 替换和 P-Box 置换。

6. **sBoxSubstitution(const QString &input)**
   - **功能**：进行 S-Box 替换。

7. **toBinary(const QString& input)**
   - **功能**：将 ASCII 字符串转换为二进制字符串。

8. **toAsciiString(const QString &binary)**
   - **功能**：将二进制字符串转换回 ASCII 字符串。

9. **isBinaryString(const QString& str)**
   - **功能**：判断输入的字符串是否为有效的二进制字符串（仅包含 0 和 1）。

10. **binaryToDecimal(const QString &binary, bool *ok)**
    - **功能**：将二进制字符串转换为十进制整数。

**注意事项**：
- 输入验证：确保用户输入的明文和密钥长度符合要求，否则程序会显示提示信息。
- 只读输出：加密后的结果在输出框中为只读状态，用户无法修改。
- 错误处理：在转换和加密过程中，若出现输入格式错误或其他异常，程序会提示用户并终止操作。

#### 2.1.2 Python 解密模块

##### 2.1.2.1 函数：`sdes_encrypt`

- **`def sdes_encrypt(plaintext, key):`**
  - **描述**：对输入的明文进行 S-DES 加密。
  - **参数**：
    - `plaintext`: 8-bit 的明文字符串。
    - `key`: 10-bit 的密钥字符串。
  - **返回值**：加密后的密文字符串（8-bit）。

##### 2.1.2.2 函数：`sdes_decrypt`

- **`def sdes_decrypt(ciphertext, key):`**
  - **描述**：对输入的密文进行 S-DES 解密。
  - **参数**：
    - `ciphertext`: 8-bit 的密文字符串。
    - `key`: 10-bit 的密钥字符串。
  - **返回值**：解密后的明文字符串（8-bit）。

### 2.2 常量定义

- **P10**: (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
- **P8**: (6, 3, 7, 4, 8, 5, 10, 9)
- **IP**: (2, 6, 3, 1, 4, 8, 5, 7)
- **IP-inverse**: (4, 1, 3, 5, 7, 2, 8, 6)
- **EPBox**: (4, 1, 2, 3, 2, 3, 4, 1)
- **SBox1**: [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
- **SBox2**: [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

### 2.3 GUI 设计

- **界面元素**：
  - 输入框：用于输入明文和密钥。
  - 加密按钮：触发加密操作，显示结果。
  - 解密按钮：触发解密操作，显示结果。
  - 输出框：显示加密或解密后的结果。

## 3 实现过程

### 3.1 第1关：基本测试
- **目标**：实现 S-DES 算法的基本解密功能，支持用户交互。
  
**实现步骤**：
1. **创建 GUI 界面**：使用 `tkinter` 创建一个窗口，包含输入框和解密按钮。
2. **用户输入**：获取用户输入的8位密文和10位密钥。
3. **格式验证**：确保输入格式正确，密文为8位，密钥为10位。
4. **调用解密函数**：
   - 使用 `key_expansion` 函数生成密钥。
   - 使用 `sdes_decrypt` 函数进行解密，返回明文。
5. **展示结果**：使用弹窗显示解密结果。

**重要函数**：
- `permute(bits, perm)`: 用于位重排。
- `key_expansion(key)`: 扩展10位密钥为两组8位密钥。
- `sdes_decrypt(ciphertext, key)`: 采用 S-DES 算法解密密文。

---

#### 3.2 第2关：交叉测试
- **目标**：确保不同组的实现可以互相解密。
  
**实现步骤**：
1. **标准化算法**：确保 A 组和 B 组都使用相同的 `P-Box` 和 `S-Box`。
2. **加密和解密**：
   - A组使用密钥和明文进行加密。
   - B组使用相同的密钥对 A组的密文进行解密。
3. **验证结果**：确保 B组解密后结果与 A组的明文一致。

**重要函数**：
- `f_function(right, key)`: S-DES 的功能函数，涉及扩展、异或和 S-Box 处理。

---

#### 3.3 第3关：扩展功能
- **目标**：支持 ASCII 编码字符串的解密。

**实现步骤**：
1. **ASCII 转二进制**：
   - 实现 `ascii_to_binary(ascii_string)` 函数，将 ASCII 字符串转换为二进制字符串。
2. **二进制转 ASCII**：
   - 实现 `binary_to_ascii(binary_string)` 函数，将解密后的二进制结果转换为 ASCII 字符串。
3. **修改解密逻辑**：
   - 在解密过程中，接收 ASCII 输入并转换为二进制，然后进行 S-DES 解密。

**重要函数**：
- `ascii_to_binary(ascii_string)`: 将 ASCII 字符串转换为二进制。
- `binary_to_ascii(binary_string)`: 将二进制字符串转换为 ASCII。

---

#### 3.4 第4关：暴力破解
- **目标**：使用暴力破解的方法找到正确的密钥。

**实现步骤**：
1. **密钥生成**：使用 `generate_keys()` 函数生成所有可能的10位二进制密钥。
2. **暴力解密**：
   - 使用 `brute_force_decrypt(ciphertext, plaintext)` 函数尝试每个密钥进行解密。
   - 如果解密结果匹配已知明文，则记录下该密钥。
3. **多线程优化**：利用多线程技术提升解密效率，使用 `Thread` 来并行处理多个密钥尝试。

**重要函数**：
- `generate_keys()`: 生成所有可能的10位密钥。
- `brute_force_decrypt(ciphertext, plaintext)`: 尝试所有密钥解密，寻找匹配的明文。

---

#### 3.5 第5关：封闭测试
- **目标**：分析是否存在多个密钥对应同一明文。

**实现步骤**：
1. **选择明文密文对**：随机选择一对明文和密文。
2. **暴力破解**：使用前面的暴力破解功能，找到所有可能的密钥。
3. **验证结果**：检查是否存在多个密钥能够加密相同的明文，记录结果。

**重要函数**：
- `brute_force_decrypt(ciphertext, plaintext)`: 不只查找一个密钥，记录所有匹配的密钥。

---

### 总结
每一关都围绕 S-DES 解密算法逐步扩展，设计了不同的功能和挑战。关键的函数和逻辑步骤已在每一关中详细描述，以便于理解和实现。开发者可以根据这些指导逐步构建和测试解密器。

## 4. 依赖环境

- **C++/QT**: 确保安装了 QT 开发环境。
- **Python**: 确保安装了 Python 及所需库（如 `numpy` 或其他）。

## 5. 测试

- 为每个方法编写单元测试，确保加密和解密过程符合 S-DES 算法的要求。
- 测试边界条件，如最小和最大输入。

## 6. 参考文献

- S-DES 算法相关文献及文档。
- C++/QT 开发文档。
- Python 编程指南。
