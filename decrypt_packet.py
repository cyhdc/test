#!/usr/bin/env python3
"""
AES-GCM 数据包解密脚本

根据 main.js.txt 分析结果:
- 算法: AES-256-GCM (密钥为32字节) 或 AES-128-GCM (密钥为16字节hex解码)
- 密钥: "0123456789abcdef0123456789abcdef"
- IV/Nonce: 12字节，位于密文前
- 数据格式: Base64([12字节Nonce][加密数据][16字节Tag])

注意:
  密钥字符串通过 B.bq.cs() 函数转换为字节数组，
  这相当于 UTF-8 编码，即将字符串的每个字符转为对应的字节。

  但 JS 代码中也存在将此字符串作为 hex 解码的情况，
  因此本脚本支持两种模式:
  1. UTF-8 模式: 密钥为 32 字节 (AES-256)
  2. Hex 模式: 密钥为 16 字节 (AES-128)
"""

import base64
import sys
import os

try:
    from Crypto.Cipher import AES
except ImportError:
    print("请安装 pycryptodome: pip install pycryptodome")
    sys.exit(1)

# 硬编码的密钥字符串 (从 JS 文件中提取)
KEY_STRING = "0123456789abcdef0123456789abcdef"

# 两种密钥格式
KEY_UTF8 = KEY_STRING.encode('utf-8')  # 32字节密钥 (AES-256)
KEY_HEX = bytes.fromhex(KEY_STRING)     # 16字节密钥 (AES-128)


def decrypt_aes_gcm(encrypted_base64: str, key: bytes = None) -> str:
    """
    解密 AES-GCM 加密的数据包

    Args:
        encrypted_base64: Base64 编码的加密数据，格式为 [12字节Nonce][加密数据][16字节Tag]
        key: 解密密钥，默认使用 UTF-8 编码的密钥

    Returns:
        解密后的明文字符串
    """
    if key is None:
        key = KEY_UTF8  # 默认使用 UTF-8 模式

    try:
        # Base64 解码
        encrypted_data = base64.b64decode(encrypted_base64)

        # 检查最小长度 (12字节 nonce + 至少1字节密文 + 16字节 tag)
        if len(encrypted_data) < 12 + 1 + 16:
            raise ValueError(f"密文太短 ({len(encrypted_data)} 字节)，无法解密")

        # 提取 nonce (前12字节)
        nonce = encrypted_data[:12]

        # 提取密文和 tag
        # GCM 模式下，tag 通常是附加在密文末尾的 16 字节
        ciphertext_with_tag = encrypted_data[12:]

        # 最后16字节是 tag
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # 创建 AES-GCM 解密器
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # 解密并验证 tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode('utf-8')

    except ValueError as e:
        # 如果 tag 验证失败，尝试不验证 tag
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext_with_tag)
            # 去除末尾的 16 字节 tag (解密后的数据会包含它)
            return plaintext[:-16].decode('utf-8', errors='replace')
        except Exception:
            raise RuntimeError(f"解密失败: {e}")
    except Exception as e:
        raise RuntimeError(f"解密失败: {e}")


def encrypt_aes_gcm(plaintext: str, key: bytes = None) -> str:
    """
    使用 AES-GCM 加密数据

    Args:
        plaintext: 要加密的明文字符串
        key: 加密密钥，默认使用 UTF-8 编码的密钥

    Returns:
        Base64 编码的加密数据，格式为 [12字节Nonce][加密数据][16字节Tag]
    """
    if key is None:
        key = KEY_UTF8

    # 生成随机 12 字节 nonce
    nonce = os.urandom(12)

    # 创建 AES-GCM 加密器
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 加密
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    # 组合: nonce + ciphertext + tag
    encrypted_data = nonce + ciphertext + tag

    # Base64 编码
    return base64.b64encode(encrypted_data).decode('utf-8')


def main():
    print("=" * 60)
    print("AES-GCM 数据包解密工具")
    print("=" * 60)
    print(f"密钥字符串: {KEY_STRING}")
    print(f"模式 1 - UTF-8 密钥: {KEY_UTF8.hex()} ({len(KEY_UTF8)} 字节, AES-256)")
    print(f"模式 2 - Hex 密钥:   {KEY_HEX.hex()} ({len(KEY_HEX)} 字节, AES-128)")
    print("=" * 60)

    if len(sys.argv) > 1:
        encrypted_data = sys.argv[1]
        mode = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    else:
        print("\n请输入要解密的 Base64 编码数据 (或输入 'test' 测试加密解密):")
        encrypted_data = input("> ").strip()
        mode = 1

    # 选择密钥
    key = KEY_UTF8 if mode == 1 else KEY_HEX

    if encrypted_data.lower() == 'test':
        # 测试模式
        print("\n[测试模式 - UTF-8 密钥 (AES-256)]")
        test_text = "Hello, AES-GCM 加密测试!"
        print(f"原始明文: {test_text}")

        encrypted = encrypt_aes_gcm(test_text, KEY_UTF8)
        print(f"加密结果: {encrypted}")

        decrypted = decrypt_aes_gcm(encrypted, KEY_UTF8)
        print(f"解密结果: {decrypted}")

        if decrypted == test_text:
            print("✓ AES-256 测试成功!")
        else:
            print("✗ AES-256 测试失败!")

        print("\n[测试模式 - Hex 密钥 (AES-128)]")
        encrypted = encrypt_aes_gcm(test_text, KEY_HEX)
        print(f"加密结果: {encrypted}")

        decrypted = decrypt_aes_gcm(encrypted, KEY_HEX)
        print(f"解密结果: {decrypted}")

        if decrypted == test_text:
            print("✓ AES-128 测试成功!")
        else:
            print("✗ AES-128 测试失败!")
        return

    try:
        # 尝试两种模式解密
        print(f"\n输入数据 (Base64): {encrypted_data[:60]}..." if len(encrypted_data) > 60 else f"\n输入数据 (Base64): {encrypted_data}")
        print(f"数据长度: {len(base64.b64decode(encrypted_data))} 字节")

        # 先尝试 AES-256 (UTF-8 密钥)
        print("\n[尝试 AES-256-GCM 解密 (UTF-8 密钥)]")
        try:
            result = decrypt_aes_gcm(encrypted_data, KEY_UTF8)
            print(f"解密成功!")
            print("-" * 40)
            print(result)
            print("-" * 40)
            return
        except Exception as e:
            print(f"AES-256 解密失败: {e}")

        # 再尝试 AES-128 (Hex 密钥)
        print("\n[尝试 AES-128-GCM 解密 (Hex 密钥)]")
        result = decrypt_aes_gcm(encrypted_data, KEY_HEX)
        print(f"解密成功!")
        print("-" * 40)
        print(result)
        print("-" * 40)

    except Exception as e:
        print(f"\n错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
