# -*- coding: utf-8 -*-
"""
AES-GCM 数据包被动解密插件 for Burp Suite

功能：
- 自动检测并解密 AES-GCM 加密的数据包
- 支持 AES-256-GCM (UTF-8 密钥) 模式
- 被动扫描，不影响正常请求

安装方法：
1. Burp Suite -> Extender -> Add
2. Extension type: Python
3. 选择此文件

作者: Claude
"""

from burp import IBurpExtender, IHttpListener, IScannerListener, ITab
from javax.swing import JPanel, JTextArea, JScrollPane, JButton, JLabel, JTextField, BoxLayout, BorderFactory
from java.awt import BorderLayout, FlowLayout, Dimension
import base64
import json
import re

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # 设置插件名称
        callbacks.setExtensionName("AES-GCM Decryptor")

        # 检查依赖
        if AES is None:
            callbacks.printOutput("[!] 请安装 pycryptodome: pip install pycryptodome")
            callbacks.printOutput("[!] 在 Burp 中使用需要将 pycrypto 加入 Python 路径")

        # 密钥配置
        self.key_string = "0123456789abcdef0123456789abcdef"
        self.key_utf8 = self.key_string.encode('utf-8')  # 32 bytes, AES-256
        self.key_hex = bytes.fromhex(self.key_string)     # 16 bytes, AES-128

        # 创建 UI
        self._create_ui()

        # 注册监听器
        callbacks.registerHttpListener(self)

        callbacks.printOutput("[*] AES-GCM Decryptor 插件已加载")
        callbacks.printOutput("[*] 密钥: " + self.key_string)
        callbacks.printOutput("[*] 监听中...")

    def _create_ui(self):
        """创建插件 UI"""
        self._panel = JPanel(BorderLayout())

        # 顶部配置面板
        config_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        config_panel.add(JLabel("密钥: "))

        self._key_field = JTextField(self.key_string, 40)
        config_panel.add(self._key_field)

        update_btn = JButton("更新密钥", actionPerformed=self._update_key)
        config_panel.add(update_btn)

        self._panel.add(config_panel, BorderLayout.NORTH)

        # 中间日志区域
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(self._log_area.getFont().deriveFont(12.0))
        scroll_pane = JScrollPane(self._log_area)
        scroll_pane.setPreferredSize(Dimension(800, 400))
        self._panel.add(scroll_pane, BorderLayout.CENTER)

        # 底部按钮
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        clear_btn = JButton("清空日志", actionPerformed=self._clear_log)
        button_panel.add(clear_btn)
        self._panel.add(button_panel, BorderLayout.SOUTH)

    def _update_key(self, event):
        """更新密钥"""
        self.key_string = self._key_field.getText().strip()
        if len(self.key_string) == 32:
            self.key_utf8 = self.key_string.encode('utf-8')
            self.key_hex = bytes.fromhex(self.key_string)
            self._log("[+] 密钥已更新: " + self.key_string)
        else:
            self._log("[!] 密钥长度必须为 32 个字符")

    def _clear_log(self, event):
        """清空日志"""
        self._log_area.setText("")

    def _log(self, message):
        """添加日志"""
        self._log_area.append(message + "\n")
        self._log_area.setCaretPosition(self._log_area.getDocument().getLength())

    def getTabCaption(self):
        return "AES-GCM Decryptor"

    def getUiComponent(self):
        return self._panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """处理 HTTP 消息"""
        if AES is None:
            return

        # 只处理响应
        if messageIsRequest:
            return

        try:
            # 获取响应
            response = messageInfo.getResponse()
            if response is None:
                return

            response_info = self._helpers.analyzeResponse(response)
            body_offset = response_info.getBodyOffset()
            body = response[body_offset:]

            # 转换为字符串
            body_str = self._helpers.bytesToString(body).strip()

            # 尝试解密
            decrypted = self._try_decrypt(body_str)

            if decrypted:
                # 获取请求 URL
                request_info = self._helpers.analyzeRequest(messageInfo)
                url = request_info.getUrl().toString()

                self._log("\n" + "=" * 60)
                self._log("[+] 解密成功!")
                self._log("URL: " + url)
                self._log("-" * 60)
                self._log("解密结果:")
                self._log(self._format_json(decrypted))

                # 添加注释
                messageInfo.setComment("AES-GCM Decrypted")
                messageInfo.setHighlight("green")

        except Exception as e:
            pass  # 忽略错误，不影响正常请求

    def _try_decrypt(self, data):
        """尝试解密数据"""
        # 检查是否是 base64 格式
        if not self._is_base64(data):
            return None

        try:
            encrypted_data = base64.b64decode(data)
        except:
            return None

        # 检查最小长度 (12 bytes nonce + 16 bytes tag + 至少 1 byte 密文)
        if len(encrypted_data) < 12 + 16 + 1:
            return None

        # 提取 nonce 和密文
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]

        if len(ciphertext_with_tag) < 17:
            return None

        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # 尝试 AES-256-GCM (UTF-8 密钥)
        try:
            cipher = AES.new(self.key_utf8, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except:
            pass

        # 尝试 AES-128-GCM (Hex 密钥)
        try:
            cipher = AES.new(self.key_hex, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except:
            pass

        return None

    def _is_base64(self, data):
        """检查是否是有效的 base64 字符串"""
        if not data:
            return False
        pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        return bool(re.match(pattern, data)) and len(data) >= 20

    def _format_json(self, json_str):
        """格式化 JSON"""
        try:
            data = json.loads(json_str)
            return json.dumps(data, indent=2, ensure_ascii=False)
        except:
            return json_str
