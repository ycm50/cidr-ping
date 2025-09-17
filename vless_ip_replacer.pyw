import tkinter as tk
from tkinter import scrolledtext, messagebox
import re


class VlessIpReplacer:
    def __init__(self, root):
        self.root = root
        self.root.title("VLESS IP 替换工具")
        self.root.geometry("800x600")

        # IP 输入框
        tk.Label(root, text="请输入IP地址（每行一个）:").pack(anchor='w', padx=10, pady=(10, 0))
        self.ip_text = scrolledtext.ScrolledText(root, width=80, height=10)
        self.ip_text.pack(padx=10, pady=5)

        # VLESS 链接输入框
        tk.Label(root, text="请输入VLESS链接（每行一个）:").pack(anchor='w', padx=10, pady=(10, 0))
        self.vless_text = scrolledtext.ScrolledText(root, width=80, height=10)
        self.vless_text.pack(padx=10, pady=5)

        # 替换按钮
        self.replace_button = tk.Button(root, text="替换IP", command=self.replace_ips)
        self.replace_button.pack(pady=10)

        # 输出框
        tk.Label(root, text="输出结果:").pack(anchor='w', padx=10, pady=(10, 0))
        self.output_text = scrolledtext.ScrolledText(root, width=80, height=15)
        self.output_text.pack(padx=10, pady=5)

    def replace_ips(self):
        # 获取输入的 IP 列表
        ip_input = self.ip_text.get("1.0", tk.END).strip()
        if not ip_input:
            messagebox.showerror("错误", "请提供至少一个IP地址")
            return
        
        ips = ip_input.splitlines()
        
        # 获取输入的 VLESS 链接
        vless_input = self.vless_text.get("1.0", tk.END).strip()
        if not vless_input:
            messagebox.showerror("错误", "请提供至少一个VLESS链接")
            return
        
        vless_links = vless_input.splitlines()
        
        # 处理每个 IP 和每个 VLESS 链接的组合
        output_lines = []
        for vless_link in vless_links:
            vless_link = vless_link.strip()
            if not vless_link:
                continue
            
            # 提取原始链接中的端口
            original_port = self.extract_port(vless_link)
            
            for ip in ips:
                ip = ip.strip()
                if not ip:
                    continue
                
                # 检查输入的IP是否为 IPv6 地址，并确保有方括号
                if ':' in ip and '.' not in ip:  # 简单判断为 IPv6
                    if not ip.startswith('['):
                        formatted_ip = f'[{ip}]'
                    else:
                        formatted_ip = ip
                else:
                    formatted_ip = ip
                # 改为匹配@与下一个?之间的内容
                # 首先提取@与?之间的内容
                at_to_question_pattern = r'(?<=@)[^?]+'
                match = re.search(at_to_question_pattern, vless_link)
                if match:
                    address_port_part = match.group(0)
                    
                    # 判断是IPv4还是IPv6
                    if ']' in address_port_part:
                        # IPv6格式，提取]与?之间的端口（不包含[和?）
                        # 先找到]的位置，然后提取到?之间的内容
                        bracket_end_index = address_port_part.find(']')
                        if bracket_end_index != -1 and bracket_end_index + 1 < len(address_port_part):
                            # 提取]后面的部分（应该包含:和端口号）
                            after_bracket = address_port_part[bracket_end_index + 1:]
                            port_pattern = r':([\d]+)'
                            port_match = re.search(port_pattern, after_bracket)
                            if port_match:
                                port = port_match.group(1)
                                # 构造新的地址和端口部分
                                new_address_port = f'{formatted_ip}:{port}'
                                # 替换@与?之间的内容
                                new_link = vless_link.replace(address_port_part, new_address_port)
                            else:
                                new_link = vless_link
                        else:
                            new_link = vless_link
                    else:
                        # IPv4格式，提取:到?之前为端口（不包含?，包含:）
                        port_pattern = r':([\d]+)'
                        port_match = re.search(port_pattern, address_port_part)
                        if port_match:
                            port = port_match.group(1)
                            # 构造新的地址和端口部分
                            new_address_port = f'{formatted_ip}:{port}'
                            # 替换@与?之间的内容
                            new_link = vless_link.replace(address_port_part, new_address_port)
                        else:
                            new_link = vless_link
                else:
                    new_link = vless_link
                
                output_lines.append(new_link)
            output_lines.append("")  # 添加空行分隔不同的 VLESS 链接
        
        # 显示结果
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "\n".join(output_lines))
        
    def extract_port(self, vless_link):
        # 从 VLESS 链接中提取端口号
        port_pattern = r':(\d+)'
        match = re.search(port_pattern, vless_link)
        if match:
            return match.group(1)
        return '443'  # 默认端口


if __name__ == "__main__":
    root = tk.Tk()
    app = VlessIpReplacer(root)
    root.mainloop()