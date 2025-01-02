import vul_manager as vulmanager
import out_toMd 
import os

# 首先探测是否存在所有漏洞
def vul_scan(host, down, proxy):
    vul_manager = vulmanager.VulManager(host, down, proxy)
    # 获取版本号
    vul_list = []
    version = vul_manager.get_version()
    vul_list.append(f"[+] {host} Nacos版本号：{version}")
    is_bypass_vul = False
    # 默认用户漏洞
    if vul_manager.default_nacos():
        vul_list.append(f"[!] {host} 存在 Nacos 默认 username and password 漏洞!")
        is_bypass_vul = True
    # 默认密钥
    if vul_manager.get_accesstoken():
        vul_list.append(f"[!] {host} 存在 Nacos 默认 jwtToken 漏洞!")
        is_bypass_vul = True
    # V1的绕过
    if vul_manager.cross_check():
        vul_list.append(f"[!] {host} 存在 Nacos V1 authbypass 漏洞!")
        is_bypass_vul = True
    # UA:Nacos-Server的绕过
    if vul_manager.cross_ua_check():
        vul_list.append(f"[!] {host} 存在 Nacos UA:Nacos-Server 漏洞!")
        is_bypass_vul = True
    # serverIdentity 鉴权绕过
    if vul_manager.serveridentity_check():
        vul_list.append(f"[!] {host} 存在 Nacos serverIdentity 鉴权绕过 漏洞!")
        is_bypass_vul = True
    # 7848 rce
    if vul_manager.jraft_rce():
        vul_list.append(f"[!] {host} 存在Nacos Jraft 反序列化RCE 漏洞!如开启7848，请检查")
    # jraft文件读取
    if vul_manager.jraft_file_rw():
        vul_list.append(f"[!] {host} 存在Nacos Jraft 文件读取漏洞!如开启7848，请检查")
    # 未授权sql命令执行
    if vul_manager.authpass_sqlexe():
        vul_list.append(f"[!] {host} 存在Nacos 未授权sql执行漏洞!可参考vulhub进行RCE")
    if down:
        if is_bypass_vul:
            filename = str(host).replace('.', '_').replace('http://', '').replace(':', '_') + '.zip'
            out_toMd.OutToMd('./config_zip/' + filename).write_file_content()
            output_md = './file_list_md/' + filename.replace('zip', 'md')
            if os.path.exists(output_md):
                vul_list.append(f"[+] 文件清单已生成 {output_md}")
            else:
                vul_list.append("[+] 配置文件为空，没有生成清单")
    return vul_list
    