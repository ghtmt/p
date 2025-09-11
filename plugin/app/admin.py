# -*- coding: utf-8 -*-
# 本资源来源于互联网公开渠道，仅可用于个人学习及爬虫技术交流。
# 严禁将其用于任何商业用途，下载后请于 24 小时内删除，搜索结果均来自源站，本人不承担任何责任。
# 七月魔改版 0909 - 完整匹配原APP密钥体系
from Crypto.Cipher import AES
from base.spider import Spider
from urllib.parse import quote
import re, sys, json, base64, urllib3, uuid, random
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.append('..')

class Spider(Spider):
    host, jiexi, headers = '', '', {}
    # 根据反编译结果正确设置密钥体系
    api_key = ''              # API接口密钥 (对应 API_AES_KEY)
    api_iv = ''               # API接口IV (对应 API_AES_IV)
    key = ''                  # 主密钥 (对应 AES_KEY)
    iv = ''                   # 主IV (对应 AES_IV)
    dynamic_key = ''          # 动态域名解密密钥
    api_ua = ''               # 外置请求接口的UA
    play_ua = ''              # 外置播放UA
    play_source_order = []    # 播放线路排序配置
    username = ''             # 登录用户名
    password = ''             # 登录密码
    login_token = ''          # 登录后的token
    is_logged_in = False      # 登录状态标记
    
    def _is_dynamic_domain(self, url):
        """判断是否为动态域名"""
        if not url:
            return False
        
        # 标准域名格式：http(s)://域名或IP(:端口)/
        standard_domain_pattern = r'^https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:\d+)?/?$'
        
        # 如果是标准域名格式，直接返回false
        if re.match(standard_domain_pattern, url):
            return False
        
        # 动态域名的特征：
        # 1. 包含常见动态域名文件后缀
        dynamic_suffixes = ['.txt', '.json', '.data', '.config', '.conf', '.domain']
        if any(url.endswith(suffix) for suffix in dynamic_suffixes):
            return True
        
        # 2. 包含动态域名相关路径
        dynamic_paths = ['/getDomain', '/dynamic', '/api/domain', '/config', '/app.json']
        if any(path in url for path in dynamic_paths):
            return True
        
        # 3. 包含API相关路径但不是标准API路径
        api_paths = ['/api.php', '/api/', '/interface']
        if any(path in url for path in api_paths) and not re.match(standard_domain_pattern, url):
            return True
        
        # 4. 用户明确标记为动态域名
        if url.startswith('dynamic:') or 'dynamic=true' in url.lower():
            return True
            
        return False

    def init(self, extend=''):
        ext = json.loads(extend.strip()) if extend.strip() else {}
        
        # 处理host配置（兼容XinJie加密host格式）
        host = ext.get('host', '')
        if not host:
            print("错误: 必须配置host参数")
            print("请在配置文件中添加: {\"host\": \"您的资源地址\"}")
            return None
        
        # 根据反编译结果正确设置密钥体系
        # API接口密钥（数据接口加解密）- 对应原APP的 API_AES_KEY 和 API_AES_IV
        self.api_key = ext.get('key', 'dq6jHm4nG2vY8wQ1')  # 默认值对应 API_AES_KEY
        self.api_iv = ext.get('iv', '8A3kPq7xZ9rT28B5')    # 默认值对应 API_AES_IV
        
        # 主密钥（动态域名解密等）- 对应原APP的 AES_KEY 和 AES_IV
        self.key = ext.get('hostkey', 'Kkebx6vFqWMCNKwmaaeGOmnZBNzbQ1Bj')  # 默认值对应 AES_KEY
        self.iv = ext.get('hostiv', 'cBqqjFQUqBeAJ61z')                    # 默认值对应 AES_IV
        
        # 动态域名解密密钥使用主密钥
        self.dynamic_key = ext.get('dynamic_key', self.key)
        
        # 初始化UA配置
        self.api_ua = ext.get('api_ua', 'XinJieApp/1.0')
        
        # 设置默认播放UA
        default_play_ua = 'Dalvik/2.1.0 (Linux; U; Android 14; 23113RK12C Build/SKQ1.231004.001)'
        self.play_ua = ext.get('play_ua', default_play_ua)
        
        # 初始化播放线路排序配置
        order_config = ext.get('排序', '')
        if order_config:
            self.play_source_order = [item.strip() for item in order_config.split('>') if item.strip()]
            print(f"播放线路排序配置: {self.play_source_order}")
        
        # 初始化登录账号密码
        self.username = ext.get('账号', '')
        self.password = ext.get('密码', '')
        
        self.headers = {
            'User-Agent': self.api_ua,
            'Accept-Encoding': 'gzip',
            'cache-control': 'no-cache'
        }
        
        # 第一步：判断是否为base64加密的host（兼容XinJie格式）
        if not host.startswith(('http://', 'https://')):
            try:
                # 使用主密钥解密host（对应原APP的AES_KEY和AES_IV）
                decrypted_host = self.decrypt_with_key(host, self.key, self.iv)
                if decrypted_host and decrypted_host.startswith(('http://', 'https://')):
                    host = decrypted_host
                    print(f"使用主密钥解密host成功: {host}")
            except Exception as e:
                print(f"host解密失败，将尝试作为普通host处理: {e}")
        
        # 第二步：判断是否为动态域名
        if self._is_dynamic_domain(host):
            print(f"检测到动态域名: {host}")
            try:
                response = self.fetch(host, headers=self.headers, verify=False)
                if response.status_code == 200:
                    content = response.text.strip()
                    
                    # 尝试解析为JSON（可能是加密的域名配置）
                    try:
                        domain_data = json.loads(content)
                        if 'server' in domain_data and 'url' in domain_data['server']:
                            host = domain_data['server']['url']
                            print(f"从JSON配置获取域名: {host}")
                        else:
                            # 可能是加密的数据，尝试使用主密钥解密
                            decrypted_data = self.decrypt_dynamic(content)
                            try:
                                domain_data = json.loads(decrypted_data)
                                if 'server' in domain_data and 'url' in domain_data['server']:
                                    host = domain_data['server']['url']
                                    print(f"从加密配置获取域名: {host}")
                            except:
                                # 解密后不是JSON，可能是纯文本域名
                                host = decrypted_data.strip()
                                print(f"从解密数据获取域名: {host}")
                    except json.JSONDecodeError:
                        # 不是JSON，可能是加密数据或纯文本
                        try:
                            decrypted_data = self.decrypt_dynamic(content)
                            host = decrypted_data.strip()
                            print(f"从解密数据获取域名: {host}")
                        except:
                            # 不是加密数据，可能是纯文本域名列表
                            addresses = [line.strip() for line in content.splitlines() if line.strip()]
                            if addresses:
                                host = addresses[0]
                                print(f"从文本列表获取域名: {host}")
            except Exception as e:
                print(f"动态域名处理失败: {e}")
        
        # 第三步：处理普通域名或IP:端口格式
        if not re.match(r'^https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:\d+)?/?$', host):
            try:
                response = self.fetch(host, headers=self.headers, verify=False)
                if response.status_code == 200:
                    text = response.text.strip()
                    addresses = [line.strip() for line in text.splitlines() if line.strip()]
                    if addresses:
                        host = addresses[0]
                        print(f"从响应内容获取域名: {host}")
            except Exception as e:
                print(f"获取host失败: {e}")
        
        # 最终确保host是标准格式
        if not host.startswith(('http://', 'https://')):
            host = 'http://' + host
        
        self.host = host.rstrip('/')
        print(f"最终使用的域名: {self.host}")
        
        # 如果有账号密码配置，尝试登录
        if self.username and self.password:
            self._login()
        
        return None

    def decrypt_with_key(self, encrypted_data, key, iv):
        """使用指定的key和iv解密数据"""
        try:
            # 密钥填充到32位
            key = key.ljust(32, '0')
            key_bytes = key.encode('utf-8')
            iv_bytes = iv.encode('utf-8')
            
            ciphertext = base64.b64decode(encrypted_data)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            plaintext = cipher.decrypt(ciphertext)
            
            # 去除PKCS7填充
            padding_length = plaintext[-1]
            plaintext = plaintext[:-padding_length]
            
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"使用密钥解密错误: {e}")
            return encrypted_data

    def _login(self):
        """登录账号"""
        try:
            print(f"尝试登录账号: {self.username}")
            login_url = f"{self.host}/admin/login.php"
            
            # 构建登录数据
            login_data = {
                'username': self.username,
                'password': self.password
            }
            
            # 发送登录请求
            response = self.fetch(login_url, headers=self.headers, data=login_data, method='POST', verify=False)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 200:
                    self.login_token = result.get('data', {}).get('token', '')
                    self.is_logged_in = True
                    
                    # 更新headers包含token
                    self.headers['Authorization'] = f'Bearer {self.login_token}'
                    print("登录成功")
                else:
                    print(f"登录失败: {result.get('msg', '未知错误')}")
            else:
                print(f"登录请求失败: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"登录过程中发生错误: {e}")

    def _ensure_login(self):
        """确保已登录，如果未登录且配置了账号密码，则尝试登录"""
        if not self.is_logged_in and self.username and self.password:
            self._login()
        return self.is_logged_in

    def decrypt_dynamic(self, encrypted_data):
        """解密动态域名数据（使用主密钥）"""
        try:
            # 使用dynamic_key或主密钥，填充到32位
            key = self.dynamic_key.ljust(32, '0')
            key_bytes = key.encode('utf-8')
            iv_bytes = self.iv.encode('utf-8')
            
            ciphertext = base64.b64decode(encrypted_data)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            plaintext = cipher.decrypt(ciphertext)
            
            # 去除PKCS7填充
            padding_length = plaintext[-1]
            plaintext = plaintext[:-padding_length]
            
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"动态域名解密错误: {e}")
            return encrypted_data

    def decrypt(self, encrypted_data, use_api_key=True):
        """通用解密方法，默认使用API密钥"""
        try:
            # 选择使用的密钥和IV
            if use_api_key:
                key = self.api_key  # API接口密钥
                iv = self.api_iv    # API接口IV
            else:
                key = self.key      # 主密钥
                iv = self.iv        # 主IV
            
            # 密钥填充到32位
            key = key.ljust(32, '0')
            key_bytes = key.encode('utf-8')
            iv_bytes = iv.encode('utf-8')
            
            ciphertext = base64.b64decode(encrypted_data)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            plaintext = cipher.decrypt(ciphertext)
            
            # 去除PKCS7填充
            padding_length = plaintext[-1]
            plaintext = plaintext[:-padding_length]
            
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"解密错误: {e}")
            return encrypted_data

    def encrypt(self, plain_data, use_api_key=True):
        """通用加密方法，默认使用API密钥"""
        try:
            # 选择使用的密钥和IV
            if use_api_key:
                key = self.api_key  # API接口密钥
                iv = self.api_iv    # API接口IV
            else:
                key = self.key      # 主密钥
                iv = self.iv        # 主IV
            
            # 密钥填充到32位
            key = key.ljust(32, '0')
            key_bytes = key.encode('utf-8')
            iv_bytes = iv.encode('utf-8')
            
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            
            # PKCS7填充
            block_size = AES.block_size
            padded_data = plain_data.encode('utf-8') + bytes([block_size - len(plain_data) % block_size] * (block_size - len(plain_data) % block_size))
            
            ciphertext = cipher.encrypt(padded_data)
            
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            print(f"加密错误: {e}")
            return plain_data

    def _sort_play_sources(self, play_sources):
        """对播放线路进行排序"""
        if not self.play_source_order or not play_sources:
            return play_sources
            
        def get_sort_key(source):
            source_name = source['name']
            source_key = source['source_key']
            
            # 检查精准匹配
            for i, pattern in enumerate(self.play_source_order):
                # 精准匹配名称或key
                if pattern.lower() == source_name.lower() or pattern.lower() == source_key.lower():
                    return i
            
            # 检查模糊匹配
            for i, pattern in enumerate(self.play_source_order):
                # 模糊匹配名称或key（包含关系）
                if (pattern.lower() in source_name.lower() or 
                    pattern.lower() in source_key.lower()):
                    return i
            
            # 未匹配到的排在最后
            return len(self.play_source_order)
        
        # 按照排序规则排序
        sorted_sources = sorted(play_sources, key=get_sort_key)
        return sorted_sources

    def homeContent(self, filter):
        if not self.host: return None
        # 确保已登录
        self._ensure_login()
        
        response = self.fetch(f'{self.host}/admin/duanjuc.php?page=1&limit=30', headers=self.headers, verify=False).json()
        data = response['data']
        if response.get('encrypted') == 1:
            # 使用API密钥解密数据（数据接口使用API密钥）
            data_ = self.decrypt(response['data'], use_api_key=True)
            data = json.loads(data_)['data']
        classes, videos = [], []
        for i in data:
            if i['type_id'] != 0:
                classes.append({'type_id': i['type_id'], 'type_name': i['type_name']})
            for j in i['videos']:
                videos.append({
                'vod_id': j['vod_id'],
                'vod_name': j['vod_name'],
                'vod_pic': j['vod_pic'],
                'vod_remarks': j['vod_remarks'],
                'vod_year': j['vod_year']
            })
        return {'class': classes, 'list': videos}

    def categoryContent(self, tid, pg, filter, extend):
        if not self.host: return None
        # 确保已登录
        self._ensure_login()
        
        response = self.fetch(f'{self.host}/admin/duanjusy.php?limit=20&page={pg}&type_id={tid}', headers=self.headers, verify=False).json()
        data = response['data']
        if response.get('encrypted') == 1:
            # 使用API密钥解密数据（数据接口使用API密钥）
            data_ = self.decrypt(response['data'], use_api_key=True)
            data1 = json.loads(data_)
            data = data1['data']
        videos = []
        for i in data:
            videos.append({
                'vod_id': i['vod_id'],
                'vod_name': i['vod_name'],
                'vod_pic': i['vod_pic'],
                'vod_remarks': i['vod_remarks'],
                'vod_year': i['vod_year']
            })
        return {'list': videos, 'pagecount': data1['pagination']['total_pages']}

    def searchContent(self, key, quick, pg='1'):
        if not self.host: return None
        # 确保已登录
        self._ensure_login()
        
        response = self.fetch(f'{self.host}/admin/duanjusy.php?suggest={key}&limit=20&page={pg}', headers=self.headers, verify=False).json()
        data = response['data']
        if response.get('encrypted') == 1:
            # 使用API密钥解密数据（数据接口使用API密钥）
            data_ = self.decrypt(response['data'], use_api_key=True)
            data1 = json.loads(data_)
            data = data1['data']
        videos = []
        for i in data:
            videos.append({
                'vod_id': i['vod_id'],
                'vod_name': i['vod_name'],
                'vod_pic': i['vod_pic'],
                'vod_remarks': i['vod_remarks'],
                'vod_year': i['vod_year'],
                'vod_content': i['vod_blurb']
            })
        return {'list': videos, 'pagecount': data1['pagination']['total_pages']}

    def detailContent(self, ids):
        # 确保已登录
        self._ensure_login()
        
        response = self.fetch(f'{self.host}/admin/duanju.php?vod_id={ids[0]}', headers=self.headers, verify=False).json()
        data = response['data']
        if response.get('encrypted') == 1:
            # 使用API密钥解密数据（数据接口使用API密钥）
            data_ = self.decrypt(response['data'], use_api_key=True)
            data = json.loads(data_)['data']
        jiexi = data.get('jiexi','')
        if jiexi.startswith('http'):
            self.jiexi = jiexi
        
        # 对播放线路进行排序
        sorted_sources = self._sort_play_sources(data['play_sources'])
        
        play_from, play_urls = [], []
        for source in sorted_sources:
            play_from.append(f"{source['name']}\u2005({source['source_key']})")
            urls = source['url'].split('#')
            urls2 = [ '$'.join([parts[0], f"{source['source_key']}@{parts[1]}"]) for parts in [url.split('$') for url in urls] ]
            play_urls.append('#'.join(urls2))
        video = {
                'vod_id': data['vod_id'],
                'vod_name': data['vod_name'],
                'vod_pic': data['vod_pic'],
                'vod_remarks': data['vod_remarks'],
                'vod_year': data['vod_year'],
                'vod_area': data['vod_area'],
                'vod_actor': data['vod_actor'],
                'vod_director': data['vod_director'],
                'vod_content': data['vod_content'],
                'type_name': data['vod_class'],
                'vod_play_from': '$$$'.join(play_from),
                'vod_play_url': '$$$'.join(play_urls)
            }
        return {'list': [video]}

    def playerContent(self, flag, id, vipflags):
        play_from, raw_url = id.split('@', 1)
        
        default_ua = self.play_ua
        
        # 确保已登录
        self._ensure_login()
        
        if self.jiexi:
            try:
                response = self.fetch(f"{self.host}/admin/jiexi.php?url={quote(raw_url, safe='')}&source={play_from}", headers=self.headers, verify=False).json()
                if response.get('encrypted') == 1:
                    # 使用API密钥解密解析结果（数据接口使用API密钥）
                    data_ = self.decrypt(response['data'], use_api_key=True)
                    data = json.loads(data_)
                play_url = data['url']
                url = play_url if play_url.startswith('http') else id
                ua = response.get('UA', default_ua)
            except Exception:
                url, ua = raw_url, default_ua
        else:
            url, ua = raw_url, default_ua
            
        return {'jx': '0','parse': '0','url': url,'header': {'User-Agent': ua}}

    def homeVideoContent(self):
        pass

    def getName(self):
        return "通用模板"

    def isVideoFormat(self, url):
        pass

    def manualVideoCheck(self):
        pass

    def destroy(self):
        pass

    def localProxy(self, param):
        pass