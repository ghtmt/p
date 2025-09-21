# coding = utf-8
#!/usr/bin/python
# 新时代青年 2025.06.25 getApp第三版  后续平凡哥 七月大姐等大佬魔改 最后更新2025.08.30七月版  请勿非法盈利，下载24小时后请删除！不删除雨滴大佬晚上会在你窗前
import re,sys,uuid,json,base64,urllib3,random,time,hashlib
from Crypto.Cipher import AES
from base.spider import Spider
from Crypto.Util.Padding import pad,unpad
sys.path.append('..')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Spider(Spider):
    xurl,key,iv,init_data,search_verify = '','','','',''
    username, password, device_id = '', '', ''
    header = {}
    sort_rule = []
    playua = ''
    playcookie = ''
    playreferer = ''
    line_specific_settings = {}
    vip_duration = ''
    vip_config = {}
    enable_delay = False  # 延迟请求开关，默认关闭
    
    def __init__(self):
        self.header = {'User-Agent': self._generate_random_ua()}

    def getName(self):
        return "首页"

    def init(self, extend=''):
        ext = json.loads(extend.strip())
        host = ext['host']
        
        # 读取延迟请求配置，默认关闭
        self.enable_delay = ext.get('延迟', ext.get('enable_delay', '0')) == '1'
        
        host_index_str = str(ext.get('host_index', '1')).strip()
        try:
            host_index = int(host_index_str) if host_index_str else 1
        except ValueError:
            host_index = 1
        
        if not re.match(r'^https?:\/\/[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:\d+)?(\/)?$', host):
            response = self.fetch(host, headers=self.header, timeout=10, verify=False)
            text = response.text.strip()
            addresses = [line.strip() for line in text.splitlines() if line.strip()]
            
            if len(addresses) > 0:
                index = host_index - 1
                if 0 <= index < len(addresses):
                    host = addresses[index]
                else:
                    host = addresses[0]
            
        host = host.rstrip('/')
        
        ua = ext.get('ua')
        if ua:
            self.header['User-Agent'] = ua
        
        # 初始化会员配置
        self.vip_config = {
            'type': ext.get('login_type', 'auto'),  # auto, login, duration, token, cookie, device, guest
            'duration': ext.get('会员时长', ''),
            'username': ext.get('username', ''),
            'password': ext.get('password', ''),
            'token': ext.get('token', ''),
            'cookie': ext.get('cookie', ''),
            'device_only': ext.get('device_only', '0') == '1'
        }
        
        self.device_id = ext.get('deviceid') or ext.get('devideid') or str(uuid.uuid4())
        
        if self.device_id:
            self.header['app-user-device-id'] = self.device_id
        
        # 处理会员验证
        self._handle_vip_verification()
        
        self.playua = ext.get('playua', 'Dalvik/2.1.0 (Linux; U; Android 14; 23113RK12C Build/SKQ1.231004.001)')
        self.playcookie = ext.get('playcookie', '')
        self.playreferer = ext.get('playreferer', '')
        
        self.line_specific_settings = {}
        for key, value in ext.items():
            if key.startswith('line_'):
                line_key = key.replace('line_', '')
                if '|' in value:
                    parts = value.split('|', 1)
                    ua_part = ''
                    referer_part = ''
                    for part in parts:
                        part = part.strip()
                        if part:
                            if part.startswith('http://') or part.startswith('https://'):
                                referer_part = part
                            else:
                                ua_part = part
                    if line_key not in self.line_specific_settings:
                        self.line_specific_settings[line_key] = {}
                    if ua_part:
                        self.line_specific_settings[line_key]['ua'] = ua_part
                    if referer_part:
                        self.line_specific_settings[line_key]['referer'] = referer_part
                elif '_ua' in key:
                    line_name = key.replace('line_', '').replace('_ua', '')
                    if line_name not in self.line_specific_settings:
                        self.line_specific_settings[line_name] = {}
                    self.line_specific_settings[line_name]['ua'] = value
                elif '_referer' in key:
                    line_name = key.replace('line_', '').replace('_referer', '')
                    if line_name not in self.line_specific_settings:
                        self.line_specific_settings[line_name] = {}
                    self.line_specific_settings[line_name]['referer'] = value
                else:
                    if line_key not in self.line_specific_settings:
                        self.line_specific_settings[line_key] = {}
                    if value.startswith('http://') or value.startswith('https://'):
                        self.line_specific_settings[line_key]['referer'] = value
                    else:
                        self.line_specific_settings[line_key]['ua'] = value
        
        api = ext.get('api', '/api.php/getappapi')
        if str(api) == '2':
            api = '/api.php/qijiappapi'
        self.xurl = host + api
        self.key = ext['datakey']
        self.iv = ext.get('dataiv', self.key)
        
        sort_rule_str = ext.get('排序', '')
        if sort_rule_str:
            self.sort_rule = [s.strip().lower() for s in sort_rule_str.split('>')]
        else:
            self.sort_rule = []
        
        res = self.fetch(self.xurl + '.index/initV119', headers=self.header, verify=False).json()
        encrypted_data = res['data']
        response = self.decrypt(encrypted_data)
        init_data = json.loads(response)
        self.init_data = init_data
        self.search_verify = init_data['config'].get('system_search_verify_status', False)

    def _apply_request_delay(self):
        """应用请求延迟，如果开启的话"""
        if self.enable_delay:
            delay_time = random.uniform(1, 3)  # 1到3秒随机延迟
            time.sleep(delay_time)

    def fetch(self, url, **kwargs):
        """重写fetch方法，添加延迟控制"""
        # 播放相关请求不加延迟
        if 'playerContent' not in sys._getframe(2).f_code.co_name:
            self._apply_request_delay()
        return super().fetch(url, **kwargs)

    def post(self, url, **kwargs):
        """重写post方法，添加延迟控制"""
        # 播放相关请求不加延迟
        if 'playerContent' not in sys._getframe(2).f_code.co_name:
            self._apply_request_delay()
        return super().post(url, **kwargs)

    def _handle_vip_verification(self):
        """处理会员验证 - 支持7种模式"""
        vip_type = self.vip_config['type']
        
        if vip_type == 'auto':
            # 自动检测优先级：token > cookie > 时长 > 账号密码 > 设备 > 游客
            if self.vip_config['token']:
                self.header['app-user-token'] = self.vip_config['token']
                self.vip_duration = self.vip_config['duration']
                print("自动选择: Token验证模式")
            elif self.vip_config['cookie']:
                self.header['Cookie'] = self.vip_config['cookie']
                self.vip_duration = self.vip_config['duration']
                print("自动选择: Cookie验证模式")
            elif self.vip_config['duration']:
                self.vip_duration = self.vip_config['duration']
                print("自动选择: 直接时长模式")
            elif self.vip_config['username'] and self.vip_config['password']:
                self.login()
                print("自动选择: 账号密码模式")
            elif self.vip_config['device_only']:
                self.vip_duration = self._generate_device_vip()
                print("自动选择: 设备验证模式")
            else:
                self.vip_duration = ''
                print("自动选择: 游客模式")
        
        elif vip_type == 'login':
            if self.vip_config['username'] and self.vip_config['password']:
                self.login()
                print("手动选择: 账号密码模式")
            else:
                print("账号密码模式但未提供用户名密码")
                self.vip_duration = ''
        
        elif vip_type == 'duration':
            self.vip_duration = self.vip_config['duration']
            print("手动选择: 直接时长模式")
        
        elif vip_type == 'token':
            if self.vip_config['token']:
                self.header['app-user-token'] = self.vip_config['token']
                self.vip_duration = self.vip_config['duration']
                print("手动选择: Token验证模式")
            else:
                print("Token模式但未提供token")
                self.vip_duration = ''
        
        elif vip_type == 'cookie':
            if self.vip_config['cookie']:
                self.header['Cookie'] = self.vip_config['cookie']
                self.vip_duration = self.vip_config['duration']
                print("手动选择: Cookie验证模式")
            else:
                print("Cookie模式但未提供cookie")
                self.vip_duration = ''
        
        elif vip_type == 'device':
            self.vip_duration = self._generate_device_vip()
            print("手动选择: 设备验证模式")
        
        elif vip_type == 'guest':
            self.vip_duration = ''
            print("手动选择: 游客模式")
        
        else:
            print(f"未知的登录模式: {vip_type}, 使用游客模式")
            self.vip_duration = ''

    def _generate_device_vip(self):
        """生成基于设备的会员验证参数"""
        device_hash = hashlib.md5(self.device_id.encode()).hexdigest()[:16]
        timestamp = int(time.time())
        vip_data = {
            'device_id': self.device_id,
            'device_hash': device_hash,
            'timestamp': timestamp,
            'vip_type': 'device'
        }
        return base64.b64encode(json.dumps(vip_data).encode()).decode()

    def login(self):
        """账号密码登录"""
        try:
            payload = {
                'password': self.vip_config['password'],
                'code': "",
                'device_id': self.device_id,
                'user_name': self.vip_config['username'],
                'invite_code': "",
                'is_emulator': "0"
            }
            
            timestamp = str(int(time.time()))
            headers = self.header.copy()
            headers.update({
                'app-api-verify-time': timestamp,
                'app-api-verify-sign': self.encrypt(timestamp)
            })
            
            response = self.post(f'{self.xurl}.index/appLogin', data=payload, headers=headers)
            if response.status_code == 200:
                response_data = response.json()
                encrypted_data = response_data['data']
                decrypted_data = self.decrypt(encrypted_data)
                user_info = json.loads(decrypted_data)
                
                auth_token = user_info['user']['auth_token']
                self.header['app-user-token'] = auth_token
                
                # 提取会员信息
                self._extract_vip_info(user_info)
                
        except Exception as e:
            print(f"登录失败: {e}")
            if self.vip_config['duration']:
                self.vip_duration = self.vip_config['duration']
                print("登录失败，使用备用时长参数")

    def _extract_vip_info(self, user_info):
        """从登录响应提取会员信息"""
        user_data = user_info.get('user', {})
        vip_status = user_data.get('vip_status', user_data.get('is_vip', 0))
        
        if vip_status == 1:
            if self.vip_config['duration']:
                self.vip_duration = self.vip_config['duration']
            else:
                # 生成基础会员参数
                vip_data = {
                    'user_id': user_data.get('user_id', ''),
                    'vip_level': user_data.get('vip_level', 1),
                    'login_time': int(time.time()),
                    'auth_token': self.header.get('app-user-token', '')[:20]
                }
                self.vip_duration = base64.b64encode(json.dumps(vip_data).encode()).decode()
            print("会员登录成功")
        else:
            self.vip_duration = ''
            print("当前账号不是会员")

    def _add_vip_to_request(self, payload=None, headers=None):
        """添加会员验证到请求"""
        if headers is None:
            headers = self.header.copy()
        if payload is None:
            payload = {}
        
        if self.vip_duration:
            if payload:
                payload['vip_duration'] = self.vip_duration
            else:
                headers['vip-duration'] = self.vip_duration
        
        return payload, headers

    def homeContent(self, filter):
        kjson = self.init_data
        result = {"class": [], "filters": {}}
        for i in kjson['type_list']:
            if not(i['type_name'] in {'全部', 'QQ', 'juo.one'} or '企鹅群' in i['type_name']):
                result['class'].append({
                    "type_id": i['type_id'],
                    "type_name": i['type_name']
                })
            name_mapping = {'class': '类型', 'area': '地区', 'lang': '语言', 'year': '年份', 'sort': '排序'}
            filter_items = []
            for filter_type in i.get('filter_type_list', []):
                filter_name = filter_type.get('name')
                values = filter_type.get('list', [])
                if not values:
                    continue
                value_list = [{"n": value, "v": value} for value in values]
                display_name = name_mapping.get(filter_name, filter_name)
                key = 'by' if filter_name == 'sort' else filter_name
                filter_items.append({
                    "key": key,
                    "name": display_name,
                    "value": value_list
                })
            type_id = i.get('type_id')
            if filter_items:
                result["filters"][str(type_id)] = filter_items
        return result

    def homeVideoContent(self):
        videos = []
        kjson = self.init_data
        for i in kjson['type_list']:
            for item in i['recommend_list']:
                vod_id = item['vod_id']
                name = item['vod_name']
                pic = item['vod_pic']
                remarks = item['vod_remarks']
                video = {
                    "vod_id": vod_id,
                    "vod_name": name,
                    "vod_pic": pic,
                    "vod_remarks": remarks
                }
                videos.append(video)
        return {'list': videos}

    def categoryContent(self, cid, pg, filter, ext):
        videos = []
        payload = {
            'area': ext.get('area','全部'),
            'year': ext.get('year','全部'),
            'type_id': cid,
            'page': str(pg),
            'sort': ext.get('sort','最新'),
            'lang': ext.get('lang','全部'),
            'class': ext.get('class','全部')
        }
        
        payload, headers = self._add_vip_to_request(payload)
        
        url = f'{self.xurl}.index/typeFilterVodList'
        res = self.post(url=url, headers=headers, data=payload, verify=False).json()
        encrypted_data = res['data']
        kjson = self.decrypt(encrypted_data)
        kjson1 = json.loads(kjson)
        for i in kjson1['recommend_list']:
            id = i['vod_id']
            name = i['vod_name']
            pic = i['vod_pic']
            remarks = i['vod_remarks']
            video = {
                "vod_id": id,
                "vod_name": name,
                "vod_pic": pic,
                "vod_remarks": remarks
            }
            videos.append(video)
        return {'list': videos, 'page': pg, 'pagecount': 9999, 'limit': 90, 'total': 999999}

    def detailContent(self, ids):
        did = ids[0]
        payload = {'vod_id': did}
        
        payload, headers = self._add_vip_to_request(payload)
        
        api_endpoints = ['vodDetail', 'vodDetail2']

        for endpoint in api_endpoints:
            url = f'{self.xurl}.index/{endpoint}'
            response = self.post(url=url, headers=headers, data=payload, verify=False)

            if response.status_code == 200:
                response_data = response.json()
                if '到期' in response_data.get('msg', '') or response_data.get('code', 1) == 0:
                    return None
                encrypted_data = response_data['data']
                kjson1 = self.decrypt(encrypted_data)
                kjson = json.loads(kjson1)
                break
        
        videos = []
        play_form = ''
        play_url = ''
        lineid = 1
        name_count = {}
        
        if self.sort_rule:
            def sort_key(line):
                line_name = line['player_info']['show'].lower()
                for idx, rule in enumerate(self.sort_rule):
                    if rule in line_name:
                        return idx
                return len(self.sort_rule)
            kjson['vod_play_list'].sort(key=sort_key)
        
        for line in kjson['vod_play_list']:
            keywords = {'防走丢', '群', '防失群', '官网'}
            player_show = line['player_info']['show']
            if any(keyword in player_show for keyword in keywords):
                player_show = f'{lineid}线'
                line['player_info']['show'] = player_show
            count = name_count.get(player_show, 0) + 1
            name_count[player_show] = count
            if count > 1:
                line['player_info']['show'] = f"{player_show}{count}"
            play_form += line['player_info']['show'] + '$$$'
            parse = line['player_info']['parse']
            parse_type = line['player_info']['parse_type']
            player_parse_type = line['player_info']['player_parse_type']
            kurls = ""
            for vod in line['urls']:
                token = 'token+' + vod['token']
                kurls += f"{str(vod['name'])}${parse},{vod['url']},{token},{player_parse_type},{parse_type}#"
            kurls = kurls.rstrip('#')
            play_url += kurls + '$$$'
            lineid += 1
        
        play_form = play_form.rstrip('$$$')
        play_url = play_url.rstrip('$$$')
        videos.append({
            "vod_id": did,
            "vod_name": kjson['vod']['vod_name'],
            "vod_actor": kjson['vod']['vod_actor'].replace('演员', ''),
            "vod_director": kjson['vod'].get('vod_director', '').replace('导演', ''),
            "vod_content": kjson['vod']['vod_content'],
            "vod_remarks": kjson['vod']['vod_remarks'],
            "vod_year": kjson['vod']['vod_year'] + '年',
            "vod_area": kjson['vod']['vod_area'],
            "vod_play_from": play_form,
            "vod_play_url": play_url
        })
        return {'list': videos}

    def playerContent(self, flag, id, vipFlags):
        line_name = flag
        play_header = {'User-Agent': self.playua}
        
        # 优化线路匹配逻辑 - 精确匹配优先
        line_settings = self.line_specific_settings.get(line_name, {})
        
        # 处理UA
        if 'ua' in line_settings:
            play_header['User-Agent'] = line_settings['ua']
        else:
            # 备用：尝试包含匹配（处理可能的名称变化）
            for line_key, settings in self.line_specific_settings.items():
                if line_key in line_name and 'ua' in settings:
                    play_header['User-Agent'] = settings['ua']
                    break
        
        # 处理Cookie
        if self.playcookie:
            play_header['Cookie'] = self.playcookie
            
        # 处理Referer
        referer = self.playreferer
        if 'referer' in line_settings:
            referer = line_settings['referer']
        else:
            # 备用：尝试包含匹配
            for line_key, settings in self.line_specific_settings.items():
                if line_key in line_name and 'referer' in settings:
                    referer = settings['referer']
                    break
        
        if referer:
            play_header['Referer'] = referer
            
        if self.vip_duration:
            play_header['vip-duration'] = self.vip_duration
            
        url = ''
        aid = id.split(',')
        uid = aid[0]
        kurl = aid[1]
        token = aid[2].replace('token+', '')
        player_parse_type = aid[3]
        parse_type = aid[4]
        
        if parse_type == '0':
            res =  {"parse": 0, "url": kurl, "header": play_header}
        elif parse_type == '2':
            res = {"parse": 1, "url": uid+kurl, "header": play_header}
        elif player_parse_type == '2':
            response = self.fetch(url=f'{uid}{kurl}', headers=play_header, verify=False)
            if response.status_code == 200:
                kjson1 = response.json()
                res = {"parse": 0, "url": kjson1['url'], "header": play_header}
        else:
            id1 = self.encrypt(kurl)
            payload = {
                'parse_api': uid,
                'url': id1,
                'player_parse_type': player_parse_type,
                'token': token
            }
            
            if self.vip_duration:
                payload['vip_duration'] = self.vip_duration
                
            url1 = f"{self.xurl}.index/vodParse"
            response = self.post(url=url1, headers=self.header, data=payload, verify=False)
            if response.status_code == 200:
                response_data = response.json()
                encrypted_data = response_data['data']
                kjson = self.decrypt(encrypted_data)
                kjson1 = json.loads(kjson)
                kjson2 = kjson1['json']
                kjson3 = json.loads(kjson2)
                url = kjson3['url']
            res = {"parse": 0, "playUrl": '', "url": url, "header": play_header}
        return res

    def searchContent(self, key, quick, pg="1"):
        videos = []
        if 'xiaohys.com' in self.xurl:
            host = self.xurl.split('api.php')[0]
            data = self.fetch(f'{host}index.php/ajax/suggest?mid=1&wd={key}').json()
            for i in data['list']:
                videos.append({
                    "vod_id": i['id'],
                    "vod_name": i['name'],
                    "vod_pic": i.get('pic')
                })
        else:
            payload = {
                'keywords': key,
                'type_id': "0",
                'page': str(pg)
            }
            
            payload, headers = self._add_vip_to_request(payload)
            
            if self.search_verify:
                verifi = self.verification()
                if verifi is None:
                    return {'list':[]}
                payload['code'] = verifi['code']
                payload['key'] = verifi['uuid']
            
            url = f'{self.xurl}.index/searchList'
            res = self.post(url=url, data=payload, headers=headers, verify=False).json()
            if not res.get('data'):
                return {'list':[] ,'msg': res.get('msg')}
            encrypted_data = res['data']
            kjson = self.decrypt(encrypted_data)
            kjson1 = json.loads(kjson)
            for i in kjson1['search_list']:
                id = i['vod_id']
                name = i['vod_name']
                pic = i['vod_pic']
                remarks = i['vod_year'] + ' ' + i['vod_class']
                videos.append({
                    "vod_id": id,
                    "vod_name": name,
                    "vod_pic": pic,
                    "vod_remarks": remarks
                })
        return {'list': videos, 'page': pg, 'pagecount': 9999, 'limit': 90, 'total': 999999}

    def localProxy(self, params):
        if params['type'] == "m3u8":
            return self.proxyM3u8(params)
        elif params['type'] == "media":
            return self.proxyMedia(params)
        elif params['type'] == "ts":
            return self.proxyTs(params)
        return None

    def isVideoFormat(self, url):
        pass

    def manualVideoCheck(self):
        pass

    def decrypt(self, encrypted_data_b64):
        key_bytes = self.key.encode('utf-8')
        iv_bytes = self.iv.encode('utf-8')
        encrypted_data = base64.b64decode(encrypted_data_b64)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted.decode('utf-8')

    def encrypt(self, sencrypted_data):
        key_bytes = self.key.encode('utf-8')
        iv_bytes = self.iv.encode('utf-8')
        data_bytes = sencrypted_data.encode('utf-8')
        padded_data = pad(data_bytes, AES.block_size)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        encrypted_bytes = cipher.encrypt(padded_data)
        encrypted_data_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_data_b64

    def ocr(self, base64img):
        dat2 = self.post("https://api.nn.ci/ocr/b64/text", data=base64img, headers=self.header, verify=False).text
        if dat2:
            return dat2
        else:
            return None

    def verification(self):
        random_uuid = str(uuid.uuid4())
        dat = self.fetch(f'{self.xurl}.verify/create?key={random_uuid}', headers=self.header, verify=False).content
        base64_img = base64.b64encode(dat).decode('utf-8')
        if not dat:
            return None
        code = self.ocr(base64_img)
        if not code:
            return None
        code = self.replace_code(code)
        if not (len(code) == 4 and code.isdigit()):
            return None
        return {'uuid': random_uuid, 'code': code}

    def replace_code(self, text):
        replacements = {'y': '9', '口': '0', 'q': '0', 'u': '0', 'o': '0', '>': '1', 'd': '0', 'b': '8', '已': '2','D': '0', '五': '5'}
        if len(text) == 3:
            text = text.replace('566', '5066')
            text = text.replace('066', '1666')
        return ''.join(replacements.get(c, c) for c in text)

    def _generate_random_ua(self):
        """生成随机安卓App User-Agent"""
        android_app_ua_templates = [
            "Dalvik/2.1.0 (Linux; U; Android {android_version}; {device} Build/{build})",
            "okhttp/3.14.9",
            "Mozilla/5.0 (Linux; Android {android_version}; {device}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{chrome_version} Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android {android_version}; {device}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{chrome_version} Mobile Safari/537.36",
            "VideoApp/3.4.5 (Linux;Android {android_version}) ExoPlayerLib/2.14.1",
        ]
        
        android_devices = [
            "SM-G991B", "SM-G996B", "SM-G998B",
            "Mi 11", "Mi 11 Pro", "Mi 11 Ultra",
            "Xiaomi 12", "Xiaomi 12 Pro", "Xiaomi 12 Ultra",
            "Pixel 6", "Pixel 6 Pro", "Pixel 7", "Pixel 7 Pro",
            "OnePlus 9", "OnePlus 9 Pro", "OnePlus 10", "OnePlus 10 Pro"
        ]
        
        build_versions = [
            "SKQ1.210506.001", "RP1A.200720.011", "SP1A.210812.016",
            "TKQ1.220807.001", "TP1A.220624.014", "TQ1A.230205.002"
        ]
        
        template = random.choice(android_app_ua_templates)
        android_version = random.randint(10, 14)
        device = random.choice(android_devices)
        build = random.choice(build_versions)
        chrome_version = f"{random.randint(90, 110)}.0.{random.randint(4000, 6000)}.{random.randint(100, 200)}"
        
        if "{android_version}" in template and "{device}" in template and "{build}" in template:
            return template.format(android_version=android_version, device=device, build=build)
        elif "{android_version}" in template and "{device}" in template and "{chrome_version}" in template:
            return template.format(android_version=android_version, device=device, chrome_version=chrome_version)
        elif "{android_version}" in template and "{device}" in template:
            return template.format(android_version=android_version, device=device)
        
        return template

# 导出类
if __name__ == '__main__':
    pass