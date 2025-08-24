# coding = utf-8
#!/usr/bin/python
# 新时代青年 2025.06.25 getApp第三版
import re,sys,uuid,json,base64,urllib3,random
from Crypto.Cipher import AES
from base.spider import Spider
from Crypto.Util.Padding import pad,unpad
sys.path.append('..')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Spider(Spider):
    xurl,key,iv,init_data,search_verify = '','','','',''
    header = {}
    sort_rule = []  # 存储排序规则
    
    def __init__(self):
        # 初始化时生成随机UA
        self.header = {'User-Agent': self._generate_random_ua()}

    def getName(self):
        return "首页"

    def init(self, extend=''):
        ext = json.loads(extend.strip())
        host = ext['host']
        
        # 处理host_index参数，从1开始计数
        host_index_str = str(ext.get('host_index', '1')).strip()
        try:
            host_index = int(host_index_str) if host_index_str else 1
        except ValueError:
            host_index = 1
        
        # 检查是否是有效的URL格式（支持IP、域名和端口）
        if not re.match(r'^https?:\/\/[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:\d+)?(\/)?$', host):
            response = self.fetch(host, headers=self.header, timeout=10, verify=False)
            text = response.text.strip()
            # 按行分割获取所有地址
            addresses = [line.strip() for line in text.splitlines() if line.strip()]
            
            # 根据host_index选择地址，索引从1开始
            if len(addresses) > 0:
                # 转换为0-based索引
                index = host_index - 1
                
                # 检查索引是否有效，无效则使用第一个地址
                if 0 <= index < len(addresses):
                    host = addresses[index]
                else:
                    host = addresses[0]  # 超出范围使用第一个地址
            
        host = host.rstrip('/')
        
        ua = ext.get('ua')
        if ua:
            self.header['User-Agent'] = ua  # 使用配置中的UA覆盖随机UA
        api = ext.get('api', '/api.php/getappapi')
        if str(api) == '2':
            api = '/api.php/qijiappapi'
        self.xurl = host + api
        self.key = ext['datakey']
        self.iv = ext.get('dataiv', self.key)
        
        # 获取排序规则
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

    def _generate_random_ua(self):
        """生成随机安卓App User-Agent"""
        # 安卓App常见的User-Agent格式
        android_app_ua_templates = [
            # 常见视频App UA格式
            "Dalvik/2.1.0 (Linux; U; Android {android_version}; {device} Build/{build})",
            "okhttp/4.9.3",
            "Mozilla/5.0 (Linux; Android {android_version}; {device}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{chrome_version} Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android {android_version}; {device}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{chrome_version} Mobile Safari/537.36",
            "VideoApp/3.4.5 (Linux;Android {android_version}) ExoPlayerLib/2.14.1",
            "Android_{android_version}_{device}",
            "VendorApp/4.2.0 Android/{android_version} ({device})"
        ]
        
        # 安卓设备列表
        android_devices = [
            "SM-G991B", "SM-G996B", "SM-G998B",  # Samsung Galaxy S21系列
            "Mi 11", "Mi 11 Pro", "Mi 11 Ultra",  # 小米
            "Xiaomi 12", "Xiaomi 12 Pro", "Xiaomi 12 Ultra",
            "Xiaomi 13", "Xiaomi 13 Pro", "Xiaomi 13 Ultra",
            "Xiaomi 14", "Xiaomi 14 Pro", "Xiaomi 14 Ultra",
            "Xiaomi 15", "Xiaomi 15 Pro", "Xiaomi 15 Ultra",
            "Redmi Note 10 Pro", "Redmi Note 11 Pro", "Redmi Note 12 Pro",
            "Pixel 6", "Pixel 6 Pro", "Pixel 7", "Pixel 7 Pro", "Pixel 8", "Pixel 8 Pro",  # Google Pixel
            "OnePlus 9", "OnePlus 9 Pro", "OnePlus 10", "OnePlus 10 Pro", "OnePlus 11",  # OnePlus
            "Vivo X70", "Vivo X70 Pro", "Vivo X80", "Vivo X80 Pro", "Vivo X90", "Vivo X90 Pro",  # Vivo
            "OPPO Find X3", "OPPO Find X3 Pro", "OPPO Find X5", "OPPO Find X5 Pro",  # OPPO
            "Realme GT", "Realme GT Neo", "Realme GT 2", "Realme GT 2 Pro"  # Realme
        ]
        
        # 构建版本列表
        build_versions = [
            "SKQ1.210506.001", "RP1A.200720.011", "SP1A.210812.016",
            "TKQ1.220807.001", "TP1A.220624.014", "TQ1A.230205.002",
            "RQ2A.210505.003", "SQ1D.220105.007", "SQ3A.220605.009"
        ]
        
        # 随机选择一个UA模板
        template = random.choice(android_app_ua_templates)
        
        # 填充模板参数
        android_version = random.randint(10, 14)
        device = random.choice(android_devices)
        build = random.choice(build_versions)
        chrome_version = f"{random.randint(90, 110)}.0.{random.randint(4000, 6000)}.{random.randint(100, 200)}"
        
        # 根据模板类型填充参数
        if "{android_version}" in template and "{device}" in template and "{build}" in template:
            return template.format(android_version=android_version, device=device, build=build)
        elif "{android_version}" in template and "{device}" in template and "{chrome_version}" in template:
            return template.format(android_version=android_version, device=device, chrome_version=chrome_version)
        elif "{android_version}" in template and "{device}" in template:
            return template.format(android_version=android_version, device=device)
        
        # 对于不需要参数的简单UA模板，直接返回
        return template

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
        url = f'{self.xurl}.index/typeFilterVodList'
        res = self.post(url=url, headers=self.header, data=payload, verify=False).json()
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
        payload = {
            'vod_id': did,
        }
        api_endpoints = ['vodDetail', 'vodDetail2']

        for endpoint in api_endpoints:
            url = f'{self.xurl}.index/{endpoint}'
            response = self.post(url=url, headers=self.header, data=payload, verify=False)

            if response.status_code == 200:
                response_data = response.json()
                encrypted_data = response_data['data']
                kjson1 = self.decrypt(encrypted_data)
                kjson = json.loads(kjson1)
                break
        videos = []
        play_form = ''
        play_url = ''
        lineid = 1
        name_count = {}
        
        # 线路排序逻辑
        if self.sort_rule:
            # 定义排序函数
            def sort_key(line):
                line_name = line['player_info']['show'].lower()
                
                # 检查是否匹配任何排序规则
                for idx, rule in enumerate(self.sort_rule):
                    # 部分匹配：只要线路名包含规则关键词就匹配
                    if rule in line_name:
                        return idx
                
                # 不在排序规则中的放在最后
                return len(self.sort_rule)
            
            # 对线路进行排序
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
        url = ''
        aid = id.split(',')
        uid = aid[0]
        kurl = aid[1]
        token = aid[2].replace('token+', '')
        player_parse_type = aid[3]
        parse_type = aid[4]
        if parse_type == '0':
            res =  {"parse": 0, "url": kurl, "header": {'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; 23113RK12C Build/SKQ1.231004.001)'}}
        elif parse_type == '2':
            res = {"parse": 1, "url": uid+kurl, "header": {'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; 23113RK12C Build/SKQ1.231004.001)'}}
        elif player_parse_type == '2':
            response = self.fetch(url=f'{uid}{kurl}',headers=self.header, verify=False)
            if response.status_code == 200:
                kjson1 = response.json()
                res = {"parse": 0, "url": kjson1['url'], "header": {'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; 23113RK12C Build/SKQ1.231004.001)'}}
        else:
            id1 = self.encrypt(kurl)
            payload = {
                'parse_api': uid,
                'url': id1,
                'player_parse_type': player_parse_type,
                'token': token
            }
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
            res = {"parse": 0, "playUrl": '', "url": url, "header": {'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; 23113RK12C Build/SKQ1.231004.001)'}}
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
            if self.search_verify:
                verifi = self.verification()
                if verifi is None:
                    return {'list':[]}
                payload['code'] = verifi['code']
                payload['key'] = verifi['uuid']
            url = f'{self.xurl}.index/searchList'
            res = self.post(url=url, data=payload, headers=self.header, verify=False).json()
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