# -*- coding: utf-8 -*-
# by @嗷呜
import json
import random
import re
import sys
import time
from base64 import b64decode, b64encode
import concurrent.futures
import requests
from Crypto.Hash import MD5
from pyquery import PyQuery as pq
sys.path.append('..')
from base.spider import Spider

class Spider(Spider):

    def init(self, extend=""):
        self.host='https://www.jumama.cc'
        self.headers.update({
            'referer': f'{self.host}/',
            'origin': self.host,
        })
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.get(self.host)
        pass

    def getName(self):
        pass

    def isVideoFormat(self, url):
        pass

    def manualVideoCheck(self):
        pass

    def destroy(self):
        pass

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="134", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    }

    config={
        "1":[{"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits"},{"n":"评分","v":"score"}]}],
        "2":[{"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits"},{"n":"评分","v":"score"}]}],
        "4":[{"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits"},{"n":"评分","v":"score"}]}],
      }

    def homeContent(self, filter):
        data=self.getpq()
        result = {}
        classes = []
        for k in data('.swiper-wrapper').eq(0)('li').items():
            i=k('a').attr('href')
            if i and 'type' in i:
                classes.append({
                    'type_name': k.text(),
                    'type_id': re.findall(r'\d+', i)[0],
                })
        result['class'] = classes
        result['list'] = self.getlist(data('.col-3-List li'))
        result['filters'] = self.config
        return result

    def homeVideoContent(self):
        pass

    def categoryContent(self, tid, pg, filter, extend):
        path=f"/list/{tid}_{pg}_desc_{extend.get('by','')}_0_0___.html"
        data=self.getpq(path)
        result = {}
        result['list'] = self.getlist(data('.col-3-List li'))
        result['page'] = pg
        result['pagecount'] = 9999
        result['limit'] = 90
        result['total'] = 999999
        return result

    def detailContent(self, ids):
        data=self.getpq(f"/detail/{ids[0]}.html")
        v=data('.ewave-content__detail')
        c=data('p')
        vod = {
            'type_name':c.eq(0)('a').text(),
            'vod_year': v('.data.hidden-sm').text(),
            'vod_remarks': v('h1').text(),
            'vod_actor': c.eq(1)('a').text(),
            'vod_director': c.eq(2)('a').text(),
            'vod_content': c.eq(4).text(),
            'vod_play_from': '',
            'vod_play_url': ''
        }
        nd=list(data('.numBox .hd li').items())
        pd=list(data('.numBox .bd .numList').items())
        n,p=[],[]
        for i,x in enumerate(nd):
            n.append(x.text())
            p.append('#'.join([f"{j.text()}${j('a').attr('href')}" for j in pd[i]('a').items()]))
        vod['vod_play_url']='$$$'.join(p)
        vod['vod_play_from']='$$$'.join(n)
        return {'list':[vod]}

    def searchContent(self, key, quick, pg="1"):
        # 使用session进行搜索请求，确保携带cookies和验证状态
        path = f"/search.html?wd={key}"
        data = self.getpq(path)
        return {'list': self.getlist(data('.col-3-List .item')), 'page': pg}

    def playerContent(self, flag, id, vipFlags):
        try:
            data = self.getpq(id)
            
            # 提取页面中的JavaScript变量
            script_text = data("script:contains('var view_path')").text()
            
            # 提取关键变量
            view_path_match = re.search(r"var view_path = '(.*?)';", script_text)
            view_path = view_path_match.group(1) if view_path_match else ""
            
            view_src_match = re.search(r"var view_src = '(.*?)';", script_text)
            view_src = view_src_match.group(1) if view_src_match else "1"
            
            view_num_match = re.search(r"var view_num = '(.*?)';", script_text)
            view_num = view_num_match.group(1) if view_num_match else "1"
            
            # 构造请求参数
            jxpath = '/jmmplayer/api.php'
            post_data = {
                'vid': view_path,
                'src': view_src,
                'num': view_num
            }
            
            # 发送请求获取播放数据
            response = self.session.post(f"{self.host}{jxpath}", data=post_data)
            result = response.json()
            
            if 'data' in result and 'url' in result['data']:
                data = result['data']
                if re.search(r'\.m3u8|\.mp4', data['url']):
                    url = data['url']
                elif data.get('urlmode') == 1:
                    url = self.decode1(data['url'])
                elif data.get('urlmode') == 2:
                    url = self.decode2(data['url'])
                else:
                    url = None
            else:
                # 尝试直接从iframe提取
                iframe_src = data("#viewPlayer iframe").attr("src")
                if iframe_src:
                    url = f"{self.host}{iframe_src}"
                else:
                    url = None
            
            if not url:
                raise Exception('未找到播放地址')
                
            p, c = 0, ''
            
        except Exception as e:
            self.log(f"解析失败: {e}")
            p, url, c = 1, f"{self.host}{id}", 'document.querySelector("#playleft iframe").contentWindow.document.querySelector("#start").click()'
        
        return {
            'parse': p, 
            'url': url, 
            'header': {
                'User-Agent': 'okhttp/3.12.1',
                'Referer': f'{self.host}/'
            },
            'click': c
        }

    def localProxy(self, param):
        wdict=json.loads(self.d64(param['wdict']))
        url=f"{wdict['jx']}{wdict['id']}"
        data=pq(self.fetch(url,headers=self.headers).text)
        html=data('script').eq(-1).text()
        url = re.search(r'src="(.*?)"', html).group(1)
        return [302,'text/html',None,{'Location':url}]

    def liveContent(self, url):
        pass

    def getpq(self, path='',min=0,max=3):
        data = self.session.get(f"{self.host}{path}")
        data=data.text
        try:
            if '人机验证' in data:
                print(f"第{min}次尝试人机验证")
                jstr=pq(data)('script').eq(-1).html()
                token,tpath,stt=self.extract(jstr)
                body={'value':self.encrypt(self.host,stt),'token':self.encrypt(token,stt)}
                cd=self.session.post(f"{self.host}{tpath}",data=body)
                if min>max:raise Exception('人机验证失败')
                return self.getpq(path,min+1,max)
            return pq(data)
        except:
            return pq(data.encode('utf-8'))

    def encrypt(self, input_str,staticchars):
        encodechars = ""
        for char in input_str:
            num0 = staticchars.find(char)
            if num0 == -1:
                code = char
            else:
                code = staticchars[(num0 + 3) % 62]
            num1 = random.randint(0, 61)
            num2 = random.randint(0, 61)
            encodechars += staticchars[num1] + code + staticchars[num2]
        return self.e64(encodechars)

    def extract(self, js_code):
        token_match = re.search(r'var token = encrypt\("([^"]+)"\);', js_code)
        token_value = token_match.group(1) if token_match else None
        url_match = re.search(r'var url = \'([^\']+)\';', js_code)
        url_value = url_match.group(1) if url_match else None
        staticchars_match = re.search(r'var\s+staticchars\s*=\s*["\']([^"\']+)["\'];', js_code)
        staticchars = staticchars_match.group(1) if staticchars_match else None
        return token_value, url_value,staticchars

    def decode1(self, val):
        url = self._custom_str_decode(val)
        parts = url.split("/")
        result = "/".join(parts[2:])
        key1 = json.loads(self.d64(parts[1]))
        key2 = json.loads(self.d64(parts[0]))
        decoded = self.d64(result)
        return self._de_string(key1, key2, decoded)

    def _custom_str_decode(self, val):
        decoded = self.d64(val)
        key = self.md5("test")
        result = ""
        for i in range(len(decoded)):
            result += chr(ord(decoded[i]) ^ ord(key[i % len(key)]))
        return self.d64(result)

    def _de_string(self, key_array, value_array, input_str):
        result = ""
        for char in input_str:
            if re.match(r'^[a-zA-Z]$', char):
                if char in key_array:
                    index = key_array.index(char)
                    result += value_array[index]
                    continue
            result += char
        return result

    def decode2(self, url):
        key = "PXhw7UT1B0a9kQDKZsjIASmOezxYG4CHo5Jyfg2b8FLpEvRr3WtVnlqMidu6cN"
        url=self.d64(url)
        result = ""
        i = 1
        while i < len(url):
            try:
                index = key.find(url[i])
                if index == -1:
                    char = url[i]
                else:
                    char = key[(index + 59) % 62]
                result += char
            except IndexError:
                break
            i += 3
        return result

    def getlist(self, data):
        videos = []
        for i in data.items():
            id = i('a').attr('href')
            if id:
                id = re.search(r'\d+', id).group(0)
                img = i('.item-pic').attr('data-echo')
                if img and 'url=' in img: img = f'{self.host}{img}'
                videos.append({
                    'vod_id': id,
                    'vod_name': i('a').attr('title'),
                    'vod_pic': img,
                    'vod_remarks': i('.item-num').text() or i('.item-des').text().replace('&nbsp', '')
                })
        return videos

    def e64(self, text):
        try:
            text_bytes = text.encode('utf-8')
            encoded_bytes = b64encode(text_bytes)
            return encoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64编码错误: {str(e)}")
            return ""

    def d64(self,encoded_text):
        try:
            encoded_bytes = encoded_text.encode('utf-8')
            decoded_bytes = b64decode(encoded_bytes)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64解码错误: {str(e)}")
            return ""

    def md5(self, text):
        h = MD5.new()
        h.update(text.encode('utf-8'))
        return h.hexdigest()