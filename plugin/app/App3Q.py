import hashlib
import time
import random
import json
import urllib.parse
import re
from base.spider import Spider

class Spider(Spider):
    def init(self, extend=""):
        """初始化，extend为ext配置字典/JSON字符串"""
        if isinstance(extend, str) and extend.strip():
            try:
                extend = json.loads(extend)
            except:
                extend = {"host": extend.strip()}
        ext = extend if isinstance(extend, dict) else {}
        self.base_url = ext.get("host", "")
        self.finger = ext.get("finger", "")
        self.aid = ext.get("pkg", "")
        self.sk = ext.get("sk", "")
        self.v = ext.get("ver", "")
        self.device_id = ext.get("deviceId", "")
        self.device_brand = ext.get("deviceBrand", "")
        self.device_model = ext.get("deviceModel", "")
        self.update_id = ext.get("updateId", "")
        self.play_order = [x.strip() for x in re.split(r"[,，|\s]+", ext.get("playFrom", "")) if x.strip()]
    
    def _build_headers(self):
        headers = {
            "user-agent": "okhttp/4.12.0",
            "accept": "application/json",
            "x-platform": "android",
            "x-ave": self.v,
            "x-aid": self.aid,
            "x-device-id": self.device_id,
            "x-device-brand": self.device_brand,
            "x-device-model": self.device_model,
            "x-update-id": self.update_id,
        }
        timestamp = str(int(time.time()))
        nonce = str(random.randint(1, 999))
        headers["x-time"] = timestamp
        headers["x-nonc"] = nonce
        sign_str = f"finger={self.finger}&id={self.aid}&nonce={nonce}&sk={self.sk}&time={timestamp}&v={self.v}"
        sign = hashlib.sha256(sign_str.encode()).hexdigest().upper()
        headers["x-sign"] = sign
        return headers
    
    def _api_request(self, path):
        url = self.base_url + path
        headers = self._build_headers()
        resp = self.fetch(url, headers=headers)
        return json.loads(resp.text)
    
    def homeContent(self, filter=False):
        result = self._api_request("/api.php/app/index/home")
        data = result.get("data", {})
        classes = []
        categories = data.get("categories", [])
        for cat in categories:
            type_name = cat.get("type_name", "")
            if type_name:
                classes.append({"type_id": type_name, "type_name": type_name})
        vod_list = []
        recommend = data.get("recommend", [])
        for item in recommend:
            vod_list.append({
                "vod_id": item.get("vod_id", ""),
                "vod_name": item.get("vod_name", ""),
                "vod_pic": item.get("vod_pic", ""),
                "vod_remarks": item.get("vod_remarks", "")
            })
        return {"class": classes, "list": vod_list}
    
    def categoryContent(self, tid, pg, filter=False, extend={}):
        pg = pg or "1"
        url = f"/api.php/app/filter/vod?type_name={urllib.parse.quote(tid)}&page={pg}&sort=hits"
        result = self._api_request(url)
        vod_list = []
        data = result.get("data", [])
        for item in data:
            vod_list.append({
                "vod_id": item.get("vod_id", ""),
                "vod_name": item.get("vod_name", ""),
                "vod_pic": item.get("vod_pic", ""),
                "vod_remarks": item.get("vod_remarks", "")
            })
        return {"list": vod_list, "page": int(pg), "pagecount": 0, "limit": 24, "total": len(vod_list)}
    
    def detailContent(self, ids):
        if not ids or len(ids) == 0:
            return {"list": []}
        vod_id = ids[0]
        result = self._api_request(f"/api.php/app/vod/get_detail?vod_id={vod_id}")
        data = result.get("data", [])
        if not data:
            return {"list": []}
        detail = data[0]
        vod_name = detail.get("vod_name", "")
        vod_pic = detail.get("vod_pic", "")
        
        play_from = detail.get("vod_play_from", "")
        play_url = detail.get("vod_play_url", "")
        
        player_map = {}
        players = result.get("vodplayer", [])
        for p in players:
            player_map[p.get("from", "")] = p.get("show", "")
        
        from_parts = play_from.split("$$$") if play_from else []
        url_parts = play_url.split("$$$") if play_url else []
        if self.play_order and len(from_parts) > 1:
            if len(url_parts) < len(from_parts):
                url_parts = url_parts + [""] * (len(from_parts) - len(url_parts))
            miss = len(self.play_order) + 1
            def order_key(f):
                names = [f, player_map.get(f, "")]
                for i, o in enumerate(self.play_order):
                    for n in names:
                        if n and (n == o or o in n or n in o):
                            return i
                return miss
            combined = sorted(zip(from_parts, url_parts[:len(from_parts)]), key=lambda t: order_key(t[0]))
            from_parts = [t[0] for t in combined]
            url_parts = [t[1] for t in combined]
        
        
        from_display = []
        for f in from_parts:
            display = player_map.get(f, f)
            from_display.append(display)
        play_from_str = "$$$".join(from_display) if from_display else ""
        
        play_url_segments = []
        for i, f in enumerate(from_parts):
            if i >= len(url_parts):
                break
            episodes = url_parts[i].split("#")
            ep_segments = []
            for ep in episodes:
                parts = ep.split("$")
                if len(parts) >= 2:
                    ep_name = parts[0]
                    ep_url = parts[1]
                    match = re.search(r'\d+', ep_name)
                    ep_num = match.group() if match else "1"
                    ep_segments.append(f"{ep_name}${ep_url}@{f}@{vod_name}@{ep_num}")
                else:
                    ep_segments.append(ep)
            if ep_segments:
                play_url_segments.append("#".join(ep_segments))
        play_url_str = "$$$".join(play_url_segments) if play_url_segments else play_url
        
        vod = {
            "vod_id": vod_id,
            "vod_name": vod_name,
            "vod_pic": vod_pic,
            "vod_class": detail.get("vod_class", ""),
            "vod_remarks": detail.get("vod_remarks", ""),
            "vod_content": detail.get("vod_content", "").strip(),
            "vod_actor": detail.get("vod_actor", ""),
            "vod_director": detail.get("vod_director", ""),
            "vod_play_from": play_from_str,
            "vod_play_url": play_url_str
        }
        return {"list": [vod]}
    
    def searchContent(self, key, quick=False, pg="1"):
        if not key:
            return {"list": [], "page": 1, "pagecount": 0}
        url = f"/api.php/app/search/index?wd={urllib.parse.quote(key)}&page={pg}&limit=15"
        result = self._api_request(url)
        vod_list = []
        data = result.get("data", [])
        for item in data:
            vod_list.append({
                "vod_id": item.get("vod_id", ""),
                "vod_name": item.get("vod_name", ""),
                "vod_pic": item.get("vod_pic", ""),
                "vod_remarks": item.get("vod_remarks", "")
            })
        return {"list": vod_list, "page": int(pg), "pagecount": 1}
    
    def playerContent(self, flag, id, vipFlags=None):
        parts = id.split("@")
        if len(parts) < 4:
            return {"parse": 0, "url": "", "header": {}}
        
        play_url = parts[0].strip()
        vod_from = parts[1].strip()
        vod_name = parts[2].strip()
        vod_index = parts[3].strip()
        
        # 如果已经包含 http，直接返回（可能已经是解码后的地址）
        if play_url.startswith("http"):
            return {"parse": 0, "url": play_url, "header": {}}
        
        # 提取真实的加密地址（去掉第XX集$前缀）
        if "$" in play_url:
            play_url = play_url.split("$")[1]
        
        # 调用解码接口
        encoded_url = urllib.parse.quote(play_url, safe="")
        decode_path = f"/api.php/app/decode/url/?url={encoded_url}&vodFrom={vod_from}"
        
        for attempt in range(3):
            try:
                result = self._api_request(decode_path)
                if not result:
                    continue
                code = result.get("code", -1)
                if code == 2 and "challenge" in result:
                    challenge = result.get("challenge", "").strip()
                    if challenge:
                        token = self._decode_challenge(challenge)
                        if token:
                            path_with_token = decode_path + "&token=" + token
                            result = self._api_request(path_with_token)
                            if result:
                                decoded = result.get("data", "").strip()
                                if decoded:
                                    return {"parse": 0, "url": decoded, "header": {}}
                else:
                    decoded = result.get("data", "").strip()
                    if decoded:
                        # 如果解码后的数据以 http 开头，直接返回
                        if decoded.startswith("http"):
                            return {"parse": 0, "url": decoded, "header": {}}
                        # 否则可能是新的加密地址，尝试再次解码
                        elif "$" in decoded:
                            # 提取加密地址部分
                            parts2 = decoded.split("$")
                            if len(parts2) >= 2:
                                new_url = parts2[1]
                                encoded_new = urllib.parse.quote(new_url, safe="")
                                decode_path2 = f"/api.php/app/decode/url/?url={encoded_new}&vodFrom={vod_from}"
                                result2 = self._api_request(decode_path2)
                                if result2:
                                    decoded2 = result2.get("data", "").strip()
                                    if decoded2:
                                        return {"parse": 0, "url": decoded2, "header": {}}
            except Exception:
                pass
        
        return {"parse": 0, "url": "", "header": {}}
    
    def _decode_challenge(self, challenge):
        try:
            pattern = r'_0x1\s*=\s*\[(.*?)\];'
            match = re.search(pattern, challenge)
            if not match:
                return ""
            parts = match.group(1).split(",")
            if len(parts) < 4:
                return ""
            a = parts[0].strip().strip("'\"")
            b = parts[1].strip().strip("'\"")
            c = parts[2].strip().strip("'\"")
            d = parts[3].strip().strip("'\"")
            format_str = f"{a}:{b}:{c}:{d}"
            hash_val = 0
            for ch in format_str:
                hash_val = ((hash_val << 5) - hash_val + ord(ch)) & 0xFFFFFFFF
            return f"{a}:{hex(abs(hash_val))[2:]}:{b[:8]}"
        except Exception:
            return ""