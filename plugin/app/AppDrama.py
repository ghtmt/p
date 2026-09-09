import base64
import json
import random
import re
import time
from base.spider import Spider

_SB = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])
_ISB = bytearray(256)
for _i in range(256):
    _ISB[_SB[_i]] = _i


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a = ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1
    return r


_TE0 = [0] * 256
_TD0 = [0] * 256
for _i in range(256):
    _s = _SB[_i]
    _t = _ISB[_i]
    _TE0[_i] = (_gmul(_s, 2) << 24) | (_s << 16) | (_s << 8) | _gmul(_s, 3)
    _TD0[_i] = (_gmul(_t, 14) << 24) | (_gmul(_t, 9) << 16) | (_gmul(_t, 13) << 8) | _gmul(_t, 11)


def _rot(tbl, n):
    return [((x >> n) | (x << (32 - n))) & 0xffffffff for x in tbl]


_TE1, _TE2, _TE3 = _rot(_TE0, 8), _rot(_TE0, 16), _rot(_TE0, 24)
_TD1, _TD2, _TD3 = _rot(_TD0, 8), _rot(_TD0, 16), _rot(_TD0, 24)
_RCON = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
         0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]


def _sub_word(t):
    return (_SB[(t >> 24) & 255] << 24) | (_SB[(t >> 16) & 255] << 16) | (_SB[(t >> 8) & 255] << 8) | _SB[t & 255]


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = _sub_word(((t << 8) | (t >> 24)) & 0xffffffff) ^ _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = _sub_word(t)
        w.append(w[i - nk] ^ t)
    return w, nr


def _expand_key_dec(key):
    w, nr = _expand_key(key)
    d = []
    for r in range(nr, -1, -1):
        d += w[4 * r:4 * r + 4]
    for i in range(4, 4 * nr):
        x = d[i]
        d[i] = _TD0[_SB[(x >> 24) & 255]] ^ _TD1[_SB[(x >> 16) & 255]] ^ _TD2[_SB[(x >> 8) & 255]] ^ _TD3[_SB[x & 255]]
    return d, nr


def _enc_block(w, nr, s0, s1, s2, s3):
    s0 ^= w[0]
    s1 ^= w[1]
    s2 ^= w[2]
    s3 ^= w[3]
    k = 4
    for _ in range(nr - 1):
        s0, s1, s2, s3 = (
            _TE0[s0 >> 24] ^ _TE1[(s1 >> 16) & 255] ^ _TE2[(s2 >> 8) & 255] ^ _TE3[s3 & 255] ^ w[k],
            _TE0[s1 >> 24] ^ _TE1[(s2 >> 16) & 255] ^ _TE2[(s3 >> 8) & 255] ^ _TE3[s0 & 255] ^ w[k + 1],
            _TE0[s2 >> 24] ^ _TE1[(s3 >> 16) & 255] ^ _TE2[(s0 >> 8) & 255] ^ _TE3[s1 & 255] ^ w[k + 2],
            _TE0[s3 >> 24] ^ _TE1[(s0 >> 16) & 255] ^ _TE2[(s1 >> 8) & 255] ^ _TE3[s2 & 255] ^ w[k + 3])
        k += 4
    return (((_SB[s0 >> 24] << 24) | (_SB[(s1 >> 16) & 255] << 16) | (_SB[(s2 >> 8) & 255] << 8) | _SB[s3 & 255]) ^ w[k],
            ((_SB[s1 >> 24] << 24) | (_SB[(s2 >> 16) & 255] << 16) | (_SB[(s3 >> 8) & 255] << 8) | _SB[s0 & 255]) ^ w[k + 1],
            ((_SB[s2 >> 24] << 24) | (_SB[(s3 >> 16) & 255] << 16) | (_SB[(s0 >> 8) & 255] << 8) | _SB[s1 & 255]) ^ w[k + 2],
            ((_SB[s3 >> 24] << 24) | (_SB[(s0 >> 16) & 255] << 16) | (_SB[(s1 >> 8) & 255] << 8) | _SB[s2 & 255]) ^ w[k + 3])


def _dec_block(w, nr, s0, s1, s2, s3):
    s0 ^= w[0]
    s1 ^= w[1]
    s2 ^= w[2]
    s3 ^= w[3]
    k = 4
    for _ in range(nr - 1):
        s0, s1, s2, s3 = (
            _TD0[s0 >> 24] ^ _TD1[(s3 >> 16) & 255] ^ _TD2[(s2 >> 8) & 255] ^ _TD3[s1 & 255] ^ w[k],
            _TD0[s1 >> 24] ^ _TD1[(s0 >> 16) & 255] ^ _TD2[(s3 >> 8) & 255] ^ _TD3[s2 & 255] ^ w[k + 1],
            _TD0[s2 >> 24] ^ _TD1[(s1 >> 16) & 255] ^ _TD2[(s0 >> 8) & 255] ^ _TD3[s3 & 255] ^ w[k + 2],
            _TD0[s3 >> 24] ^ _TD1[(s2 >> 16) & 255] ^ _TD2[(s1 >> 8) & 255] ^ _TD3[s0 & 255] ^ w[k + 3])
        k += 4
    return (((_ISB[s0 >> 24] << 24) | (_ISB[(s3 >> 16) & 255] << 16) | (_ISB[(s2 >> 8) & 255] << 8) | _ISB[s1 & 255]) ^ w[k],
            ((_ISB[s1 >> 24] << 24) | (_ISB[(s0 >> 16) & 255] << 16) | (_ISB[(s3 >> 8) & 255] << 8) | _ISB[s2 & 255]) ^ w[k + 1],
            ((_ISB[s2 >> 24] << 24) | (_ISB[(s1 >> 16) & 255] << 16) | (_ISB[(s0 >> 8) & 255] << 8) | _ISB[s3 & 255]) ^ w[k + 2],
            ((_ISB[s3 >> 24] << 24) | (_ISB[(s2 >> 16) & 255] << 16) | (_ISB[(s1 >> 8) & 255] << 8) | _ISB[s0 & 255]) ^ w[k + 3])


def _pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def _unpad(data):
    return data[:-data[-1]] if data and 1 <= data[-1] <= 16 else data


def _blocks(data):
    return [tuple(int.from_bytes(data[i + j:i + j + 4], "big") for j in range(0, 16, 4)) for i in range(0, len(data) - len(data) % 16, 16)]


def _join(parts):
    return b"".join(x.to_bytes(4, "big") for p in parts for x in p)


def _ecb_encrypt(data, key):
    w, nr = _expand_key(key)
    return _join([_enc_block(w, nr, *b) for b in _blocks(_pad(data))])


def _ecb_decrypt(data, key):
    w, nr = _expand_key_dec(key)
    return _unpad(_join([_dec_block(w, nr, *b) for b in _blocks(data)]))


def _cbc_encrypt(data, key, iv):
    w, nr = _expand_key(key)
    prev = tuple(int.from_bytes(iv[i:i + 4], "big") for i in range(0, 16, 4))
    out = []
    for b in _blocks(_pad(data)):
        prev = _enc_block(w, nr, *[b[i] ^ prev[i] for i in range(4)])
        out.append(prev)
    return _join(out)


def _cbc_decrypt(data, key, iv):
    w, nr = _expand_key_dec(key)
    prev = tuple(int.from_bytes(iv[i:i + 4], "big") for i in range(0, 16, 4))
    out = []
    for b in _blocks(data):
        out.append(tuple(x ^ y for x, y in zip(_dec_block(w, nr, *b), prev)))
        prev = b
    return _unpad(_join(out))


def _der_len(data, i):
    n = data[i]
    i += 1
    if n & 0x80:
        c = n & 0x7f
        n = int.from_bytes(data[i:i + c], "big")
        i += c
    return n, i


def _rsa_pub(key):
    data = base64.b64decode(key + "=" * (-len(key) % 4))
    i = 0
    if data[i] != 0x30:
        return 0, 0
    _, i = _der_len(data, i + 1)
    if data[i] == 0x30:
        n, i = _der_len(data, i + 1)
        i += n
        if data[i] != 0x03:
            return 0, 0
        n, i = _der_len(data, i + 1)
        data = data[i + 1:i + n]
        i = 0
        if data[i] != 0x30:
            return 0, 0
        _, i = _der_len(data, i + 1)
    if data[i] != 0x02:
        return 0, 0
    n, i = _der_len(data, i + 1)
    mod = int.from_bytes(data[i:i + n], "big")
    i += n
    if data[i] != 0x02:
        return 0, 0
    n, i = _der_len(data, i + 1)
    return mod, int.from_bytes(data[i:i + n], "big")


def _rsa_encrypt(text, key):
    mod, exp = _rsa_pub(key)
    if not mod:
        return ""
    size = (mod.bit_length() + 7) // 8
    msg = text.encode("utf-8")
    fill = bytes(random.randrange(1, 256) for _ in range(size - 3 - len(msg)))
    block = b"\x00\x02" + fill + b"\x00" + msg
    return base64.b64encode(pow(int.from_bytes(block, "big"), exp, mod).to_bytes(size, "big")).decode()


def _varint(value):
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _pb_str(field, text):
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return _varint((field << 3) | 2) + _varint(len(raw)) + raw


def _pb_int(field, value):
    return _varint(field << 3) + _varint(int(value))


def _read_varint(data, i):
    value = shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        value |= (b & 0x7f) << shift
        if not b & 0x80:
            break
        shift += 7
    return value, i


def _pb_parse(data):
    out = {}
    i = 0
    while i < len(data):
        tag, i = _read_varint(data, i)
        wire = tag & 7
        if wire == 0:
            value, i = _read_varint(data, i)
        elif wire == 2:
            size, i = _read_varint(data, i)
            value = data[i:i + size]
            i += size
        elif wire == 5:
            value = int.from_bytes(data[i:i + 4], "little")
            i += 4
        elif wire == 1:
            value = int.from_bytes(data[i:i + 8], "little")
            i += 8
        else:
            break
        out.setdefault(tag >> 3, []).append(value)
    return out


def _ps(msg, field):
    vals = msg.get(field) or []
    return vals[-1].decode("utf-8", "ignore") if vals and isinstance(vals[-1], bytes) else ""


def _pi(msg, field):
    vals = msg.get(field) or []
    return vals[-1] if vals and isinstance(vals[-1], int) else 0


def _pm(msg, field):
    vals = msg.get(field) or []
    return _pb_parse(vals[-1]) if vals and isinstance(vals[-1], bytes) else {}


class Spider(Spider):
    VIDEO = re.compile(r"\.(mp4|m3u8|flv|mkv|avi|ts|mov|mpd|m4a|wmv)(\?.*)?$", re.I)
    FILTER_KEYS = ("class", "lang", "area", "year", "extend_sort")
    FILTER_NAMES = {"class": "类型", "lang": "语言", "area": "地区", "year": "年份", "extend_sort": "排序"}
    CHARS = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    UA = "okhttp/3.12.1"
    PAGE_SIZE = 21

    def init(self, extend=""):
        ext = extend if isinstance(extend, dict) else {}
        if isinstance(extend, str) and extend.strip():
            try:
                ext = json.loads(extend)
            except:
                ext = {}
        self.ext = ext
        self.host = (ext.get("host") or "").rstrip("/")
        self.public_key = ext.get("publicKey", "")
        self.dyn_key = ""
        self.pkg = ext.get("pkg", "")
        self.app_name = ext.get("appName", "")
        self.version = ext.get("version", "")
        self.decrypt = str(ext.get("decrypt", "1"))
        self.data_key = (ext.get("dataKey") or "").encode("utf-8")
        self.data_iv = (ext.get("dataIv") or "").encode("utf-8")
        self.params_key = b"ed5fdsgucxumegqa"
        self.android_id = "".join(random.choice("0123456789abcdef") for _ in range(16))
        self.sess = None
        self.classes = []
        self.filters = {}
        self.site = ext.get("site", "")
        self.zoned = False
        self.home_cache = None
        self.rec_cache = None
        self.rec_thread = None
        self.play_order = [x.strip() for x in re.split(r"[,，|\s]+", str(ext.get("playFrom") or "")) if x.strip()]
        if not self.host and self.site:
            cached = self._cache_get("drama_host")
            if cached:
                self.host = cached
        if not self.host and self.site:
            self._refresh_host()
    def _cache_get(self, key, stale=False):
        try:
            value = self.getCache(key)
            if isinstance(value, dict) and value.get("d") and (stale or int(value.get("e", 0)) > int(time.time())):
                return value.get("d")
        except:
            pass
        return None
    def _cache_set(self, key, data, ttl):
        try:
            self.setCache(key, {"e": int(time.time()) + ttl, "d": data})
        except:
            pass
    def _refresh_host(self):
        if not self.site:
            return False
        try:
            domain = json.loads(self._get(self.site, {"User-Agent": self.UA})).get("domain", "")
        except:
            return False
        if not domain:
            return False
        self.host = domain.rstrip("/")
        self._cache_set("drama_host", self.host, 3600)
        return True
    def _ensure_zone(self):
        if self.zoned:
            return self.dyn_key
        self.zoned = True
        cached = self._cache_get("drama_dynkey")
        if cached:
            self.dyn_key = cached
            return self.dyn_key
        key = self._zone()
        if key:
            self._cache_set("drama_dynkey", key, 3600)
        return key

    def _rand(self, size):
        return "".join(random.choice(self.CHARS) for _ in range(size - 1)) + "="

    def _session(self):
        if self.sess is None:
            try:
                import requests
                self.sess = requests.Session()
            except:
                self.sess = False
        return self.sess or None
    def _get(self, url, headers):
        sess = self._session()
        if sess:
            try:
                return sess.get(url, headers=headers, timeout=45).content.decode("utf-8", "ignore")
            except:
                pass
        try:
            return self.fetch(url, headers=headers, timeout=45).text
        except:
            return ""

    def _post(self, url, body, headers):
        sess = self._session()
        if sess:
            try:
                return sess.post(url, data=body, headers=headers, timeout=45).content
            except:
                pass
        try:
            rsp = self.post(url, data=body, headers=headers, timeout=45)
            return rsp.content if hasattr(rsp, "content") else (rsp.text or "").encode("utf-8", "ignore")
        except:
            return b""

    def _device(self):
        uid = "".join(random.choice("0123456789ABCDEF") for _ in range(32))
        return {
            "country": "CN", "vName": self.version, "cpuId": "MT6893Z%2FCZA", "young": 0,
            "facturer": "Xiaomi", "pkg": self.pkg, "uuid": uid, "resolution": "1080x2272",
            "mac": "02%3A00%3A00%3A00%3A00%3A00", "abid": "397", "model": "M2012K11AC",
            "plat": "android", "udid": uid, "dpi": "440", "net": "1", "lang": "zh",
            "brand": "Xiaomi", "density": "2.75", "appName": self.app_name, "cpu": "arm64-v8a",
            "chid": "10000", "carrier": "%E8%81%94%E9%80%9A", "_vOsCode": 33, "vOs": "13",
            "v": 1, "tenantId": "", "vApp": self.version.replace(".", ""), "device": 0,
            "androidID": self.android_id}

    def _wrap(self, device, proto):
        data = _cbc_encrypt(json.dumps(device, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), self.params_key, self.params_key).hex()
        mime = "application/x-protobuf" if proto else "application/json; charset=utf-8"
        return {
            "User-Agent": self.UA,
            "Accept": "application/x-protobuf" if proto else "application/json",
            "Content-Type": mime,
            "publicParams": json.dumps({"paramsData": data}, separators=(",", ":"))}

    def _headers(self):
        key = self.dyn_key or self.public_key
        device = self._device()
        stamp = int(time.time() * 1000)
        rnd = self._rand(16)
        sig2 = base64.b64encode(_ecb_encrypt((str(stamp) + rnd).encode("utf-8"), self.data_iv)).decode()
        device["sig"] = _rsa_encrypt(str(stamp) + rnd + (device["vApp"] or "3019"), key)
        device["random_str"] = rnd
        device["timestamp"] = stamp
        device["sig2"] = sig2[:8]
        device["sig3"] = sig2[8:]
        return self._wrap(device, True)

    def _json_headers(self):
        return self._wrap(self._device(), False)

    def _body(self, params):
        stamp = int(time.time() * 1000)
        rnd = self._rand(8)
        query = "&".join(k + "=" + str(v) for k, v in params.items() if str(v or ""))
        enc = rnd + base64.b64encode(_ecb_encrypt((query + str(stamp)).encode("utf-8"), self.data_key)).decode()
        return _pb_str(1, enc[:20]) + _pb_str(2, enc[20:]) + _pb_str(3, self._rand(20)) + _pb_int(4, stamp) + _pb_str(5, rnd)

    def _zone(self):
        stamp = int(time.time() * 1000)
        rnd = self._rand(16)
        body = _pb_int(1, stamp) + _pb_str(2, _rsa_encrypt(str(stamp) + rnd, self.public_key)) + _pb_str(3, self._rand(16)) + _pb_str(4, rnd) + _pb_str(5, self._rand(16))
        outer = _pb_parse(self._post(self.host + "/api/v5/find/app/zone", body, self._headers()))
        self.last_code = _pi(outer, 1)
        self.last_msg = _ps(outer, 2)
        msg = _pb_parse((outer.get(3) or [b""])[-1])
        key = _ps(msg, 2) + _ps(msg, 3) + _ps(msg, 4) + _ps(msg, 5)
        if key and _rsa_pub(key)[0]:
            self.dyn_key = key
        return self.dyn_key

    def _result(self, raw):
        return _pb_parse(_pb_parse(raw).get(3)[-1]) if raw and _pb_parse(raw).get(3) else {}

    def _api(self, path, params):
        if not self.host:
            self._refresh_host()
        if not self.dyn_key and not self.zoned:
            cached = self._cache_get("drama_dynkey")
            if cached:
                self.dyn_key = cached
                self.zoned = True
        outer = _pb_parse(self._post(self.host + path, self._body(params), self._headers()))
        self.last_code = _pi(outer, 1)
        self.last_msg = _ps(outer, 2)
        if self.last_code != 1 and not self.zoned and self._ensure_zone():
            outer = _pb_parse(self._post(self.host + path, self._body(params), self._headers()))
            self.last_code = _pi(outer, 1)
            self.last_msg = _ps(outer, 2)
        data = (outer.get(3) or [b""])[-1]
        return _pb_parse(data) if data else {}

    def _sort_play(self, groups):
        items = list(groups.items())
        if not self.play_order or len(items) < 2:
            return items
        miss = len(self.play_order)

        def rank(name):
            for i, rule in enumerate(self.play_order):
                if name and (name == rule or rule in name or name in rule):
                    return i
            return miss

        return sorted(items, key=lambda t: rank(t[0]))

    def _vod_list(self, page):
        out = []
        for raw in page.get(1) or []:
            item = _pb_parse(raw)
            cover = _pm(item, 2)
            out.append({
                "vod_id": str(_pi(item, 3)),
                "vod_name": _ps(item, 5),
                "vod_pic": _ps(cover, 2) or _ps(cover, 1),
                "vod_remarks": _ps(item, 13) or _ps(item, 11)})
        return out

    def homeContent(self, filter=False):
        if not self.host:
            self._refresh_host()
        self._prefetch_rec()
        if self.home_cache:
            self.classes = self.home_cache.get("class") or []
            self.filters = self.home_cache.get("filters") or {}
            return self.home_cache
        cached = self._cache_get("drama_home")
        if cached:
            self.home_cache = cached
            self.classes = cached.get("class") or []
            self.filters = cached.get("filters") or {}
            return cached
        text = self._get(self.host + "/api/v3/drama/getCategory?orderBy=type_id", self._json_headers())
        try:
            data = json.loads(text).get("data") or []
        except:
            data = []
        if not data:
            stale = self._cache_get("drama_home", True)
            if stale:
                self.home_cache = stale
                self.classes = stale.get("class") or []
                self.filters = stale.get("filters") or {}
                return stale
        classes, filters = [], {}
        for cat in data:
            name = str(cat.get("name", ""))
            if not name or name == "公告":
                continue
            tid = str(cat.get("id", ""))
            classes.append({"type_id": tid, "type_name": name})
            try:
                cfg = json.loads(cat.get("converUrl") or "{}")
            except:
                cfg = {}
            items = []
            for key in self.FILTER_KEYS:
                values = [x for x in str(cfg.get(key) or "").split(",") if x]
                if values:
                    items.append({"key": key, "name": self.FILTER_NAMES.get(key, key), "value": [{"n": v, "v": v} for v in values]})
            if items:
                filters[tid] = items
        self.classes = classes
        self.filters = filters
        result = {"class": classes, "filters": filters}
        if classes:
            self.home_cache = result
            self._cache_set("drama_home", result, 3600)
        return result

    def _prefetch_rec(self):
        if self.rec_cache or self.rec_thread or not self.host:
            return
        cached = self._cache_get("drama_rec")
        if cached:
            self.rec_cache = cached
            return
        try:
            from threading import Thread
            self.rec_thread = Thread(target=self._load_rec)
            self.rec_thread.daemon = True
            self.rec_thread.start()
        except:
            self.rec_thread = None

    def homeVideoContent(self):
        if self.rec_thread:
            try:
                self.rec_thread.join(50)
            except:
                pass
            self.rec_thread = None
        if self.rec_cache:
            return self.rec_cache
        cached = self._cache_get("drama_rec")
        if cached:
            self.rec_cache = cached
            return cached
        if not self.host:
            self._refresh_host()
        return self._load_rec()

    def _load_rec(self):
        text = self._get(self.host + "/api/ex/v3/security/tag/list", self._json_headers())
        try:
            data = json.loads(text).get("data") or ""
        except:
            data = ""
        if not data:
            return self._cache_get("drama_rec", True) or {"list": []}
        if self.decrypt != "0":
            try:
                data = _ecb_decrypt(base64.b64decode(_ecb_decrypt(base64.b64decode(data), self.data_key)), self.data_iv).decode("utf-8", "ignore")
            except:
                return {"list": []}
        try:
            groups = json.loads(data)
        except:
            return {"list": []}
        out = []
        for group in groups if isinstance(groups, list) else []:
            for section in group.get("sections") or []:
                for vod in section.get("vodList") or []:
                    cover = vod.get("coverImage") or {}
                    out.append({
                        "vod_id": str(vod.get("id", "")),
                        "vod_name": vod.get("name", ""),
                        "vod_pic": cover.get("path", "") or cover.get("thumbnailPath", ""),
                        "vod_remarks": vod.get("remark", "")})
        if not out:
            return self._cache_get("drama_rec", True) or {"list": []}
        result = {"list": out}
        if out:
            self.rec_cache = result
            self._cache_set("drama_rec", result, 1800)
        return result

    def categoryContent(self, tid, pg, filter=False, extend={}):
        pg = str(pg or "1")
        ext = extend or {}
        params = {
            "pagesize": str(self.PAGE_SIZE),
            "typeId1": str(tid),
            "page": pg,
            "vodOrderBy": ext.get("extend_sort", "") or "最新",
            "vodArea": ext.get("area", ""),
            "vodLang": ext.get("lang", ""),
            "vodClass": ext.get("class", ""),
            "vodYear": ext.get("year", "")}
        page = self._api("/api/proto/v5/drama/category", params)
        videos = self._vod_list(page)
        total = _pi(page, 16)
        count = (total + self.PAGE_SIZE - 1) // self.PAGE_SIZE if total else (int(pg) + 1 if videos else int(pg))
        return {"list": videos, "page": int(pg), "pagecount": max(count, int(pg)), "limit": self.PAGE_SIZE, "total": total or len(videos)}

    def searchContent(self, key, quick=False, pg="1"):
        if not str(key or "").strip():
            return {"list": [], "page": int(pg or 1)}
        page = self._api("/api/proto/v5/drama/search", {"searchKeys": key, "page": str(pg or "1"), "pagesize": str(self.PAGE_SIZE)})
        return {"list": self._vod_list(page), "page": int(pg or 1)}

    def detailContent(self, ids):
        if not ids:
            return {"list": []}
        item = self._api("/api/proto/v5/drama/getDetail", {"id": str(ids[0])})
        if not item:
            return {"list": []}
        cover = _pm(item, 2)
        groups = {}
        for raw in item.get(29) or []:
            video = _pb_parse(raw)
            name = _ps(video, 10) or self.app_name or "橘汁"
            path = _ps(video, 4)
            if not path:
                continue
            if not self.VIDEO.search(path):
                path = base64.b64encode(json.dumps({"vodPlayFrom": _ps(video, 9), "playUrl": path}, separators=(",", ":")).encode("utf-8")).decode()
            groups.setdefault(name, []).append((_ps(video, 2) or str(_pi(video, 13))) + "$" + path)
        lines = self._sort_play(groups)
        vod = {
            "vod_id": str(_pi(item, 4) or ids[0]),
            "vod_name": _ps(item, 9),
            "vod_pic": _ps(cover, 1) or _ps(cover, 2),
            "type_name": _ps(item, 13),
            "vod_year": str(_pi(item, 18) or ""),
            "vod_area": _ps(item, 1),
            "vod_remarks": _ps(item, 26),
            "vod_actor": _ps(item, 25),
            "vod_director": _ps(item, 12),
            "vod_content": _ps(item, 6) or _ps(item, 7),
            "vod_play_from": "$$$".join(t[0] for t in lines),
            "vod_play_url": "$$$".join("#".join(t[1]) for t in lines)}
        return {"list": [vod]}

    def playerContent(self, flag, id, vipFlags=None):
        if self.VIDEO.search(id or ""):
            return {"parse": 0, "url": id, "header": {"User-Agent": self.UA}}
        try:
            obj = json.loads(base64.b64decode(id + "=" * (-len(id) % 4)).decode("utf-8", "ignore"))
        except:
            return {"parse": 0, "url": id, "header": {"User-Agent": self.UA}}
        msg = self._api("/api/proto/v5/videoUsableUrl", {k: str(v) for k, v in obj.items()})
        header = {}
        for raw in msg.get(6) or []:
            entry = _pb_parse(raw)
            if _ps(entry, 1):
                header[_ps(entry, 1)] = _ps(entry, 2)
        url = _ps(msg, 1)
        return {"parse": 0, "url": url or obj.get("playUrl", ""), "header": header or {"User-Agent": self.UA}}

    def isVideoFormat(self, url):
        return bool(self.VIDEO.search(url or ""))

    def manualVideoCheck(self):
        return False

    def getName(self):
        return self.app_name or "橘汁"

    def localProxy(self, param):
        return [200, "text/plain", ""]

    def destroy(self):
        return ""
