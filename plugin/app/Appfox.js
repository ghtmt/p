//本资源来源于互联网公开渠道，仅可用于个人学习爬虫技术。
//严禁将其用于任何商业用途，下载后请于 24 小时内删除，搜索结果均来自源站，本人不承担任何责任。

let headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Connection': 'Keep-Alive',
    'Accept-Language': 'zh-CN,zh;q=0.8',
    'Cache-Control': 'no-cache'
}, timeout = 5000, ver = 2, custom_first = 0, cateMode = 1, uas = {}, parses = {}, play_config = {}, custom_parses = {}, detail_cache = [], host = '', froms = '', cms = '', app_key = '', app_sign = '';

async function init(cfg) {
    let ext = (cfg.ext || '');
    if (typeof ext == 'string' && ext.startsWith('http')) {
        host = ext;
    } else if (typeof ext == 'object') {
        try {
            host = ext.host;
            app_key = ext.key || '';
            app_sign = ext.sign || '';
            ver = ext.ver || 2;
            cms = (ext.cms || '').replace(/\/$/, '');
            if (/^https?:\/\/.*\/vod/.test(cms)) {
                cms += cms.includes('?') ? '&' : '?';
            }
            froms = ext.from || '';
            custom_parses = ext.parse || {};
            custom_first = ext.custom_first || 0;
            cateMode = ext.category !== undefined ? ext.category : 1;
            let ua = ext.ua;
            if (ua) {
                if (typeof ua === 'string') {
                    headers['User-Agent'] = ua;
                } else if (typeof ua === 'object') {
                    uas = { host: ua.host, config: ua.config, home: ua.home, category: ua.category, search: ua.search, parse: ua.parse, player: ua.player };
                }
            }
            timeout = (ext.timeout || 5) * 1000;
        } catch (e) {}
    }

    if (!/^https?:\/\/[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:\d+)?(\/)?$/.test(host)) {
        let hds = Object.assign({}, headers);
        if (uas.host) hds['User-Agent'] = uas.host;
        let hostRes = await req(host, { headers: hds, timeout: timeout });
        try {
            let hostJson = JSON.parse(hostRes.content);
            if (hostJson.apiDomain) host = hostJson.apiDomain;
        } catch (e) {
            let contentStr = (hostRes.content || '').trim();
            if (contentStr.startsWith('http')) host = contentStr;
        }
    }
    host = host.replace(/\/$/, '');

    let auth_val = (app_key && app_sign);
    if (ver === 3 && !auth_val) {
        let hds2 = getHeaders2();
        if (uas.config) hds2['User-Agent'] = uas.config;
        let configRes = await fetchAPI(`${host}/api.php/Appfox/config`, { headers: hds2, timeout: timeout });
        let config = configRes.data || {};
        if (config.app_key && config.app_sign) {
            app_key = config.app_key;
            app_sign = config.app_sign;
        }
        let player_list = config.playerList || [];
        let jiexi_data_list = config.jiexiDataList || [];
        if (player_list.length > 0) {
            play_config = { playerList: player_list, jiexiDataList: jiexi_data_list };
        }
    } else if (auth_val) {
        ver = 3;
    }
}

async function home(filter) {
    if (!host || cateMode === 0) return JSON.stringify({ class: [] });
    let hds = Object.assign({}, headers);
    if (uas.home) hds['User-Agent'] = uas.home;
    let classes = [];
    let filters = {};
    let data = { class: classes, filters: filters };
    if (cms && cateMode !== 2) {
        let class_url = cms.replace(/&$/, '');
        class_url = class_url.replace(/&ac=videolist/g, '').replace(/ac=videolist&/g, '').replace(/ac=videolist/g, '');
        class_url = class_url.replace('ac=detail', 'ac=list');
        let classRes = await fetchAPI(class_url, { headers: hds, timeout: timeout });
        if (classRes && classRes.class) classes = classRes.class;
        let listRes = await fetchAPI(cms.replace(/&$/, ''), { headers: hds, timeout: timeout });
        data = listRes || {};
        data.class = classes;
        if (cateMode === 2 && data.list) {
            data.list.forEach(i => i.vod_id = `msearch:${i.vod_id}`);
        }
    } else {
        let initRes = await fetchAPI(`${host}/api.php/Appfox/init`, { headers: hds, timeout: timeout });
        if (initRes && initRes.data && initRes.data.type_list) {
            initRes.data.type_list.forEach(i => {
                let tidStr = String(i.type_id);
                classes.push({ type_id: tidStr, type_name: i.type_name });
                if (filter && i.filter_type_list && i.filter_type_list.length > 0) {
                    let typeFilters = [];
                    i.filter_type_list.forEach(f => {
                        let filterName = f.name;
                        switch (f.name) {
                            case 'class': filterName = '类型'; break;
                            case 'area': filterName = '地区'; break;
                            case 'lang': filterName = '语言'; break;
                            case 'year': filterName = '年份'; break;
                            case 'sort': filterName = '排序'; break;
                        }
                        let valueList = [];
                        let initVal = '';
                        f.list.forEach(v => {
                            if (v) { valueList.push({ n: v, v: v }); }
                        });
                        if (valueList.length > 0) {
                            if (f.name === 'sort' && f.list.includes('最新')) {
                                initVal = '最新';
                            } else if (f.list.includes('全部')) {
                                initVal = '全部';
                            } else {
                                initVal = valueList[0].v;
                            }
                            typeFilters.push({ key: f.name, name: filterName, init: initVal, value: valueList });
                        }
                    });
                    if (typeFilters.length > 0) { filters[tidStr] = typeFilters; }
                }
            });
        }
        data.class = classes;
        data.filters = filters;
    }
    return JSON.stringify(data);
}

async function homeVod() {
    if (!host || cateMode === 0) return JSON.stringify({ list: [] });
    if (cms && cateMode !== 2) return JSON.stringify({ list: [] });
    let hds = Object.assign({}, headers);
    if (uas.homeVideo || uas.home) hds['User-Agent'] = uas.homeVideo || uas.home;
    let path = 'index';
    if (ver === 2 || ver === 3) {
        let navRes = await fetchAPI(`${host}/api.php/appfox/nav`, { headers: hds, timeout: timeout });
        let navigationId = '';
        if (navRes && navRes.data) {
            for (let i of navRes.data) {
                if (typeof i === 'object') {
                    navigationId = i.navigationId;
                    break;
                }
            }
        }
        if (!navigationId) return JSON.stringify({ list: [] });
        path = `nav_video?id=${navigationId}`;
    }
    let indexRes = await fetchAPI(`${host}/api.php/Appfox/${path}`, { headers: hds, timeout: timeout });
    let videos = [];
    if (indexRes && indexRes.data) {
        indexRes.data.forEach(i => {
            if (i.banner) videos.push(...i.banner);
            if (i.categories) {
                i.categories.forEach(k => {
                    if (k.videos) videos.push(...k.videos);
                });
            }
        });
    }
    if (videos.length > 0 && cateMode === 2) {
        videos.forEach(i => i.vod_id = `msearch:${i.vod_id}`);
    }
    return JSON.stringify({ list: videos });
}

async function category(tid, pg, filter, extend) {
    if (!host) return JSON.stringify({ list: [] });
    let hds = Object.assign({}, headers);
    if (uas.category) hds['User-Agent'] = uas.category;
    let data = { list: [] };
    if (cms && cateMode !== 2) {
        data = await fetchAPI(`${cms}pg=${pg}&t=${tid}`, { headers: hds, timeout: timeout }) || { list: [] };
    } else {
        let extClass = extend.class || '全部';
        let extArea = extend.area || '全部';
        let extLang = extend.lang || '全部';
        let extYear = extend.year || '全部';
        let extSort = extend.sort || '最新';
        let url = `${host}/api.php/Appfox/vodList?type_id=${tid}&class=${encodeURIComponent(extClass)}&area=${encodeURIComponent(extArea)}&lang=${encodeURIComponent(extLang)}&year=${encodeURIComponent(extYear)}&sort=${encodeURIComponent(extSort)}&page=${pg}`;
        let res = await fetchAPI(url, { headers: hds, timeout: timeout });
        if (res && res.data && res.data.recommend_list) {
            data.list = res.data.recommend_list;
        }
    }
    if (cateMode === 2 && data.list) {
        data.list.forEach(i => i.vod_id = `msearch:${i.vod_id}`);
    }
    return JSON.stringify({...data, page: parseInt(pg)});
}

async function search(wd, quick, pg = 1) {
    if (!host) return JSON.stringify({ list: [] });
    let hds = Object.assign({}, headers);
    if (uas.search) hds['User-Agent'] = uas.search;
    let response = { list: [] };
    if (cms) {
        let _cms = cms.includes('?') ? cms.split('?')[0] + '?' : cms;
        response = await fetchAPI(`${_cms}ac=detail&wd=${encodeURIComponent(wd)}`, { headers: hds, timeout: timeout }) || { list: [] };
        detail_cache = response.list || [];
    } else {
        if (ver === 3) {
            let body = { ac: 'detail', wd: wd, pg: String(pg) };
            let hds2 = getHeaders2(JSON.stringify(body));
            if (uas.search) hds2['User-Agent'] = uas.search;
            let res = await req(`${host}/api.php/appfoxs/vod`, { method: 'post', data: body, headers: hds2, postType: '', timeout: timeout });
            response = parseContent(res.content);
        } else {
            let path = `${host}/api.php/Appfox/vod?ac=detail&wd=${encodeURIComponent(wd)}`;
            if (froms) path += `&from=${froms}`;
            response = await fetchAPI(path, { headers: hds, timeout: timeout }) || { list: [] };
        }
        detail_cache = response.list || [];
    }
    return JSON.stringify(response);
}

async function detail(id) {
    let hds = Object.assign({}, headers);
    let detail_ua = uas.detail || uas.search;
    if (detail_ua) hds['User-Agent'] = detail_ua;
    let video = detail_cache.find(i => String(i.vod_id) === String(id));
    if (!video) {
        if (cms) {
            let _cms = cms.includes('?') ? cms.split('?')[0] + '?' : cms;
            let response = await fetchAPI(`${_cms}ac=detail&ids=${id}`, { headers: hds, timeout: timeout });
            if (response && response.list && response.list.length > 0) video = response.list[0];
        } else {
            if (ver === 3) {
                let body = { ac: 'detail', ids: String(id) };
                let hds2 = getHeaders2(JSON.stringify(body));
                if (detail_ua) hds2['User-Agent'] = detail_ua;
                let res = await req(`${host}/api.php/appfoxs/vod`, { method: 'post', data: body, headers: hds2, postType: '', timeout: timeout });
                let detail_response = parseContent(res.content);
                if (detail_response && detail_response.list) video = detail_response.list[0];
            } else {
                let detail_response = await fetchAPI(`${host}/api.php/Appfox/vod?ac=detail&ids=${id}`, { headers: hds, timeout: timeout });
                if (detail_response && detail_response.list) video = detail_response.list[0];
            }
        }
    }
    if (!video) return JSON.stringify({ list: [] });
    let play_from = (video.vod_play_from || '').split('$$$');
    let play_urls = (video.vod_play_url || '').split('$$$');
    try {
        let config_hds = ver === 3 ? getHeaders2() : Object.assign({}, headers);
        if (uas.config) config_hds['User-Agent'] = uas.config;
        if (!play_config || !play_config.playerList) {
            if (ver === 3) {
                let res = await req(`${host}/api.php/appfoxs/config`, { headers: config_hds, timeout: timeout });
                let config_response = parseContent(res.content);
                play_config = { playerList: config_response?.data?.playerList || [], jiexiDataList: config_response?.data?.jiexiDataList || [] };
            } else {
                let config_response = await fetchAPI(`${host}/api.php/Appfox/config`, { headers: config_hds, timeout: timeout });
                play_config = { playerList: config_response?.data?.playerList || [], jiexiDataList: config_response?.data?.jiexiDataList || [] };
            }
        }
        let player_list = play_config.playerList || [];
        let jiexi_data_list = play_config.jiexiDataList || [];
        let player_map = {};
        player_list.forEach(p => player_map[p.playerCode] = p);
        let processed_play_urls = [];
        for (let idx = 0; idx < play_from.length; idx++) {
            let play_code = play_from[idx];
            if (player_map[play_code]) {
                let player_info = player_map[play_code];
                if (player_info.playerCode !== player_info.playerName) {
                    play_from[idx] = `${player_info.playerName}\u2005(${play_code})`;
                }
            }
            if (idx < play_urls.length) {
                let urls = play_urls[idx].split('#');
                let processed_urls = [];
                for (let url of urls) {
                    let parts = url.split('$');
                    if (parts.length >= 2) {
                        processed_urls.push(parts[0] + '$' + play_code + '@' + parts[1]);
                    } else {
                        processed_urls.push(url);
                    }
                }
                processed_play_urls.push(processed_urls.join('#'));
            }
        }
        video.vod_play_from = play_from.join('$$$');
        video.vod_play_url = processed_play_urls.join('$$$');
        parses = {};
        jiexi_data_list.forEach(p => {
            if ((p.url || '').startsWith('http')) {
                parses[p.playerCode] = p.url;
            }
        });

    } catch (e) {}
    return JSON.stringify({ list: [video] });
}

async function play(flag, id, flags) {
    let split_idx = id.indexOf('@');
    let play_from = split_idx > -1 ? id.substring(0, split_idx) : '';
    let raw_url = split_idx > -1 ? id.substring(split_idx + 1) : id;
    let jx = 0, parse = 0, parsed = 0;
    let hds = { ...headers };
    if (uas.parse) hds['User-Agent'] = uas.parse;
    let player_ua = uas.player || 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1';
    let url = raw_url;
    let parses_main = custom_first === 1 ? [custom_parses, parses] : [parses, custom_parses];
    for (let parses2 of parses_main) {
        if (!parsed && !/^https?:\/\/.*\.(m3u8|mp4|flv|mkv)/.test(url)) {
            for (let key in parses2) {
                if (!key.includes(play_from)) continue;
                let parsers = parses2[key];
                if (Array.isArray(parsers)) {
                    for (let parser of parsers) {
                        if (parser.startsWith('parse:')) {
                            url = parser.split('parse:')[1] + raw_url;
                            jx = 0; parse = 1; parsed = 1;
                            break;
                        }
                        try {
                            let res = await fetchAPI(`${parser}${raw_url}`, { headers: hds, timeout: timeout });
                            if (res && res.url && res.url.startsWith('http')) {
                                url = res.url; parsed = 1;
                                break;
                            }
                        } catch(e) {}
                    }
                } else if (typeof parsers === 'string') {
                    if (parsers.startsWith('parse:')) {
                        url = parsers.split('parse:')[1] + raw_url;
                        jx = 0; parse = 1; parsed = 1;
                        break;
                    }
                    try {
                        let res = await fetchAPI(`${parsers}${raw_url}`, { headers: hds, timeout: timeout });
                        if (res && res.url && res.url.startsWith('http')) {
                            url = res.url; parsed = 1;
                            break;
                        }
                    } catch(e) {}
                }
                if (parsed || parse) break;
            }
        }
        if (parsed || parse) break;
    }
    if (!/^https?:\/\/.*\.(m3u8|mp4|flv|mkv)/.test(url) && parsed !== 1) { jx = 1; }
    return JSON.stringify({ jx: jx, parse: parse, url: url, header: { 'User-Agent': player_ua } });
}

function decryptData(data) {
    try {
        let k = md5X(app_key).substring(0, 16);
        let iv = k.split('').reverse().join('');
        return aesX('AES/CBC/PKCS7', false, data, true, k, iv, false);
    } catch (e) {
        return data;
    }
}

function parseContent(content) {
    if (!content) return {};
    try {
        return JSON.parse(content);
    } catch (e) {
        try {
            return JSON.parse(decryptData(content));
        } catch (e2) {
            return content;
        }
    }
}

async function fetchAPI(url, options = {}) {
    try {
        let res = await req(url, options);
        return parseContent(res.content);
    } catch (e) {
        return {};
    }
}

function getHeaders2(body = '') {
    let timestamp = new Date().getTime();
    let nonce = Math.floor(Math.random() * 900000) + 100000;
    let sign = md5X(`${app_sign}${app_key}${timestamp}${nonce}${body}`);
    return {
        'User-Agent': headers['User-Agent'],
        'x-security-auth': `${timestamp}|${nonce}|${sign}`,
        'content-type': 'application/json; charset=utf-8'
    };
}

export function __jsEvalReturn() {
    return {
        init: init,
        home: home,
        homeVod: homeVod,
        category: category,
        search: search,
        detail: detail,
        play: play
    };
}
