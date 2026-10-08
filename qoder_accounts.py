"""qoder_accounts.py —— Qoder 双区域账号池、OAuth 设备授权与凭证生命周期

覆盖与 WorkBuddy 网关同等完整的账号能力：

  - 双区域常量表 REALM_CONFIGS（国内 qoder.com.cn / 国际 qoder.com）
  - OAuth 设备授权（PKCE S256，浏览器授权 + /deviceToken/poll 轮询，
    dt- 30 天 / drt- 1 年）——免桌面客户端一键登录
  - PAT 导入（pt- 长期令牌 -> jobToken 交换 jt-/jrt-）
  - 按 token 前缀路由的刷新（drt- -> deviceToken/refresh；
    jrt- -> jobToken/refresh，失败回落 PAT 重新交换）
  - 每日签到 / 额度（quota）/ 套餐（plan）查询
  - 会话亲和（同一对话固定落到同一账号）与轮询负载
  - 账号导入导出（Dry-Run 预检）与 JSON 持久化（原子写）
"""
import base64
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import uuid

from qoder_fingerprint import derive_id, generate_request_id


# ---------------------------------------------------------------------------
# 出口（egress）：显式控制代理，杜绝进程级 *_PROXY 劫持
# ---------------------------------------------------------------------------
# 教训（经验④）：urllib 默认 opener 隐式读取进程级 HTTP_PROXY/HTTPS_PROXY/
# ALL_PROXY。网关进程一旦继承用户级代理变量，连 CN 域（qoder.com.cn）都会被
# 迫走代理，把两个本来独立的故障域耦合在一起——代理一抖全线瘫痪。出口身份
# 也是账号身份的一部分（共用出口 = 账号被关联）。
#
# 因此这里不再依赖默认 opener：默认**直连**（忽略环境变量），只有显式配置了
# 出口时才使用代理。全局出口用环境变量 QD_HTTPS_PROXY / QD_HTTP_PROXY 显式
# 指定（注意与用户级 HTTP_PROXY 区分），账号级出口走 Account.egress。
_EGRESS_HTTP_PROXY = os.environ.get("QD_HTTP_PROXY") or ""
_EGRESS_HTTPS_PROXY = os.environ.get("QD_HTTPS_PROXY") or ""

# 强制直连白名单：仅本机 + 国内版上游。
#   - localhost/127.0.0.1/::1：本地服务（如 /health 探测），走代理无意义
#   - qoder.com.cn：**国内版始终直连**。这是来自真实事故的结论——多账号共用
#     境外机房 IP 时 WAF 高频拦截，切回大陆家宽直连后 WAF 归零且快 4.6 倍；
#     若继承用户级代理变量，CN 域会被拖进代理故障域（代理一抖全线瘫痪）。
#   **不含** qoder.sh（国际版）：国际版可能确需代理出口（见 README），
#   故允许其走显式配置的 QD_* / 账号级 egress。默认无显式配置时同样是直连。
_EGRESS_NO_PROXY = ("localhost", "127.0.0.1", "::1",
                    "*.qoder.com.cn", "qoder.com.cn")


def _egress_bypass_host(host):
    """True 表示该 host 应绕过代理直连（CN/intl 上游 + 本机）。

    注意：**不能**依赖 ProxyHandler 的 "no" 键——CPython 的 proxy_open 调的是
    全局 proxy_bypass()（查注册表/环境变量），从不读 proxies dict 里的 "no"。
    所以在 open_url 里自行判定，命中则改用直连 opener。
    """
    h = str(host or "").strip().strip("[]").lower()
    if not h:
        return False
    for pat in _EGRESS_NO_PROXY:
        if pat.startswith("*."):
            if h == pat[2:] or h.endswith("." + pat[2:]):
                return True
        elif h == pat:
            return True
    return False


def validate_egress_proxy(proxy):
    """校验出口代理地址（SSRF 面收敛）。

    代理地址来自账号 JSON / 环境变量。它会把**该账号的全部出站**（含携带
    Bearer token 与对话内容的 600s SSE）导向该地址，因此是凭据级信任边界：
    配错或被人写入就等于把流量交给攻击者（MITM）。

    注意：代理本身**允许**指向本机/内网（Clash 等常见于 127.0.0.1:7890），
    所以不能像 validate_public_http_url 那样禁私网。这里只做两件事：
      1. 强制 http/https scheme，拒绝 file:// 等可被滥用为本地读取的 scheme；
      2. 拒绝空串/无 host 的畸形值。
    返回规范化后的地址；不合法则 raise ValueError。
    """
    raw = str(proxy or "").strip()
    if not raw:
        raise ValueError("empty proxy address")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("proxy must be http/https, got %r" % parsed.scheme)
    if not (parsed.hostname or "").strip():
        raise ValueError("proxy host is required")
    return raw


def _validated_proxy_or_none(proxy):
    """校验失败时返回 None（宁可直连也不把流量交给非法代理）。"""
    if not proxy:
        return None
    try:
        return validate_egress_proxy(proxy)
    except ValueError:
        return None


class _ExplicitProxyHandler(urllib.request.ProxyHandler):
    """显式配置的代理**必须生效**，不被进程级 no_proxy 静默绕过。

    CPython 的 ProxyHandler.proxy_open 里有：
        if req.host and proxy_bypass(req.host): return None
    proxy_bypass 只看 getproxies_environment()/注册表，**从不读 handler 的
    no 键**。后果有两个方向，都必须消除：
      (a) 反向（更危险）：机器上若恰好有 no_proxy 含 qoder.com.cn，账号**显式
          指定**的出口会被静默绕过成直连 → 出口 IP 泄露，账号身份暴露。
      (b) 正向：我们无法用 handler 的 no 键实现"CN 域不走代理"的白名单。
    这里只对**显式配置**的代理覆写 proxy_open，跳过 proxy_bypass；未显式配置
    时仍用基类（空 ProxyHandler({}) 强制直连）。
    """

    def proxy_open(self, req, proxy, type):
        orig_type = req.type
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if proxy_type is None:
            proxy_type = orig_type
        # 刻意不做 proxy_bypass 检查：显式配置优先于环境变量。
        if user and password:
            user_pass = "%s:%s" % (urllib.parse.unquote(user),
                                   urllib.parse.unquote(password))
            creds = base64.b64encode(user_pass.encode()).decode("ascii")
            req.add_header("Proxy-authorization", "Basic " + creds)
        hostport = urllib.parse.unquote(hostport)
        req.set_proxy(hostport, proxy_type)
        if orig_type == proxy_type or orig_type == "https":
            return None
        return self.parent.open(req, timeout=req.timeout)


def egress_opener(http_proxy=None, https_proxy=None):
    """返回一个**显式**的 urllib opener。

    默认（无代理参数）返回一个只含 HTTPSHandler/HTTPHandler 的 opener，
    **不读任何环境变量**——即强制直连，避免进程级代理把 CN 域也拖下水。
    显式给了代理才挂 ProxyHandler（且不被 no_proxy 绕过）。
    """
    handlers = []
    proxy_map = {}
    hp = _validated_proxy_or_none(
        https_proxy if https_proxy is not None else _EGRESS_HTTPS_PROXY)
    pp = _validated_proxy_or_none(
        http_proxy if http_proxy is not None else _EGRESS_HTTP_PROXY)
    if hp:
        proxy_map["https"] = hp
    if pp:
        proxy_map["http"] = pp
    if proxy_map:
        handlers.append(_ExplicitProxyHandler(proxy_map))
    else:
        # 空 ProxyHandler({}) 显式禁用代理，压过环境变量。
        handlers.append(urllib.request.ProxyHandler({}))
    handlers.append(urllib.request.HTTPSHandler(context=_egress_ssl_context()))
    handlers.append(urllib.request.HTTPHandler())
    return urllib.request.build_opener(*handlers)


_EGRESS_SSL_CTX = None


def _egress_ssl_context():
    global _EGRESS_SSL_CTX
    if _EGRESS_SSL_CTX is None:
        _EGRESS_SSL_CTX = ssl.create_default_context()
    return _EGRESS_SSL_CTX


_EGRESS_OPENER_CACHE = {}
_EGRESS_OPENER_LOCK = threading.Lock()


def get_egress_opener(https_proxy=None, http_proxy=None):
    """带缓存的 opener 获取（按代理串缓存，避免每次请求重建）。

    这是全局唯一的传输缝（transport seam）：所有出站请求都经由它，测试与
    调用方只需替换本函数即可注入传输层，无需关心代理细节。
    """
    # 缓存键必须区分 None（"未指定 -> 取全局默认"）与 ""（"强制直连"）：
    # 用 `or ""` 会把两者折叠成同一个键，导致先请求者建好的 opener 被另一种
    # 语义复用（代理/直连互相串用）。故用 repr 保留哨兵区别。
    key = (repr(https_proxy), repr(http_proxy))
    with _EGRESS_OPENER_LOCK:
        op = _EGRESS_OPENER_CACHE.get(key)
        if op is None:
            op = egress_opener(http_proxy=http_proxy, https_proxy=https_proxy)
            _EGRESS_OPENER_CACHE[key] = op
        return op


# ---------------------------------------------------------------------------
# TLS 指纹伪装（可选）：用 curl_cffi 模仿真实客户端握手
# ---------------------------------------------------------------------------
# 背景：Python stdlib 的 TLS ClientHello 是 OpenSSL 出厂形态——无 GREASE、
# 无 ALPN、11 个扩展，JA3 固定为 93c7d42c0df602fb91589311534831f5。这个指纹
# 全世界所有 Python 脚本共用，任何 HTTP 头（UA/cosy-*）都改不掉它，因为它
# 在握手层、HTTP 之下。上游若用 Cloudflare 之类做 JA3/JA4 评分，这一层是
# 唯一无法用改头解决的面。
#
# 处置：**默认关闭，保持零依赖**。显式设置 QD_TLS_IMPERSONATE（如 chrome）
# 且已安装 curl_cffi 时才启用；未安装则告警并回落 stdlib，不影响可用性。
# 启用后 curl_cffi 同时解决 JA3 + ALPN + HTTP/2 + 头顺序。
_TLS_IMPERSONATE = (os.environ.get("QD_TLS_IMPERSONATE") or "").strip()
_TLS_WARNED = False

# 「强制直连」哨兵：与 None（"未指定，用全局默认"）严格区分。
# 必须是**独立对象**而非空串：用 `is` 判身份才可靠（空串会因字符串驻留
# 与其他 "" 混淆，且 `or` 短路会让一侧的强制直连误伤另一侧）。
class _Direct(object):
    __slots__ = ()

    def __repr__(self):
        return "DIRECT"


_DIRECT = _Direct()


def _curl_cffi_module():
    """返回 curl_cffi.requests 模块；不可用时返回 None（并只告警一次）。"""
    global _TLS_WARNED
    try:
        from curl_cffi import requests as _cr
        return _cr
    except Exception as exc:
        if not _TLS_WARNED:
            _TLS_WARNED = True
            import sys as _sys
            print("[qd-proxy] WARN: QD_TLS_IMPERSONATE=%r 但 curl_cffi 不可用"
                  " (%s)；回落 stdlib 传输（TLS 指纹仍为 OpenSSL）"
                  % (_TLS_IMPERSONATE, exc), file=_sys.stderr)
        return None


def tls_impersonate_active():
    """当前是否真的能用 curl_cffi 伪装（供 /health 展示）。"""
    if not _TLS_IMPERSONATE:
        return False
    if _curl_cffi_module() is None:
        return False
    # 目标名必须被 curl_cffi 认得，否则每个请求都会在握手前抛错——
    # 若只看"变量已设 + 模块可导入"，/health 会谎报 impersonate(chromex)
    # 而实际全链路失败（正是"以为开了其实没生效"的反向误判）。
    return _impersonate_target_valid()


def _impersonate_target_valid():
    global _TLS_TARGET_OK
    if _TLS_TARGET_OK is None:
        try:
            from curl_cffi.requests.impersonate import BrowserTypeLiteral  # noqa
            ok = _TLS_IMPERSONATE in _known_impersonate_targets()
        except Exception:
            # 拿不到清单时不做断言（宁可不拦，也不要误判为无效）
            ok = True
        _TLS_TARGET_OK = bool(ok)
    return _TLS_TARGET_OK


_TLS_TARGET_OK = None


def _known_impersonate_targets():
    """curl_cffi 支持的 impersonate 目标名集合（不同版本不同，故动态取）。

    直接从库里取权威清单（含 `chrome`/`edge` 这类别名），而不是自己扫模块
    属性——后者会漏掉别名，把合法的 `chrome` 误判为无效目标。
    """
    try:
        from curl_cffi.requests import impersonate as _imp
        # BrowserTypeLiteral 是 typing.Literal[...]（不是字符串元组），
        # 目标名在 __args__ 里。
        _lit = getattr(_imp, "BrowserTypeLiteral", None)
        names = set(getattr(_lit, "__args__", None) or ())
        if not names:
            # 退路：扫模块里的字符串常量 + 别名表
            for attr in dir(_imp):
                v = getattr(_imp, attr, None)
                if isinstance(v, str) and v and not attr.startswith("_"):
                    names.add(v)
            names |= set((getattr(_imp, "REAL_TARGET_MAP", None) or {}).keys())
        return {n for n in names if isinstance(n, str)}
    except Exception:
        return set()


def tls_summary():
    if not _TLS_IMPERSONATE:
        return "stdlib-openssl"
    if _curl_cffi_module() is None:
        return "stdlib-openssl(curl_cffi missing)"
    if not tls_impersonate_active():
        return "stdlib-openssl(bad target %r)" % _TLS_IMPERSONATE
    return "impersonate(%s)" % _TLS_IMPERSONATE


class _CurlCffiResponse(object):
    """把 curl_cffi 响应适配成 stdlib 的响应契约。

    现有消费代码依赖两点：
      1. `for raw in resp:` 逐行产出 **bytes**（SSE 行）
      2. `resp.close()` / `with resp:` 释放连接
    curl_cffi 的 Response 不可迭代，这里用 iter_content 逐块产出，并在
    **字节层面**切行（不能按文本切：多字节字符可能跨块，按 bytes 切安全）。
    """

    __slots__ = ("_r", "_buf", "_done", "_body", "status", "headers",
                 "reason", "url")

    def __init__(self, r):
        self._r = r
        self._buf = b""
        self._done = False
        self._body = None       # read() 的缓存（惰性消费 iter_content）
        self.status = r.status_code
        self.headers = r.headers
        self.reason = getattr(r, "reason", "")
        self.url = getattr(r, "url", "")

    def __iter__(self):
        if self._done:
            # 已被 read() 消费过：不再二次请求，直接产出已缓存的整包。
            if self._body:
                for line in self._body.split(b"\n"):
                    yield line
            return
        for chunk in self._r.iter_content(chunk_size=8192):
            if not chunk:
                continue
            self._buf += chunk
            while b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                yield line
        if self._buf:
            tail, self._buf = self._buf, b""
            yield tail
        # 迭代完成即标记：curl_cffi 对已耗尽的响应二次 iter_content 会**永久
        # 阻塞且不响应 timeout**（实测），必须避免再次调用。
        self._done = True

    def read(self, *a):
        """返回完整 body（仅支持整读，忽略 n——调用方均为无参整读）。

        **不能**直接返回 `self._r.content`：请求用的是 stream=True，此时
        curl_cffi 的 content 恒为 b""（body 走迭代器），会让 http_json 拿到
        空串、json.loads 抛错，进而打断所有非 SSE 链路（token 刷新 / quota /
        签到 / 模型列表）。

        语义对齐 stdlib：若 body 已被迭代消费完，返回 b""（而不是再发一次
        iter_content——那会永久挂死）。
        """
        if self._body is None:
            if self._done:
                self._body = b""      # 已被 __iter__ 消费，与 stdlib 一致
            else:
                chunks = []
                try:
                    for chunk in self._r.iter_content(chunk_size=65536):
                        if chunk:
                            chunks.append(chunk)
                except Exception:
                    pass
                self._body = b"".join(chunks)
                self._done = True
        return self._body

    def close(self):
        try:
            self._r.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False

    def __getattr__(self, name):
        return getattr(self._r, name)


def _curl_cffi_error(url, r):
    """把 curl_cffi 的非 2xx 响应转成 urllib.error.HTTPError。

    现有全部错误分类（429/401/403/418/5xx 与 qoder_detail 透传）都建立在
    HTTPError 异常上；curl_cffi 默认不抛，必须在这里补上，否则错误分支全部失效。

    注意：请求用了 stream=True，此时 `r.content` **是空的**——必须显式读
    迭代器拿 body，否则 detail 为空，会让 _is_transient_upstream() 与
    session_dead() 全部失判（实测踩过）。
    """
    body = b""
    try:
        body = r.content
    except Exception:
        body = b""
    if not body:
        try:
            body = b"".join(r.iter_content(chunk_size=65536))
        except Exception:
            body = b""
    hdrs = r.headers
    exc = urllib.error.HTTPError(url, r.status_code,
                                 getattr(r, "reason", "") or "", hdrs,
                                 io.BytesIO(body))
    try:
        r.close()
    except Exception:
        pass
    return exc


def _resolve_proxy(value, global_default):
    """把「显式值 / _DIRECT / None」解析成 libcurl 的代理串。

    - _DIRECT -> ""（显式禁用该 scheme 的代理）
    - None    -> 用全局默认（QD_*）；全局也没有 -> ""
    - 其他    -> 校验后使用；非法则 ""（宁可直连也不交给非法代理）
    """
    if value is _DIRECT:
        return ""
    if value is None:
        return _validated_proxy_or_none(global_default) or ""
    return _validated_proxy_or_none(value) or ""


def _neutralise_libcurl_no_proxy():
    """摘除进程级 no_proxy/NO_PROXY，避免 libcurl 绕过显式代理。

    libcurl 在**请求时**读进程级 no_proxy/NO_PROXY，会把我们显式配置的代理
    静默绕过成直连（实测：设 no_proxy=域名 后显式代理失效、直接解析域名）。
    这正是 stdlib 路径用 _ExplicitProxyHandler 堵掉的同一个洞。

    curl_cffi 不暴露 CURLOPT_NOPROXY，只能摘环境变量。采用**每次调用前幂等
    清除**而非"临时摘除再恢复"：
      - 只 pop 不恢复，故多线程并发无竞态窗口（后者会出现 A 摘、B 恢复的
        交错，导致 A 的请求仍被绕过）；
      - 每次调用都执行，可覆盖"清除之后又被注入"的情况。
    本网关的出口策略由 QD_* 与账号级 egress 显式控制，进程级 no_proxy 对本
    进程无正当用途。
    """
    for _k in ("no_proxy", "NO_PROXY"):
        if _k in os.environ:
            os.environ.pop(_k, None)


# 必须在**模块导入时**清一次：libcurl 在进程内首次请求时读取并缓存 no_proxy，
# 之后再清只对后续请求生效（实测：首次请求仍按缓存值绕过显式代理）。
# 本模块在网关启动早期即被导入，早于任何出站请求，因此这里能覆盖首次请求；
# 每次调用前的再次清除（见 _open_url_curl_cffi）用于兜底"之后又被注入"的情况。
#
# 仅在启用 TLS 伪装时才执行：默认关闭时 import 不得产生任何环境副作用
# （"默认关闭 = 零影响"）。libcurl 只在 curl_cffi 路径下才会被用到。
if _TLS_IMPERSONATE:
    _neutralise_libcurl_no_proxy()


def _normalise_curl_error(exc):
    """把 curl_cffi 异常归一成 urllib 风格，**保留瞬时/非瞬时的分类语义**。

    不能简单 `URLError(str(exc))`：那会丢掉类型信息，而调用方的
    `_is_transient_transport` 依赖类型（或 reason 的类型）判定是否可重试。
    实测差异（curl 错误码）：
      - 28 "Operation too slow"（读超时）→ 字符串里没有 "timed out"，
        stdlib 同类是 TimeoutError(瞬时) -> 必须映射成 TimeoutError
      - 6  "Could not resolve host"（DNS）→ stdlib 同类是 gaierror(OSError, 瞬时)
      - 7  "Failed to connect"、35 SSL、52 空响应 → 连接类，瞬时
    映射后两条传输路径的重试分类保持一致。
    """
    msg = str(exc)
    low = msg.lower()
    code = getattr(exc, "code", None)
    try:
        code = int(code) if code is not None else None
    except (TypeError, ValueError):
        code = None
    # 连接被拒/无法连接/DNS 失败：stdlib 侧分别对应 ConnectionRefusedError /
    # OSError(gaierror)，均被 _is_transient_transport 判为瞬时。
    if code in (6, 7, 28, 35, 52, 55, 56) or any(
            k in low for k in ("timed out", "timeout", "too slow",
                               "could not resolve", "connection refused",
                               "failed to connect", "ssl", "eof", "reset")):
        if code == 28 or "too slow" in low or "timed out" in low:
            return urllib.error.URLError(TimeoutError(msg))
        return urllib.error.URLError(ConnectionError(msg))
    return urllib.error.URLError(msg)


def _open_url_curl_cffi(url, data, headers, method, timeout,
                        https_proxy, http_proxy):
    cr = _curl_cffi_module()
    # 代理解析必须与 stdlib 路径语义一致，且**不能让 libcurl 读环境变量**：
    # 实测 curl_cffi 下 proxies=None 与 proxies={} 都会回退读 HTTP_PROXY/
    # HTTPS_PROXY/ALL_PROXY（正是本模块要消除的劫持），只有空串 "" 才真正
    # 禁用代理。故两个 scheme 都必须显式给值（哪怕是 ""）。
    proxies = {"http": _resolve_proxy(http_proxy, _EGRESS_HTTP_PROXY),
               "https": _resolve_proxy(https_proxy, _EGRESS_HTTPS_PROXY)}
    _neutralise_libcurl_no_proxy()
    try:
        r = cr.request(method, url, data=data, headers=headers,
                       timeout=timeout, proxies=proxies,
                       impersonate=_TLS_IMPERSONATE, stream=True,
                       allow_redirects=True,
                       # 必须关掉浏览器默认头注入：实测默认会加上
                       # Sec-Ch-Ua: "Google Chrome";v="150"、Sec-Fetch-*、
                       # Upgrade-Insecure-Requests、Accept-Language 等，而这些会
                       # 挂在账号自身的 User-Agent / cosy-* 上，形成现实中不存在
                       # 的组合（浏览器 client hints + Go CLI UA），**比不伪装更
                       # 易被识别**。关掉后自定义头（含 cosy-*）完整保留。
                       default_headers=False)
    except Exception as exc:
        # 归一成 urllib 风格并保留分类语义（见 _normalise_curl_error）。
        raise _normalise_curl_error(exc)
    if r.status_code >= 400:
        raise _curl_cffi_error(url, r)
    return _CurlCffiResponse(r)


def open_url(req_or_url, timeout=30, https_proxy=None, http_proxy=None):
    """统一出站入口：经显式 opener 打开 URL。

    默认直连（忽略进程级 *_PROXY）；显式给代理才走代理。所有模块的 HTTP
    调用都应走这里，保证"出口"只有一个开关。

    CN/intl 上游域名与 localhost 始终直连（见 _egress_bypass_host）：避免
    代理抖动把两个独立的故障域耦合在一起。

    若启用 QD_TLS_IMPERSONATE 且装了 curl_cffi，则改走 curl_cffi 传输
    （真实客户端 TLS 指纹 + HTTP/2）；否则用 stdlib，行为与从前一致。
    """
    host = ""
    try:
        if isinstance(req_or_url, str):
            host = urllib.parse.urlsplit(req_or_url).hostname or ""
        else:
            host = getattr(req_or_url, "host", "") or ""
            if ":" in host:          # req.host 形如 "host:port"
                host = host.rsplit(":", 1)[0]
    except Exception:
        host = ""
    if _egress_bypass_host(host):
        # 强制直连：用 _DIRECT 哨兵而非 None——None 表示"未指定，用全局默认"，
        # 用它会把"强制直连"反转成"走全局代理"（CN 域被拖进代理故障域）。
        https_proxy = http_proxy = _DIRECT
    # 门控必须与 /health 的 tls_summary 用**同一个**判定：若只看"变量已设 +
    # 模块可导入"，拼错目标名时会走进 curl_cffi 且每个请求抛 ImpersonateError
    # -> /health 说"已回落 stdlib"而实际全链路失败（反向误判）。
    if tls_impersonate_active():
        if isinstance(req_or_url, str):
            url = req_or_url
            data, headers = None, {}
            method = "GET"
        else:
            url = req_or_url.full_url
            data = req_or_url.data
            headers = dict(req_or_url.headers or {})
            method = req_or_url.get_method()
        return _open_url_curl_cffi(url, data, headers, method, timeout,
                                   https_proxy, http_proxy)
    # stdlib 路径：_DIRECT 必须解析成**空串**（不是 None！）。
    # egress_opener 里 None 的语义是"未指定 -> 取全局默认"，把 _DIRECT 转成
    # None 会把"强制直连"反转成"走全局代理"——CN/intl 上游会被拖进代理故障域，
    # 正是本模块要消除的。空串经 _validated_proxy_or_none("") -> None，
    # 最终落到空 ProxyHandler({})，真正直连。
    if https_proxy is _DIRECT:
        https_proxy = ""
    if http_proxy is _DIRECT:
        http_proxy = ""
    return get_egress_opener(https_proxy=https_proxy,
                             http_proxy=http_proxy).open(req_or_url,
                                                         timeout=timeout)


def egress_summary():
    """给看板/日志用：当前全局出口是直连还是代理（不回显凭据）。"""
    if _EGRESS_HTTPS_PROXY or _EGRESS_HTTP_PROXY:
        return "proxy(configured)"
    return "direct"


# ---------------------------------------------------------------------------
# 区域常量（逆向自官方桌面/CLI 客户端）
# ---------------------------------------------------------------------------
REALM_CONFIGS = {
    "cn": {
        "name": "国内版 (China)",
        "openapi": "https://openapi.qoder.com.cn",
        "gateway": "https://gateway.qoder.com.cn",
        "website": "https://qoder.com.cn",
        "client_id": "1c5e33e1-364d-4ce6-b02c-acaa81274a5c",
        "redirect_uri": "qoder-work-cn://",
        "domain": "qoder.com.cn",
        "ua": "QoderWork/1.1.34",
        "has_checkin": True,       # 官方：仅国内版有每日签到 (sash daily-check-in)
        "send_client_id": True,    # CN 设备授权 URL: client_id + machine_id + redirect_uri
        "send_redirect_uri": True,
        "nonce_dashed": True,      # CN nonce 使用带横线 uuid
        "home_dir": ".qoder-cn",   # 官方客户端本地目录（凭证 / 模型目录缓存）
        "app_dir": "com.qodercn.app.stable",   # 桌面 App Roaming 数据目录
    },
    "intl": {
        "name": "国际版 (Global)",
        "openapi": "https://openapi.qoder.sh",
        "gateway": "https://api3.qoder.sh",
        "website": "https://qoder.com",
        "client_id": "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb",
        "redirect_uri": "qoder://aicoding.aicoding-agent/login-success",
        "domain": "qoder.com",
        "ua": "Qoder/1.1.34",
        "has_checkin": False,      # 官方：国际版无签到接口 (见 cpa docs/PROTOCOL.md)
        "send_client_id": True,    # Intl 设备授权 URL: client_id + machine_id (无 redirect_uri)
        "send_redirect_uri": False,
        "nonce_dashed": False,     # intl nonce 为 32-hex uuid-simple
        "home_dir": ".qoder",
        "app_dir": "com.qoder.app.stable",
    },
}

CLIENT_UA = "Go-http-client/2.0"
LOGIN_TTL_SECONDS = 600
DEFAULT_USER_TYPE = "personal_professional_trial"

# 不可逆处置的证据门槛：session-dead 连续命中 N 次才禁用（经验⑤）。
SESSION_DEAD_THRESHOLD = 3


def _env_int(name, default):
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


# 单号负载上限：把负载从头部账号匀开，避免"谁被用得多谁先死"（经验③）。
#   MAX_CONCURRENT_PER_ACCOUNT：同时在途请求上限（摊开瞬时并发）
#   MAX_DAILY_PER_ACCOUNT     ：单号日请求总量上限（摊开**顺序型**长会话——
#       滑动 TTL 亲和会把一个长会话整天钉在同一号上，只有日总量能兜住。
#       事故数据：被封的号 2600~3600 次/日，幸存 847~1563，即此上限的由来）
# 两者均可用环境变量覆盖；日总量设 0 表示不限制。
MAX_CONCURRENT_PER_ACCOUNT = max(1, _env_int("QD_MAX_CONCURRENT_PER_ACCOUNT", 2))
MAX_DAILY_PER_ACCOUNT = max(0, _env_int("QD_MAX_DAILY_PER_ACCOUNT", 1200))

# 低余额保护：内存估算扣减 + 选号硬过滤 + 加速探测。
#   LOW_BALANCE_FLOOR        ：选号过滤下限（与 近期单次最大观测成本×3 取大）
#   LOW_BALANCE_ACCEL        ：加速线——跌破它把探测间隔缩到 LOW_S，
#                              扣减时跨过它会安排一次 ~15s 后的事件探测
#   CREDIT_DEDUCT_PER_KTOK   ：估算扣减系数（积分/1k tokens）。
#       实测口径（usage.jsonl vs credits.jsonl 快照差值）约 0.039，
#       默认取 0.1（~2.5x 保守高估，宁可多扣也不少扣）。
LOW_BALANCE_FLOOR = max(0, _env_int("QD_LOW_BALANCE_FLOOR", 100))
LOW_BALANCE_ACCEL = max(0, _env_int("QD_LOW_BALANCE_ACCEL", 300))
CREDIT_PROBE_NORMAL_S = max(15, _env_int("QD_CREDIT_PROBE_NORMAL_S", 600))
CREDIT_PROBE_LOW_S = max(15, _env_int("QD_CREDIT_PROBE_LOW_S", 45))
LOW_BALANCE_PROBE_DELAY_S = max(1, _env_int("QD_LOW_BALANCE_PROBE_DELAY_S", 15))
CREDIT_DEDUCT_PER_KTOK = max(0.0, _env_float("QD_CREDIT_DEDUCT_PER_KTOK", 0.1))
# 扣减落盘节流：每账号至多 60s 写一次盘（探测路径随 fetch_credits 写）。
CREDIT_SAVE_GAP_S = 60

# 业务端点（全部挂 openapi 基址，纯 Bearer，无 COSY 签名）
PATH_DEVICE_POLL = "/api/v1/deviceToken/poll"
PATH_DEVICE_REFRESH = "/api/v1/deviceToken/refresh"
PATH_JOB_EXCHANGE = "/api/v1/jobToken/exchange"
PATH_JOB_REFRESH = "/api/v1/jobToken/refresh"
PATH_USERINFO = "/api/v1/userinfo"
PATH_QUOTA = "/api/v2/quota/usage"
PATH_PLAN = "/api/v2/user/plan"
PATH_CHECKIN_STATUS = "/sash/api/v1/me/daily-check-in/status"
PATH_CHECKIN_CLAIM = "/sash/api/v1/me/daily-check-in/claim"
PATH_PRO_ELIGIBILITY = "/sash/api/v1/me/pro-upgrade/eligibility"
PATH_PRO_CLAIM = "/sash/api/v1/me/pro-upgrade/claim"

# 会话死亡标记：上游主动吊销离线会话，刷新已无意义，需要重新登录。
SESSION_DEAD_MARKERS = ("TOKEN_EXPIRE", "12153", "Offline user session not found")


def session_dead(msg):
    s = str(msg or "")
    return any(m in s for m in SESSION_DEAD_MARKERS)


def get_realm_config(realm):
    return REALM_CONFIGS.get(realm) or REALM_CONFIGS["cn"]


def detect_realm_from_domain(domain):
    d = str(domain or "").lower()
    if "qoder.sh" in d or (d.endswith("qoder.com") and "qoder.com.cn" not in d) \
            or "qoder.com/" in d:
        return "intl"
    return "cn"


def normalize_epoch(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number > 1e11:      # 毫秒
        number /= 1000.0
    return int(number)


# ---------------------------------------------------------------------------
# 带重试的 HTTP JSON 工具
# ---------------------------------------------------------------------------
# 198.18.0.0/15 (RFC 2544 benchmarking) 与 fdfe:dcba:9876::/48 被 Clash/mihomo
# 等本地代理用作 fake-IP DNS 段：开启透明代理的机器上所有公网域名都会解析到
# 这些网段。命中它说明 DNS 已被本机代理接管、真实 IP 不可见，此时跳过解析级
# 校验（名称级校验已完成）。
_FAKEIP_NETS = [
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("2001:2::/48"),
    ipaddress.ip_network("fdfe:dcba:9876::/48"),
]


def _host_boundary_violation(ip, allow_local):
    """True when the resolved/IP address must be refused."""
    if ip.is_loopback:
        return not allow_local
    if (ip.is_private or ip.is_reserved or ip.is_link_local
            or ip.is_multicast or ip.is_unspecified):
        return True
    return False


def validate_public_http_url(url, allow_local=False):
    """SSRF 防护：仅允许 http/https，且 host 不得指向本机/私有/保留网段。

    上游网关与 openapi 域名均为公网地址；任何指向 localhost、回环、内网或
    保留地址的 URL 一律拒绝，防止上游配置或导入数据把请求引向内网。
    allow_local 仅供显式面向本机网关的开发/验证脚本开启（如 _verify_models.py），
    服务端请求路径一律使用默认 False。
    """
    parsed = urllib.parse.urlsplit(str(url or ""))
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs are allowed")
    host = (parsed.hostname or "").strip().strip("[]").lower()
    if not host:
        raise ValueError("URL host is required")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        if not allow_local:
            raise ValueError("requests to localhost are not allowed")
        return url
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _host_boundary_violation(literal, allow_local):
            raise ValueError(
                "requests to private/reserved address %s are not allowed" % literal)
        return url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("cannot resolve URL host %r: %s" % (host, exc))
    addrs = []
    for info in infos:
        addr = str(info[4][0]).strip("[]")
        try:
            addrs.append(ipaddress.ip_address(addr))
        except ValueError:
            raise ValueError("URL host resolved to a non-IP address: %r" % addr)
    if addrs and all(any(ip in net for net in _FAKEIP_NETS) for ip in addrs):
        return url  # fake-IP DNS：真实 IP 不可见，名称级校验已通过
    for ip in addrs:
        if _host_boundary_violation(ip, allow_local):
            raise ValueError(
                "requests to private/reserved address %s are not allowed" % ip)
    return url


def _retryable(exc):
    """Transient network faults worth another attempt (TLS resets, timeouts, 5xx)."""
    if isinstance(exc, ssl.SSLError):
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    if isinstance(exc, urllib.error.URLError):
        return True
    if isinstance(exc, (TimeoutError, ConnectionResetError, ConnectionAbortedError, OSError)):
        return True
    return False


def http_json(url, data=None, method=None, headers=None, timeout=30,
              retries=3, backoff=1.0, log=None, https_proxy=None,
              http_proxy=None):
    """urlopen + json decode with retries. 所有 openapi 调用统一走这里。

    走**显式** opener（见 get_egress_opener）：默认直连、忽略进程级 *_PROXY，
    只有显式配置出口时才走代理。
    """
    validate_public_http_url(url)
    attempts = max(1, int(retries or 1))
    last = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers=headers or {},
        )
        try:
            with open_url(req, timeout=timeout,
                          https_proxy=https_proxy,
                          http_proxy=http_proxy) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            last = exc
            if attempt >= attempts or not _retryable(exc):
                break
            if log:
                log("network retry %d/%d after %s" % (attempt, attempts, exc))
            time.sleep(backoff * attempt)
    raise last


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
# 账号级「额度耗尽」标记（与排队 10605 严格区分）：
#   110 = Billing daily count exceeded（当日计费额度用尽）
#   112 = 需订阅 / 额度不足（上游附定价页 URL）
# 两者都是**账号级、非请求级**问题：换号即可继续，且该账号应跨日排除。
# 曾因把它们当普通 403 早退，导致池中还有 7 个健康号却让整个请求失败。
QUOTA_EXHAUSTED_MARKERS = (
    "billing daily count exceeded",
    '"code":"110"', '"code": "110"',
    '"code":"112"', '"code": "112"',
    "pricingurl",
)


def quota_exhausted(msg):
    """上游错误是否表示「本账号额度已耗尽」（换号可解，需长冷却）。"""
    s_ = str(msg or "").lower()
    return any(m in s_ for m in QUOTA_EXHAUSTED_MARKERS)


# 额度耗尽后的默认冷却：额度按自然日重置，故跨到次日；兜底 6 小时。
# 可用 QD_QUOTA_COOLDOWN_S 覆盖（例如套餐按小时恢复时调小）。
try:
    QUOTA_COOLDOWN_S = max(60, int(os.environ.get("QD_QUOTA_COOLDOWN_S") or 21600))
except ValueError:
    QUOTA_COOLDOWN_S = 21600


def _next_local_midnight(now=None):
    """下一个本地 00:00 的时间戳（额度按自然日重置）。"""
    now = time.time() if now is None else now
    lt = time.localtime(now)
    nxt = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + 1,
                       0, 0, 0, 0, 0, -1))
    return nxt


class Account(object):
    def __init__(self, data, path=None):
        data = data or {}
        self.path = path
        self.uid = str(data.get("uid") or "")
        self.nickname = str(data.get("nickname") or "")
        self.domain = str(data.get("domain") or "")
        self.realm = str(data.get("realm") or detect_realm_from_domain(self.domain))
        if self.realm not in REALM_CONFIGS:
            self.realm = "cn"
        if not self.domain:
            self.domain = get_realm_config(self.realm)["domain"]
        self.platform = str(data.get("platform") or "CLI")
        self.access_token = str(data.get("accessToken") or "")
        self.refresh_token = str(data.get("refreshToken") or "")
        self.personal_token = str(data.get("personalToken") or "")
        self.expires_at = normalize_epoch(data.get("expiresAt"))
        self.added_at = data.get("addedAt") or time.time()
        self.source = str(data.get("source") or "oauth")
        self.enabled = data.get("enabled", True)
        self.last_error = str(data.get("lastError") or "")
        self.cooldown_until = float(data.get("cooldownUntil") or 0)
        # 按模型粒度的限流冷却：上游频控只针对单模型，不能拖垮整个账号。
        self.model_cooldowns = {}
        self.credits = data.get("credits") or None
        self.plan = str(data.get("plan") or "")
        self.last_checkin = data.get("lastCheckin") or None
        self.user_type = str(data.get("userType") or "") or DEFAULT_USER_TYPE
        self.organization_id = str(data.get("organizationId") or "")
        self.organization_name = str(data.get("organizationName") or "")
        # 账号级出口（可选）：{"https_proxy": "...", "http_proxy": "..."}
        # 原则：一个账号长期一个出口；不配置则跟随全局直连。
        egress = data.get("egress")
        self.egress = egress if isinstance(egress, dict) else {}
        # 连续 session-dead 证据计数（不可逆禁用需多次证据，见 note_session_dead）
        self.session_dead_streak = int(data.get("sessionDeadStreak") or 0)
        # 额度耗尽（110/112）跨日排除：与错误冷却分开存储，便于看板区分
        # 「被限流」与「没额度」——两者运维处置完全不同。
        self.quota_until = float(data.get("quotaUntil") or 0)
        # 单号在途并发 / 日总量（内存态，不持久化）
        self._inflight = {}          # token -> 占用时间
        self._daily_count = 0
        self._daily_day = time.strftime("%Y-%m-%d")
        self._load_lock = threading.Lock()
        # 低余额保护（内存态，不持久化）
        self._credits_lock = threading.Lock()
        self.last_used_at = 0.0        # 最近一次请求占用时间（活跃判定）
        self.probe_due_at = 0.0        # 事件触发的探测时间（跨过加速线时安排）
        self.max_observed_cost = 0     # 近期单次最大估算成本（动态 floor）
        self._credits_saved_at = 0.0   # 上次额度落盘时间（节流）

    # -- 持久化 ------------------------------------------------------------
    def to_dict(self):
        return {
            "uid": self.uid,
            "nickname": self.nickname,
            "domain": self.domain,
            "realm": self.realm,
            "platform": self.platform,
            "accessToken": self.access_token,
            "refreshToken": self.refresh_token,
            "personalToken": self.personal_token,
            "expiresAt": self.expires_at,
            "addedAt": self.added_at,
            "source": self.source,
            "enabled": self.enabled,
            "lastError": self.last_error,
            "cooldownUntil": self.cooldown_until,
            "credits": self.credits,
            "plan": self.plan,
            "lastCheckin": self.last_checkin,
            "userType": self.user_type,
            "organizationId": self.organization_id,
            "organizationName": self.organization_name,
            "egress": self.egress,
            "sessionDeadStreak": self.session_dead_streak,
            "quotaUntil": self.quota_until,
        }

    def public(self):
        exp = self.expires_at
        return {
            "uid": self.uid,
            "nickname": self.nickname or (self.uid[:8] if self.uid else "?"),
            "domain": self.domain,
            "realm": self.realm,
            "platform": self.platform,
            "enabled": bool(self.enabled),
            "source": self.source,
            "tokenFamily": token_family(self),
            "expiresAt": exp,
            "expiresIn": _human_delta(exp - time.time()) if exp else None,
            "hasRefreshToken": bool(self.refresh_token),
            "hasPAT": bool(self.personal_token),
            "lastError": self.last_error,
            "inCooldown": self.cooldown_until > time.time(),
            "cooldownFor": round(max(0.0, self.cooldown_until - time.time())) or None,
            "quotaExhausted": self.quota_until > time.time(),
            "quotaFor": round(max(0.0, self.quota_until - time.time())) or None,
            "lowBalance": self.low_balance(),
            "addedAt": self.added_at,
            "file": os.path.basename(self.path) if self.path else None,
            "credits": self.credits,
            "plan": self.plan,
            "lastCheckin": self.last_checkin,
            "canCheckin": bool(get_realm_config(self.realm)["has_checkin"]),
            "userType": self.user_type,
            "machineId": derive_id(self.uid, "machine"),
            "sessionId": derive_id(self.uid, "session"),
        }

    def save(self, directory):
        base = Path(directory).resolve()
        base.mkdir(parents=True, exist_ok=True)
        safe_uid = re.sub(r"[^A-Za-z0-9_-]", "_", str(self.uid or "")).strip("_ ")
        name = (safe_uid or uuid.uuid4().hex) + ".json"
        path = base / name
        tmp = base / (name + ".tmp")
        if not (path.is_relative_to(base) and tmp.is_relative_to(base)):
            raise ValueError("invalid path for account save")
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, path)
        self.path = str(path)
        return self.path

    def delete(self):
        if self.path and os.path.exists(self.path):
            os.remove(self.path)

    # -- 健康与冷却 --------------------------------------------------------
    def ready(self, model=None):
        if not self.enabled or not self.access_token:
            return False
        if self.cooldown_until > time.time():
            return False
        if self.quota_until > time.time():
            return False
        if model and self.model_cooldowns.get(model, 0.0) > time.time():
            return False
        exp = self.expires_at
        if not exp:
            return True
        remaining = exp - time.time()
        if remaining > 240:          # 剩余 >4 分钟直接用（jt- 24h / dt- 30d）
            return True
        if remaining > 0:
            self.refresh()
            return True
        return self.refresh()

    def note_error(self, message, cooldown=60, single_account=False, model=None, until=None):
        self.last_error = str(message)[:200]
        if model:
            wait = max(1.0, float(until) - time.time()) if until else (
                3.0 if single_account else float(cooldown))
            self.model_cooldowns[model] = time.time() + wait
            return
        actual_cooldown = 3 if single_account else cooldown
        self.cooldown_until = time.time() + actual_cooldown

    def throttle_wait(self, model=None):
        """Seconds until this account can serve `model` again (0 = right now)."""
        if not self.enabled or not self.access_token:
            return 0.0
        now = time.time()
        wait = max(0.0, self.cooldown_until - now)
        if model:
            wait = max(wait, max(0.0, self.model_cooldowns.get(model, 0.0) - now))
        return wait

    def clear_error(self, model=None):
        if model:
            self.model_cooldowns.pop(model, None)
        else:
            self.model_cooldowns.clear()
        if self.last_error or self.cooldown_until:
            self.last_error = ""
            self.cooldown_until = 0

    # -- 不可逆处置的证据门槛 ----------------------------------------------
    def note_quota_exhausted(self, message="", cooldown=None):
        """记一次额度耗尽（上游 110/112）：跨日排除本账号。

        与 note_error 的区别：这是**确定性的账号状态**（额度不会在 60s 后
        恢复），必须长时间排除，否则每个请求都会再撞一次 110/112，既浪费
        一次上游往返，又让客户端看到一次无谓的失败。
        取「下一个本地 00:00」与固定兜底中的**较晚者**，避免月初/时区边界
        上过早恢复；上限 QUOTA_COOLDOWN_S 防止时钟异常导致永久排除。
        """
        self.last_error = str(message)[:200] or "quota exhausted (110/112)"
        now = time.time()
        base = float(cooldown) if cooldown else float(QUOTA_COOLDOWN_S)
        self.quota_until = max(self.quota_until,
                               min(now + base, _next_local_midnight(now) + 60))
        # 持久化：额度排除是**跨小时**的状态，只放内存会在重启后丢失，
        # 于是下一个请求又撞上同一个已耗尽的账号（正是本次要消除的浪费）。
        if self.path:
            try:
                self.save(os.path.dirname(self.path))
            except Exception:
                pass

    def clear_quota(self):
        self.quota_until = 0.0

    def note_session_dead(self):
        """记一次 session-dead 证据；达到阈值才返回 True（可禁用）。

        教训（经验⑤）：12153 语义不透明，一次命中就永久 enabled=False 会
        错杀好号。禁用是不可逆动作，证据门槛必须显著高于冷却。故先冷却、
        累计连续 N 次（期间任何一次成功即清零）才升级为禁用。
        """
        self.session_dead_streak += 1
        return self.session_dead_streak >= SESSION_DEAD_THRESHOLD

    def clear_session_dead(self):
        if self.session_dead_streak:
            self.session_dead_streak = 0

    # -- 单号并发与日总量（负载均衡 = 安全，见经验③） ----------------------
    def try_acquire(self, max_concurrent=None, daily_cap=None):
        """尝试占用一个在途名额；超并发/超日总量则返回 False（转投他号）。

        "谁被用得多谁先死"——上限的作用是把负载从头部账号匀开，而不是
        让头部账号先撞风控。超限时 pick 会跳过本账号选下一个。
        返回 token（供 release 用）；失败返回 None。
        """
        if max_concurrent is None:
            max_concurrent = MAX_CONCURRENT_PER_ACCOUNT
        if daily_cap is None:
            daily_cap = MAX_DAILY_PER_ACCOUNT
        with self._load_lock:
            self._prune_inflight()
            self._rollover_daily()
            if max_concurrent and len(self._inflight) >= max_concurrent:
                return None
            if daily_cap and self._daily_count >= daily_cap:
                return None
            token = uuid.uuid4().hex
            self._inflight[token] = time.time()
            self._daily_count += 1
            self.last_used_at = time.time()
            return token

    def release(self, token):
        """归还 try_acquire 返回的 token。必须传 token——无参"弹最老"会静默
        挤掉别的在途请求的名额。"""
        if not token:
            return
        with self._load_lock:
            self._inflight.pop(token, None)

    def _prune_inflight(self):
        """自愈：清掉超时的在途记录。

        请求超时上限 600s（+60s 余量）。即使某条路径漏了 release，也不会
        永久占住名额把账号饿死。
        """
        cutoff = time.time() - 660
        for tok in [t for t, ts in self._inflight.items() if ts < cutoff]:
            self._inflight.pop(tok, None)

    def _rollover_daily(self):
        today = time.strftime("%Y-%m-%d")
        if self._daily_day != today:
            self._daily_day = today
            self._daily_count = 0

    def load_stats(self):
        with self._load_lock:
            self._prune_inflight()
            self._rollover_daily()
            return {"inflight": len(self._inflight), "daily": self._daily_count,
                    "daily_cap": MAX_DAILY_PER_ACCOUNT,
                    "max_concurrent": MAX_CONCURRENT_PER_ACCOUNT}

    def has_capacity(self, max_concurrent=None, daily_cap=None):
        """非侵入式容量检查（供选号过滤用，不占用名额）。"""
        if max_concurrent is None:
            max_concurrent = MAX_CONCURRENT_PER_ACCOUNT
        if daily_cap is None:
            daily_cap = MAX_DAILY_PER_ACCOUNT
        with self._load_lock:
            self._prune_inflight()
            self._rollover_daily()
            if max_concurrent and len(self._inflight) >= max_concurrent:
                return False
            if daily_cap and self._daily_count >= daily_cap:
                return False
            return True

    # -- 低余额保护 ---------------------------------------------------------
    def credit_remain(self):
        """内存中的余额（从未探测过返回 None，不参与过滤）。"""
        c = self.credits
        if not isinstance(c, dict):
            return None
        try:
            return int(c.get("remain"))
        except (TypeError, ValueError):
            return None

    def low_balance_floor(self):
        """过滤阈值 = max(配置下限, 近期单次最大观测成本 × 3)。"""
        return max(LOW_BALANCE_FLOOR, int(self.max_observed_cost) * 3)

    def low_balance(self):
        r = self.credit_remain()
        return r is not None and r < self.low_balance_floor()

    def deduct_credits(self, total_tokens, now=None):
        """请求成功后按估算成本扣减内存余额；落盘节流（CREDIT_SAVE_GAP_S）。

        返回 (cost, crossed)：crossed=True 表示本次扣减让余额从
        >= LOW_BALANCE_ACCEL 跌破加速线，已安排 probe_due_at 事件探测。
        探测到余额回升后无需"复活"——pick 的过滤是无状态现算。
        """
        now = time.time() if now is None else now
        cost = max(1, int(round(float(total_tokens or 0)
                                * CREDIT_DEDUCT_PER_KTOK / 1000.0)))
        crossed = False
        with self._credits_lock:
            self.last_used_at = now
            if cost > self.max_observed_cost:
                self.max_observed_cost = cost
            c = self.credits
            if isinstance(c, dict):
                before = self.credit_remain()
                if before is not None:
                    c["remain"] = before - cost
                    c["updated_at"] = now
                    c["updated_iso"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    if before >= LOW_BALANCE_ACCEL > before - cost:
                        crossed = True
                        self.probe_due_at = now + LOW_BALANCE_PROBE_DELAY_S
                    if self.path \
                            and now - self._credits_saved_at >= CREDIT_SAVE_GAP_S:
                        self._credits_saved_at = now
                        try:
                            self.save(os.path.dirname(self.path))
                        except Exception:
                            pass
        return cost, crossed

    # -- 出站头 ------------------------------------------------------------
    def egress_kwargs(self):
        """账号级出口（经验④：一个账号长期一个出口，不随请求轮换）。

        未配置则返回空 dict，走全局出口（默认直连）。
        """
        if not self.egress:
            return {}
        return {"https_proxy": self.egress.get("https_proxy") or None,
                "http_proxy": self.egress.get("http_proxy") or None}

    def headers(self, purpose="openapi"):
        cfg = get_realm_config(self.realm)
        return {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": CLIENT_UA,
            "Authorization": "Bearer " + self.access_token,
            "X-Request-ID": generate_request_id(self.uid),
            "X-Machine-ID": derive_id(self.uid, "machine"),
            "X-Session-ID": derive_id(self.uid, "session"),
            "Origin": cfg["website"],
            "Referer": cfg["website"] + "/",
        }

    # -- 刷新（按 token 前缀路由） ----------------------------------------
    def refresh(self):
        """刷新 access token。drt- 走 deviceToken，jrt-/PAT 走 jobToken。

        PAT 永不覆盖活跃的 OAuth 会话，只做 jrt- 过期后的最终兜底。
        """
        cfg = get_realm_config(self.realm)
        base = cfg["openapi"]
        # 1) OAuth 设备族
        if self.refresh_token.startswith("drt-"):
            return self._post_token(base + PATH_DEVICE_REFRESH,
                                    {"refresh_token": self.refresh_token}, kind="device")
        # 2) jobToken 族：jrt- 优先，失败回落 PAT 重新交换
        if self.refresh_token:
            if self._post_token(base + PATH_JOB_REFRESH,
                                {"refresh_token": self.refresh_token}, kind="job"):
                return True
        if self.personal_token:
            if self._post_token(base + PATH_JOB_EXCHANGE,
                                {"personal_token": self.personal_token}, kind="job"):
                return True
        if not self.refresh_token and not self.personal_token:
            self.last_error = "no refresh token; sign in again"
        return False

    def _post_token(self, url, payload, kind):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": CLIENT_UA,
        }
        try:
            data = http_json(url, data=json.dumps(payload).encode(), method="POST",
                             headers=headers, timeout=30, **self.egress_kwargs())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            self.last_error = "refresh failed: HTTP %d %s" % (exc.code, body[:160])
            if exc.code in (401, 403) and session_dead(body):
                # 不可逆处置需多次证据（经验⑤）：本路径可被 ready()->refresh()
                # 与 22:00 全量保活批量触发，一击禁用会在一轮巡检内误杀全池。
                # 与 chat 路径共用同一门槛；刷新成功（见下方）即视为存活证据清零。
                if self.note_session_dead():
                    self.enabled = False
                    self.last_error = ("session dead (TOKEN_EXPIRE) x%d: "
                                       "re-login required"
                                       % self.session_dead_streak)
            return False
        except Exception as exc:
            self.last_error = "refresh failed: %s" % exc
            return False

        if kind == "device":
            token = data.get("token") or data.get("device_token") or ""
            refresh = data.get("refresh_token") or self.refresh_token
            exp = _device_expiry(data)
        else:
            token = data.get("token") or ""
            refresh = data.get("refresh_token") or self.refresh_token
            if data.get("expires_in"):
                exp = int(time.time() + int(data["expires_in"]) / 1000)
            else:
                exp = self.expires_at
        if not token:
            self.last_error = "refresh returned no token"
            return False
        self.access_token = token
        self.refresh_token = refresh
        self.expires_at = exp or self.expires_at
        self.last_error = ""
        self.cooldown_until = 0
        # 刷新成功 = 会话仍然存活，是明确的恢复证据：清掉 session-dead 计数。
        # 否则残留的 streak 会让下一次单次命中即触发禁用，架空"连续 N 次"。
        self.clear_session_dead()
        if self.path and os.path.exists(os.path.dirname(self.path)):
            self.save(os.path.dirname(self.path))
        try:
            from qoder_sign import SESSIONS
            SESSIONS.invalidate(self.uid)   # 旧 COSY 会话携带旧 token，必须重建
        except Exception:
            pass
        return True

    # -- 签到 / 额度 / 套餐 ------------------------------------------------
    def can_checkin(self):
        if not get_realm_config(self.realm)["has_checkin"]:
            return False
        if not self.last_checkin:
            return True
        today_str = time.strftime("%Y-%m-%d")
        return not str(self.last_checkin).startswith(today_str)

    def checkin_status(self):
        """GET daily-check-in/status -> (ok, summary|error)。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_CHECKIN_STATUS
        try:
            q = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=2, **self.egress_kwargs())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return False, "HTTP %d %s" % (exc.code, body[:160])
        except Exception as exc:
            return False, str(exc)
        last = ""
        if q.get("lastClaimedAt"):
            try:
                last = time.strftime("%Y-%m-%d",
                                     time.localtime(int(q["lastClaimedAt"])))
            except Exception:
                last = ""
        today = time.strftime("%Y-%m-%d")
        status = str(q.get("status") or "")
        return True, {
            "status": status,
            "active": status in ("CLAIMABLE", "CLAIMED"),
            "today_checked_in": status == "CLAIMED" and last == today,
            "streak_days": int(q.get("currentStreakDays") or 0),
            "total_claim_days": int(q.get("totalClaimDays") or 0),
            "reward_credits": int(q.get("rewardCredits") or 0),
            "total_reward_credits": int(q.get("totalRewardCredits") or 0),
            "next_claim_at": int(q.get("nextClaimAt") or 0),
            "last_claimed_at": int(q.get("lastClaimedAt") or 0),
            "reward_expires_at": int(q.get("rewardExpiresAt") or 0),
        }

    def checkin(self):
        """每日签到：先查状态，未签则领取。返回 {ok, msg, ...}。"""
        if not get_realm_config(self.realm)["has_checkin"]:
            return {"ok": False, "error": "checkin is not available for this realm"}
        ok, st = self.checkin_status()
        if not ok:
            return {"ok": False, "error": st}
        if st["today_checked_in"]:
            return {"ok": True, "already": True, "msg": "今日已签到",
                    "streak_days": st["streak_days"], "reward_credits": st["reward_credits"]}
        if not st["active"]:
            # CLAIMABLE / CLAIMED 之外的状态（如 DISABLED：活动批次下线），
            # 不发起无意义的 claim，按"活动未开放"成功跳过。
            return {"ok": True, "disabled": True, "status": st.get("status"),
                    "msg": "官方签到活动未开放 (status=%s)" % (st.get("status") or "?")}
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_CHECKIN_CLAIM
        try:
            res = http_json(url, data=b"{}", method="POST",
                            headers=self.headers(), timeout=15, retries=1,
                            **self.egress_kwargs())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            # 上游并发/重复领取返回 409 ALREADY_CLAIMED —— 归一化为“已签”
            if "ALREADY_CLAIMED" in body:
                self._stamp_checkin()
                return {"ok": True, "already": True, "msg": "今日已签到"}
            return {"ok": False, "error": "HTTP %d %s" % (exc.code, body[:160])}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        if str(res.get("result") or "") == "ALREADY_CLAIMED" or res.get("success") is False and "ALREADY" in str(res.get("error") or ""):
            self._stamp_checkin()
            return {"ok": True, "already": True, "msg": "今日已签到"}
        if res.get("success") is False:
            # 复查一次：上游可能已记账
            ok2, st2 = self.checkin_status()
            if ok2 and st2["today_checked_in"]:
                self._stamp_checkin()
                return {"ok": True, "already": True, "msg": "今日已签到（复查确认）"}
            return {"ok": False, "error": str(res.get("error") or res)[:160]}
        reward = int(res.get("rewardCredits") or 0)
        self._stamp_checkin()
        return {"ok": True, "msg": "签到成功 +%d 积分" % reward,
                "reward_credits": reward}

    def _stamp_checkin(self):
        self.last_checkin = time.strftime("%Y-%m-%d %H:%M:%S")
        if self.path and os.path.exists(os.path.dirname(self.path)):
            self.save(os.path.dirname(self.path))

    def fetch_credits(self):
        """GET /api/v2/quota/usage -> 聚合基础额度 + 赠送/签到额度。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_QUOTA
        try:
            q = http_json(url, method="GET", headers=self.headers(), timeout=30,
                          **self.egress_kwargs())
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        uq = q.get("userQuota") or {}
        aq = q.get("addOnQuota") or {}

        def _num(d, k):
            try:
                return float(d.get(k) or 0)
            except Exception:
                return 0.0

        remain = int(_num(uq, "remaining") + _num(aq, "remaining"))
        used = int(_num(uq, "used") + _num(aq, "used"))
        size = int(_num(uq, "total") + _num(aq, "total"))
        self.credits = {
            "remain": remain,
            "used": used,
            "size": size,
            "exceeded": bool(q.get("isQuotaExceeded")),
            "usage_pct": q.get("totalUsagePercentage"),
            "expires_at": normalize_epoch(q.get("expiresAt")),
            "packages": [
                {"name": "基础额度", "remain": int(_num(uq, "remaining")),
                 "used": int(_num(uq, "used")), "size": int(_num(uq, "total"))},
                {"name": "赠送/签到额度", "remain": int(_num(aq, "remaining")),
                 "used": int(_num(aq, "used")), "size": int(_num(aq, "total"))},
            ],
            "updated_at": time.time(),
            "updated_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if self.path and os.path.exists(os.path.dirname(self.path)):
            self.save(os.path.dirname(self.path))
            self._credits_saved_at = time.time()
        return {"ok": True, "credits": self.credits}

    def fetch_plan(self):
        """GET /api/v2/user/plan -> 套餐名（Pro Trial 等）。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PLAN
        try:
            p = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=1, **self.egress_kwargs())
        except Exception:
            return self.plan
        name = str(p.get("plan_tier_name") or p.get("user_type") or "")
        if name and name != self.plan:
            self.plan = name
            if self.path and os.path.exists(os.path.dirname(self.path)):
                self.save(os.path.dirname(self.path))
        return name

    # -- Pro 升级包（一次性 +1800） ---------------------------------------
    def pro_eligibility(self):
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PRO_ELIGIBILITY
        try:
            m = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=1, **self.egress_kwargs())
            return True, bool(m.get("eligible"))
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 403, 410):
                # 端点不存在 / 活动已下线：查询成功，只是不可领取
                return True, False
            return False, "HTTP %d" % exc.code
        except Exception as exc:
            return False, str(exc)

    def pro_claim(self):
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PRO_CLAIM
        try:
            m = http_json(url, data=b"{}", method="POST", headers=self.headers(),
                          timeout=15, retries=1, **self.egress_kwargs())
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            if exc.code == 409 or "ALREADY" in body:
                return {"ok": True, "already": True, "msg": "Pro 升级包已领取过"}
            return {"ok": False, "error": "HTTP %d %s" % (exc.code, body[:160])}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        if m.get("success") is False:
            return {"ok": False, "error": str(m.get("message") or m)[:160]}
        return {"ok": True, "msg": "Pro 升级包领取成功", "data": m}


def token_family(acc):
    """返回账号当前的凭证族：device(OAuth) / job(PAT交换) / pat。"""
    rt = acc.refresh_token or ""
    if rt.startswith("drt-"):
        return "device"
    if rt.startswith("jrt-"):
        return "job"
    if (acc.access_token or "").startswith("pt-"):
        return "pat"
    return "unknown"


def _device_expiry(data):
    """deviceToken 响应的过期时间：expires_in(ms) / expires_at(RFC3339)，默认 30 天。"""
    if data.get("expires_in"):
        return int(time.time() + int(data["expires_in"]) / 1000)
    if data.get("expires_at"):
        try:
            import datetime
            dt = datetime.datetime.strptime(str(data["expires_at"])[:19],
                                             "%Y-%m-%dT%H:%M:%S")
            return int(dt.timestamp())
        except Exception:
            pass
    return int(time.time()) + 30 * 86400


def _human_delta(seconds):
    if seconds is None:
        return None
    if seconds <= 0:
        return "expired"
    days = seconds / 86400.0
    if days >= 1:
        return "%.0f days" % days
    hours = seconds / 3600.0
    if hours >= 1:
        return "%.1f hours" % hours
    return "%d min" % int(seconds / 60)


# ---------------------------------------------------------------------------
# 会话亲和（同一对话固定同一账号，上游按账号缓存 prompt prefix）
# ---------------------------------------------------------------------------
class SessionAffinity(object):
    def __init__(self, ttl=7200, max_entries=5000):
        self.ttl = ttl
        self.max_entries = max_entries
        self.bindings = {}
        self._lock = threading.Lock()

    def get(self, key):
        if not key:
            return None
        with self._lock:
            entry = self.bindings.get(key)
            if not entry:
                return None
            uid, exp = entry
            if time.time() > exp:
                self.bindings.pop(key, None)
                return None
            self.bindings[key] = (uid, time.time() + self.ttl)
            return uid

    def bind(self, key, uid):
        if not key or not uid:
            return
        with self._lock:
            if len(self.bindings) >= self.max_entries:
                now = time.time()
                self.bindings = {k: v for k, v in self.bindings.items() if v[1] > now}
            self.bindings[key] = (uid, time.time() + self.ttl)

    def unbind(self, key):
        if not key:
            return
        with self._lock:
            self.bindings.pop(key, None)

    def has_uid(self, uid):
        """该账号是否持有至少一条未过期绑定（守护线程活跃判定用）。"""
        if not uid:
            return False
        now = time.time()
        with self._lock:
            for bound_uid, exp in self.bindings.values():
                if bound_uid == uid and exp > now:
                    return True
            return False


# ---------------------------------------------------------------------------
# AccountPool
# ---------------------------------------------------------------------------
_ACTIVE_POOL = None


def add_to_pool(account):
    """把导入的账号写入活动账号池（AccountPool 构造时自注册）。"""
    if _ACTIVE_POOL is None:
        raise RuntimeError("account pool not initialised")
    return _ACTIVE_POOL.add(account)


class AccountPool(object):
    def __init__(self, directory, log=None):
        global _ACTIVE_POOL
        self.dir = directory
        self.log = log or (lambda msg: None)
        self.accounts = []
        self.logins = {}
        self._lock = threading.RLock()
        self._cursor = 0
        self.affinity = SessionAffinity()
        _ACTIVE_POOL = self

    def load(self):
        with self._lock:
            self.accounts = []
            if not os.path.isdir(self.dir):
                return self.accounts
            for name in sorted(os.listdir(self.dir)):
                if not name.endswith(".json"):
                    continue
                if name in ("settings.json", "active_realm.json"):
                    continue
                path = os.path.join(self.dir, name)
                try:
                    with open(path, encoding="utf-8") as fh:
                        account = Account(json.load(fh), path)
                except Exception as exc:
                    self.log("account %s unreadable: %s" % (name, exc))
                    continue
                if account.uid:
                    self.accounts.append(account)
            return self.accounts

    def list_public(self, realm=None):
        with self._lock:
            accs = self.accounts if (not realm or realm == "all") else \
                [a for a in self.accounts if a.realm == realm]
            return [a.public() for a in accs]

    def get(self, uid):
        with self._lock:
            for account in self.accounts:
                if account.uid == uid:
                    return account
        return None

    def add(self, account):
        with self._lock:
            existing = self.get(account.uid)
            if existing is not None:
                account.added_at = existing.added_at
                account.path = existing.path
                if not account.credits and existing.credits:
                    account.credits = existing.credits
                if not account.plan and existing.plan:
                    account.plan = existing.plan
                if not account.last_checkin and existing.last_checkin:
                    account.last_checkin = existing.last_checkin
                if not account.personal_token and existing.personal_token:
                    account.personal_token = existing.personal_token
                self.accounts[self.accounts.index(existing)] = account
            else:
                self.accounts.append(account)
            account.save(self.dir)
            return account

    def remove(self, uid):
        with self._lock:
            account = self.get(uid)
            if account is None:
                return False
            account.delete()
            self.accounts.remove(account)
            return True

    # -- 选择与健康 --------------------------------------------------------
    def count_ready(self, realm=None, model=None):
        with self._lock:
            snapshot = [a for a in self.accounts if not realm or a.realm == realm]
        return sum(1 for a in snapshot if a.enabled and a.access_token and
                   a.ready(model=model))

    def pick_for_session(self, realm=None, session_key=None, exclude=None, model=None):
        exclude = exclude or set()
        # 绑定账号的"忙"分两种，处置必须不同：
        #   - 并发满（瞬时，秒级）：**保持绑定**，由调用方 try_acquire 给短退避。
        #     解绑会造成对话级账号漂移、prompt 缓存作废。
        #   - 日总量耗尽（持久，小时级）：**必须解绑改选**，否则一个长会话会被
        #     整天钉在同一号上（正是"谁被用得多谁先死"）。故此处只查日总量。
        if session_key:
            bound_uid = self.affinity.get(session_key)
            if bound_uid and bound_uid not in exclude:
                account = self.get(bound_uid)
                if account and account.realm == realm and account.ready(model=model) \
                        and account.has_capacity(max_concurrent=0):
                    return account
                self.affinity.unbind(session_key)
        account = self.pick(realm=realm, exclude=exclude, model=model)
        # 只把会话绑到**有容量**的账号：否则下一轮发现满员又解绑，造成亲和
        # 抖动（会话在账号间来回跳），与"同会话固定账号"的目标相冲。
        if account and session_key and account.has_capacity():
            self.affinity.bind(session_key, account.uid)
        return account

    def pick(self, realm=None, exclude=None, model=None):
        """选号：负载最小优先，同负载按游标轮询打破平局。

        教训（经验③/⑥）：所有对上游发请求的选号入口都必须过同一道闸。
        这里统一叠加 has_capacity()，让"谁被用得多"不再集中到头部账号。

        均匀分布由两层保证：
          1. **负载最小优先**：候选按 (日请求数, 在途数) 升序，今天被用得少的
             先上 —— 自我纠偏：某号因重试/冷却恢复/亲和绑定偏移而落后时，
             后续新会话优先补给它，各号请求量长期趋近相等。
          2. **游标轮询打破平局**：负载完全相同时选离游标最近者并推进游标，
             退化行为与纯轮询一致（防"偶数号池只落在同一半"的步长问题）。
        """
        exclude = exclude or set()
        with self._lock:
            snapshot = [a for a in self.accounts if not realm or a.realm == realm]
            start = self._cursor
        total = len(snapshot)
        if total == 0:
            return None
        # 第一轮：ready 且有容量；第二轮：放宽容量。
        # 放宽是**有意的可用性兜底**（全池瞬时打满时宁可超发也不硬失败），
        # 但它确实会让并发上限失效——所以显式记日志，让它可观测而非静默。
        # 低余额硬过滤只加在这里（不动 ready()——它被面板展示等多处复用）：
        # remain < floor 的号跳过；余额未知（从未探测）不参与过滤。
        for require_capacity in (True, False):
            best = None      # (负载键, 候选下标, 账号)；负载键越小越优先
            for offset in range(total):
                index = (start + offset) % total
                account = snapshot[index]
                if account.uid in exclude:
                    continue
                if not account.ready(model=model):
                    continue
                if account.low_balance():
                    continue
                if require_capacity and not account.has_capacity():
                    continue
                stats = account.load_stats()
                key = (stats["daily"], stats["inflight"], offset)
                if best is None or key < best[0]:
                    best = (key, index, account)
            if best is None:
                continue
            _, index, account = best
            if not require_capacity:
                # 第二轮命中满员账号：**不是**要超发，而是要把这个账号交给
                # 调用方，让它的 try_acquire 失败并走"忙 -> 短退避"分支
                # （区分"忙"与"故障"，避免高负载把健康池喂进 failgate）。
                self.log("all accounts at capacity - returning %s for "
                         "caller-side backpressure" % account.uid[:8])
            with self._lock:
                self._cursor = (index + 1) % total
            return account
        # 降级：候选全部低于余额下限。宁可耗尽报错（110/112 走 quotaUntil）
        # 也不主动拒服务——按 remain 降序选余额最多的一个，并记日志。
        fallback = [a for a in snapshot
                    if a.uid not in exclude and a.ready(model=model)]
        if fallback:
            fallback.sort(key=lambda a: a.credit_remain() or 0, reverse=True)
            account = fallback[0]
            self.log("all candidates below low-balance floor (%d) - "
                     "picking %s (remain=%s) anyway"
                     % (account.low_balance_floor(), account.uid[:8],
                        account.credit_remain()))
            with self._lock:
                self._cursor = (snapshot.index(account) + 1) % total
            return account
        return None

    def representative(self, realm=None):
        """代表账号（用于健康/用量展示）。

        教训（经验⑥）：这里原先只要 access_token 就返回，绕过 ready()。
        改为优先返回可用账号；仅在全部不可用时才退回任一账号，保证展示不空。
        """
        with self._lock:
            candidates = [a for a in self.accounts if not realm or a.realm == realm]
        for account in candidates:
            if account.access_token and account.ready():
                return account
        for account in candidates:
            if account.access_token:
                return account
        return candidates[0] if candidates else None

    def set_enabled(self, uid, enabled):
        account = self.get(uid)
        if account is None:
            return None
        account.enabled = bool(enabled)
        if enabled:
            account.clear_error()
            # 人工重新启用是显式恢复动作：一并清掉 session-dead 计数，
            # 避免残留 streak 让下次单次命中就直接禁用。
            account.clear_session_dead()
        account.save(self.dir)
        return account.public()

    def set_all_enabled(self, enabled, realm=None):
        with self._lock:
            for account in self.accounts:
                if realm and account.realm != realm:
                    continue
                account.enabled = bool(enabled)
                if enabled:
                    account.clear_error()
                    account.clear_session_dead()
                account.save(self.dir)

    # -- 导入 / 导出 -------------------------------------------------------
    def preview_import_rows(self, rows, realm=None, overwrite=False):
        """报告 import_rows() 会做什么，不触碰账号池（Dry-Run）。"""
        preview = {"added": [], "updated": [], "skipped": [], "invalid": []}
        known = {a.uid for a in self.accounts}
        seen = set()
        for index, row in enumerate(rows):
            try:
                kwargs = normalise_import_row(row, realm=realm)
            except Exception as exc:
                preview["invalid"].append({"index": index + 1, "reason": str(exc)})
                continue
            uid = kwargs["uid"]
            if uid in seen:
                preview["skipped"].append({"uid": uid,
                                           "reason": "duplicate inside the document"})
            elif uid in known and not overwrite:
                preview["skipped"].append({"uid": uid, "reason": "already exists"})
            elif uid in known:
                preview["updated"].append(uid)
            else:
                preview["added"].append(uid)
            seen.add(uid)
        return preview

    def import_rows(self, rows, realm=None, overwrite=False):
        """从导出/外部文档批量导入账号。

        返回报告：added / updated / skipped / invalid。
        一行解析失败不影响其余行；全部解析通过才写盘。
        """
        added, updated, skipped, invalid = [], [], [], []
        seen = set()
        for index, row in enumerate(rows):
            try:
                kwargs = normalise_import_row(row, realm=realm)
            except Exception as exc:
                invalid.append({"index": index + 1, "reason": str(exc)})
                continue
            uid = kwargs["uid"]
            if uid in seen:
                skipped.append({"uid": uid,
                                "reason": "duplicate inside the document"})
                continue
            seen.add(uid)
            existing = self.get(uid) is not None
            if existing and not overwrite:
                skipped.append({"uid": uid, "reason": "already exists"})
                continue
            try:
                self.add(Account(kwargs))
            except Exception as exc:
                invalid.append({"index": index + 1, "reason": str(exc)})
                continue
            (updated if existing else added).append(uid)
        return {
            "added": added,
            "updated": updated,
            "skipped": skipped,
            "invalid": invalid,
        }

    # -- OAuth 设备授权登录 ------------------------------------------------
    @staticmethod
    def _local_machine_id(realm):
        """读取本机官方客户端的 machine_id（优先，保持设备一致），缺则生成。"""
        cfg = get_realm_config(realm)
        home = os.path.join(os.path.expanduser("~"), cfg["home_dir"], ".auth")
        p = os.path.join(home, "machine_id")
        try:
            with open(p, encoding="utf-8") as fh:
                mid = fh.read().strip()
            if mid:
                return mid
        except Exception:
            pass
        return str(uuid.uuid4())

    def start_login(self, realm="cn", platform="CLI"):
        """构造 PKCE 设备授权 URL（浏览器打开完成授权）。

        双区 URL 参数差异（官方逆向）：
          CN   : challenge, challenge_method, nonce(带横线), redirect_uri,
                 client_id, machine_id
          Intl : challenge, challenge_method, nonce(32-hex), client_id,
                 machine_id（新协议带 client_id/machine_id、不带 redirect_uri）
        """
        cfg = get_realm_config(realm)
        verifier, challenge = _make_pkce()
        nonce = uuid.uuid4().hex if not cfg["nonce_dashed"] else str(uuid.uuid4())
        q = {
            "challenge": challenge,
            "challenge_method": "S256",
            "nonce": nonce,
        }
        if cfg.get("send_redirect_uri"):
            q["redirect_uri"] = cfg["redirect_uri"]
        if cfg.get("send_client_id"):
            q["client_id"] = cfg["client_id"]
            q["machine_id"] = self._local_machine_id(realm)
        auth_url = cfg["website"] + "/device/selectAccounts?" + urllib.parse.urlencode(q)
        state = "qd-%d" % time.time_ns()
        with self._lock:
            self.logins[state] = {
                "created": time.time(),
                "verifier": verifier,
                "nonce": nonce,
                "region": realm,
                "platform": platform,
            }
        return {"state": state, "authUrl": auth_url, "realm": realm,
                "platform": platform}

    def poll_login(self, state):
        state = str(state or "").strip()
        with self._lock:
            info = self.logins.get(state)
        if not info:
            return {"status": "unknown",
                    "message": "state not recognised - start the login again"}
        if time.time() - info["created"] > LOGIN_TTL_SECONDS:
            with self._lock:
                self.logins.pop(state, None)
            return {"status": "expired", "message": "login window expired - start again"}
        realm = info.get("region") or "cn"
        cfg = get_realm_config(realm)
        q = urllib.parse.urlencode({
            "nonce": info["nonce"],
            "verifier": info["verifier"],
            "challenge_method": "S256",
        })
        url = cfg["openapi"] + PATH_DEVICE_POLL + "?" + q
        validate_public_http_url(url)
        req = urllib.request.Request(url, method="GET", headers={
            "Accept": "application/json",
            "User-Agent": "QoderWork",
        })
        try:
            with open_url(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                status = resp.status
        except urllib.error.HTTPError as exc:
            # 404 / 202 = 用户尚未完成授权（继续轮询）
            if exc.code in (404, 202):
                return {"status": "pending",
                        "message": "等待浏览器完成 Qoder 设备授权"}
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return {"status": "error", "message": "poll http %d %s" % (exc.code, body[:160])}
        except Exception as exc:
            return {"status": "pending", "message": "poll error: %s" % exc}
        if status in (404, 202):
            return {"status": "pending", "message": "等待浏览器完成 Qoder 设备授权"}
        try:
            data = json.loads(raw)
        except Exception:
            return {"status": "pending", "message": "waiting for grant"}
        token = data.get("token") or data.get("device_token") or ""
        if not token:
            return {"status": "pending", "message": "waiting for token"}

        uid = str(data.get("user_id") or "")
        nickname = ""
        # 拉取 userinfo 补全昵称/用户类型（尽力而为，不阻塞入库）
        try:
            ui_url = cfg["openapi"] + PATH_USERINFO
            validate_public_http_url(ui_url)
            req_ui = urllib.request.Request(ui_url, method="GET", headers={
                "Accept": "application/json",
                "User-Agent": CLIENT_UA,
                "Authorization": "Bearer " + token,
            })
            with open_url(req_ui, timeout=15) as resp_ui:
                ui = json.loads(resp_ui.read().decode("utf-8"))
            uid = str(ui.get("id") or uid)
            nickname = str(ui.get("name") or "")
            user_type = str(ui.get("user_type") or "") or DEFAULT_USER_TYPE
            org_id = str(ui.get("organization_id") or "")
            org_name = str(ui.get("organization_name") or "")
        except Exception:
            user_type, org_id, org_name = DEFAULT_USER_TYPE, "", ""

        account = Account({
            "uid": uid or ("q-" + uuid.uuid4().hex[:24]),
            "nickname": nickname or ("u" + (uid[-8:] if uid else "")),
            "domain": cfg["domain"],
            "realm": realm,
            "platform": info.get("platform") or "CLI",
            "accessToken": token,
            "refreshToken": data.get("refresh_token") or "",
            "expiresAt": _device_expiry(data),
            "source": "oauth",
            "enabled": True,
            "userType": user_type,
            "organizationId": org_id,
            "organizationName": org_name,
        })
        self.add(account)
        with self._lock:
            self.logins.pop(state, None)
        return {"status": "ok", "account": account.public()}

    def cancel_login(self, state):
        with self._lock:
            return self.logins.pop(state, None) is not None

    # -- PAT 导入 ----------------------------------------------------------
    def import_pat(self, pat, realm="cn"):
        """导入 pt- 个人访问令牌：交换 jobToken 并拉取身份后入库。"""
        pat = str(pat or "").strip()
        if not pat.startswith("pt-"):
            raise ValueError("PAT must start with pt-")
        cfg = get_realm_config(realm)
        data = http_json(cfg["openapi"] + PATH_JOB_EXCHANGE,
                         data=json.dumps({"personal_token": pat}).encode(),
                         method="POST",
                         headers={"Content-Type": "application/json",
                                  "Accept": "application/json",
                                  "User-Agent": CLIENT_UA},
                         timeout=30)
        token = data.get("token") or ""
        if not token:
            raise ValueError("jobToken exchange returned no token")
        uid, nickname, user_type, org_id, org_name = "", "", DEFAULT_USER_TYPE, "", ""
        try:
            ui = http_json(cfg["openapi"] + PATH_USERINFO, method="GET",
                           headers={"Accept": "application/json",
                                    "User-Agent": CLIENT_UA,
                                    "Authorization": "Bearer " + token},
                           timeout=15, retries=2)
            uid = str(ui.get("id") or "")
            nickname = str(ui.get("name") or "")
            user_type = str(ui.get("user_type") or "") or DEFAULT_USER_TYPE
            org_id = str(ui.get("organization_id") or "")
            org_name = str(ui.get("organization_name") or "")
        except Exception:
            pass
        if data.get("expires_in"):
            exp = int(time.time() + int(data["expires_in"]) / 1000)
        else:
            exp = int(time.time()) + 24 * 3600
        account = Account({
            "uid": uid or ("p-" + uuid.uuid4().hex[:24]),
            "nickname": nickname or ("u" + (uid[-8:] if uid else uid[:8])),
            "domain": cfg["domain"],
            "realm": realm,
            "platform": "CLI",
            "accessToken": token,
            "refreshToken": data.get("refresh_token") or "",
            "personalToken": pat,
            "expiresAt": exp,
            "source": "pat",
            "enabled": True,
            "userType": user_type,
            "organizationId": org_id,
            "organizationName": org_name,
        })
        self.add(account)
        return account


def _make_pkce():
    """RFC 7636 S256: (verifier, challenge)。"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    raw = os.urandom(64)
    verifier = "".join(alphabet[b % len(alphabet)] for b in raw)
    challenge = __import__("hashlib").sha256(verifier.encode("ascii")).digest()
    import base64 as _b64
    return verifier, _b64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# 本机已登录凭证的只读探测与导入（与 wb 网关的桌面扫描同构，双区都支持）
#
# 两类官方存储：
#   1. 桌面 App（Electron）： %APPDATA%\com.qoder[.cn].app.stable\auth.v1.dat
#      布局 "v10" + AES-256-GCM；密钥在同目录 Local State 的
#      os_crypt.encrypted_key（DPAPI 保护）-> 剥 "DPAPI" 前缀 -> DPAPI 解出。
#      明文 schema: {schemaVersion, token(dt-), refreshToken(drt-), expiresAt,
#                    user:{id,name,email,...}}
#   2. CLI/官方客户端： ~/.qoder[.cn]/.auth/user[.{profile}]
#      AES-128-CBC key=iv=machine_id 前 16 字符，标准 Base64（strict padding）；
#      明文 UserInfo JSON（或明文以 "{" 开头的兼容形态）。
# 扫描全程只读；看板两步确认后才写入网关账号池。
# ---------------------------------------------------------------------------
def _read_chromium_os_crypt_key(app_dir):
    """Local State.os_crypt.encrypted_key -> DPAPI 解出的 32 字节 AES key。"""
    import base64 as _b64
    from qoder_sign import dpapi_unprotect
    p = os.path.join(app_dir, "Local State")
    with open(p, encoding="utf-8") as fh:
        state = json.load(fh)
    ek = (state.get("os_crypt") or {}).get("encrypted_key")
    if not ek:
        raise RuntimeError("Local State has no os_crypt.encrypted_key")
    blob = _b64.b64decode(ek)
    if blob[:5] != b"DPAPI":
        raise RuntimeError("unexpected encrypted_key header %r" % blob[:5])
    return dpapi_unprotect(blob[5:])


def _roaming_app_dir(cfg):
    base = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(base, cfg["app_dir"])


def _load_app_auth(realm):
    """解出桌面 App auth.v1.dat 的明文 dict；失败抛异常。"""
    from qoder_sign import chromium_decrypt_v10
    cfg = get_realm_config(realm)
    app_dir = _roaming_app_dir(cfg)
    key = _read_chromium_os_crypt_key(app_dir)
    with open(os.path.join(app_dir, "auth.v1.dat"), "rb") as fh:
        blob = fh.read()
    plain = chromium_decrypt_v10(blob, key)
    data = json.loads(plain.decode("utf-8"))
    if not isinstance(data, dict) or not data.get("token"):
        raise RuntimeError("auth.v1.dat has unexpected schema")
    return data


def _load_cli_user(realm, path, machine_key):
    """解 CLI 端 ~/.qoder*/.auth/user（AES-128-CBC）或明文兼容形态。"""
    from qoder_sign import aes_cbc_decrypt
    with open(path, encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw.startswith("{"):
        return json.loads(raw)
    key = (machine_key or "")[:16].encode("utf-8")
    if len(key) != 16:
        raise RuntimeError("machine_id shorter than 16 bytes")
    pt = aes_cbc_decrypt(base64.b64decode(raw), key, key)
    return json.loads(pt.decode("utf-8"))


def scan_desktop_credentials():
    """只读探测本机双区已登录凭证。返回候选列表（不含任何明文令牌）。"""
    found = []
    for realm in ("intl", "cn"):
        cfg = get_realm_config(realm)
        # 1) 桌面 App (auth.v1.dat)
        item = {
            "kind": "app",
            "path": os.path.join(_roaming_app_dir(cfg), "auth.v1.dat"),
            "file": "auth.v1.dat",
            "realm": realm,
            "realmName": cfg["name"],
            "domain": cfg["domain"],
            "readable": False,
            "valid": False,
            "uid": "",
            "nickname": "",
            "expiresAt": 0,
            "error": "",
        }
        try:
            data = _load_app_auth(realm)
            user = data.get("user") or {}
            item["readable"] = True
            exp = normalize_epoch(data.get("expiresAt")) or 0
            if not exp and data.get("token"):
                # expiresAt 是 RFC3339 -> normalize_epoch 处理不了，单独解析
                try:
                    import datetime
                    exp = int(datetime.datetime.strptime(
                        str(data["expiresAt"])[:19], "%Y-%m-%dT%H:%M:%S"
                    ).timestamp())
                except Exception:
                    exp = 0
            token_prefix = str(data.get("token") or "")[:3]
            item.update({
                "valid": token_prefix == "dt-" or bool(data.get("refreshToken")),
                "uid": str(user.get("id") or ""),
                "nickname": str(user.get("name") or ""),
                "expiresAt": exp,
                "expiresIn": _human_delta(exp - time.time()) if exp else None,
            })
        except FileNotFoundError:
            item["error"] = "not found (未登录或未安装该版本客户端)"
        except Exception as exc:
            item["error"] = str(exc)
        found.append(item)

        # 2) CLI 端 user / user.{profile}
        auth_dir = os.path.join(os.path.expanduser("~"), cfg["home_dir"], ".auth")
        if os.path.isdir(auth_dir):
            machine_key = ""
            try:
                with open(os.path.join(auth_dir, "machine_id"),
                          encoding="utf-8") as fh:
                    machine_key = fh.read().strip()
            except Exception:
                pass
            try:
                names = [n for n in os.listdir(auth_dir)
                         if n == "user" or n.startswith("user.")]
            except Exception:
                names = []
            for n in names:
                p = os.path.join(auth_dir, n)
                cli_item = {
                    "kind": "cli",
                    "path": p,
                    "file": n,
                    "realm": realm,
                    "realmName": cfg["name"],
                    "domain": cfg["domain"],
                    "readable": False,
                    "valid": False,
                    "uid": "",
                    "nickname": "",
                    "expiresAt": 0,
                    "error": "",
                }
                try:
                    data = _load_cli_user(realm, p, machine_key)
                    token = str(data.get("access_token") or "")
                    cli_item["readable"] = True
                    exp = normalize_epoch(data.get("expire_time"))
                    cli_item.update({
                        "valid": token.startswith(("dt-", "jt-")),
                        "uid": str(data.get("uid") or ""),
                        "nickname": str(data.get("name") or ""),
                        "expiresAt": exp,
                        "expiresIn": _human_delta(exp - time.time()) if exp else None,
                    })
                except Exception as exc:
                    cli_item["error"] = str(exc)
                found.append(cli_item)
    return found


def import_desktop_credential(path=None, realm=None):
    """把扫描到的凭证导入账号池。path=None 时导入扫描到的全部有效项。"""
    if not path:
        imported, errors = [], []
        for item in scan_desktop_credentials():
            if not item.get("valid"):
                continue
            try:
                imported.append(import_desktop_credential(
                    path=item["path"], realm=item["realm"]))
            except Exception as exc:
                errors.append("%s/%s: %s" % (item["realm"], item["file"], exc))
        if errors:
            raise RuntimeError("; ".join(errors[:3]))
        return imported

    # 定位该 path 归属的 realm（按扫描结果匹配；否则按目录名猜）
    target_realm = realm
    matched = None
    for item in scan_desktop_credentials():
        if os.path.abspath(item["path"]) == os.path.abspath(path):
            matched = item
            target_realm = item["realm"]
            break
    if target_realm not in REALM_CONFIGS:
        target_realm = "cn"
    cfg = get_realm_config(target_realm)

    token = refresh = ""
    uid = nickname = ""
    exp = 0
    base = os.path.basename(path)
    if base == "auth.v1.dat":
        data = _load_app_auth(target_realm)
        token = str(data.get("token") or "")
        refresh = str(data.get("refreshToken") or "")
        user = data.get("user") or {}
        uid = str(user.get("id") or "")
        nickname = str(user.get("name") or "")
        try:
            import datetime
            exp = int(datetime.datetime.strptime(
                str(data.get("expiresAt") or "")[:19], "%Y-%m-%dT%H:%M:%S"
            ).timestamp())
        except Exception:
            exp = 0
    else:
        auth_dir = os.path.dirname(path)
        machine_key = ""
        try:
            with open(os.path.join(auth_dir, "machine_id"),
                      encoding="utf-8") as fh:
                machine_key = fh.read().strip()
        except Exception:
            pass
        data = _load_cli_user(target_realm, path, machine_key)
        token = str(data.get("access_token") or "")
        refresh = str(data.get("refresh_token") or "")
        uid = str(data.get("uid") or "")
        nickname = str(data.get("name") or "")
        exp = normalize_epoch(data.get("expire_time"))

    if not token:
        raise RuntimeError("credential has no access token")
    if not uid:
        uid = "d-" + uuid.uuid4().hex[:24]
    account = Account({
        "uid": uid,
        "nickname": nickname or uid[:8],
        "domain": cfg["domain"],
        "realm": target_realm,
        "platform": "CLI",
        "accessToken": token,
        "refreshToken": refresh,
        "expiresAt": exp or (int(time.time()) + 30 * 86400),
        "source": "desktop-app",
        "enabled": True,
    })
    return add_to_pool(account)


# ---------------------------------------------------------------------------
# 导入 / 导出（与 WorkBuddy 网关同构的文档格式）
# ---------------------------------------------------------------------------
EXPORT_FORMAT = "qoder-accounts"
EXPORT_VERSION = 1

# 描述运行期状态而非凭证本身的字段：导入时导出可查、但绝不信任。
VOLATILE_FIELDS = ("cooldownUntil", "lastError", "credits", "lastCheckin",
                   "plan", "sessionDeadStreak", "quotaUntil")


def account_to_export(account):
    data = account.to_dict()
    data.pop("path", None)
    return data


def build_export_document(accounts, realm=None, include_secrets=True, uids=None):
    wanted = None
    if uids is not None:
        wanted = {str(u) for u in uids}
    rows = []
    for account in accounts:
        if realm and account.realm != realm:
            continue
        if wanted is not None and account.uid not in wanted:
            continue
        row = account_to_export(account)
        if not include_secrets:
            row.pop("accessToken", None)
            row.pop("refreshToken", None)
            row.pop("personalToken", None)
        rows.append(row)
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(rows),
        "accounts": rows,
    }


def _coerce_account_rows(blob):
    """把任意受支持的容器规整成账号 dict 列表。返回 (rows, error)。"""
    if isinstance(blob, list):
        rows = blob
    elif isinstance(blob, dict) and isinstance(blob.get("accounts"), list):
        rows = blob["accounts"]
    elif isinstance(blob, dict):
        looks_like_account = (
            blob.get("accessToken")
            or isinstance(blob.get("auth"), dict)
            or isinstance(blob.get("account"), dict)
        )
        if not looks_like_account:
            keys = ", ".join(sorted(blob.keys())[:6]) or "none"
            return [], ("not an account document (expected an accounts array, "
                        "a list, or an account object; got keys: %s)" % keys)
        rows = [blob]
    else:
        return [], "expected an object or a list of accounts"

    out = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            return [], "account #%d is not an object" % (index + 1)
        out.append(row)
    if not out:
        return [], "no accounts found in the document"
    return out, ""


def normalise_import_row(row, realm=None):
    """把一行导入数据规整成 Account kwargs；无可用凭证时 raise ValueError。"""
    auth = row.get("auth") if isinstance(row.get("auth"), dict) else None
    profile = row.get("account") if isinstance(row.get("account"), dict) else None

    def pick(key, default=None):
        for layer in (row, auth, profile):
            if isinstance(layer, dict) and layer.get(key) not in (None, ""):
                return layer.get(key)
        return default

    token = str(pick("accessToken") or "").strip()
    if not token:
        raise ValueError("no accessToken")
    detected = str(realm or pick("realm") or "").strip().lower()
    if detected not in ("cn", "intl"):
        detected = detect_realm_from_domain(pick("domain"))
    cfg = get_realm_config(detected)
    raw_uid = str(pick("uid") or "").strip()
    uid = re.sub(r"[^A-Za-z0-9_-]", "_", raw_uid).strip("_ ")
    if not uid:
        uid = "p-" + uuid.uuid4().hex[:24]
    exp = normalize_epoch(pick("expiresAt"))
    if not exp:
        exp = int(time.time()) + 3600
    return {
        "uid": uid,
        "nickname": str(pick("nickname") or ""),
        "domain": str(pick("domain") or cfg["domain"]),
        "realm": detected,
        "platform": str(pick("platform") or "CLI"),
        "accessToken": token,
        "refreshToken": str(pick("refreshToken") or ""),
        "personalToken": str(pick("personalToken") or ""),
        "expiresAt": exp,
        "source": "import",
        "enabled": True,
        "userType": str(pick("userType") or "") or DEFAULT_USER_TYPE,
        "organizationId": str(pick("organizationId") or ""),
        "organizationName": str(pick("organizationName") or ""),
        "lastError": "",
        "cooldownUntil": 0.0,
        # 账号级出口必须随导入保留：否则导入/覆盖会把已配置的出口静默清空，
        # 该账号悄悄退回全局出口（出口突变 = 关联信号）。
        "egress": pick("egress") if isinstance(pick("egress"), dict) else {},
    }