#!/usr/bin/env python3
"""Qoder -> OpenAI-compatible reverse proxy (CN + Intl dual realm).

把 Qoder 国内版 (qoder.com.cn) 与国际版 (qoder.com) 的原生服务封装为标准
OpenAI 兼容接口。上游链路：

    客户端 OpenAI 请求
      -> build_qoder_body()      (官方 baseprompt 模板 + 会话压平)
      -> qoder_encode()          (Qoder 自定义 Base64 变体)
      -> COSY 签名               (RSA 包裹 AES 会话密钥 + MD5 请求签名)
      -> POST {gateway}/algo/api/v2/service/pro/sse/agent_chat_generation
      -> SSE 信封解包            ({"headers","body","statusCodeValue"} 嵌套帧)
      -> 标准 OpenAI SSE / chat.completion 回给客户端

暴露：
    GET  /v1/models
    POST /v1/chat/completions     (stream=true / false)
    POST /v1/responses            (Responses API 双向转换)
    GET  /health
    以及看板全套管理接口 (accounts / usage / tasks / scheduler / settings / logs)

仅使用 Python 标准库（AES/RSA/COSY 签名均为内置纯实现）。

    python qoder_proxy.py                    # bind 127.0.0.1:8790
    python qoder_proxy.py --port 9000
    python qoder_proxy.py --api-key sk-local  # require a bearer token
"""
import argparse
import hashlib
import io
from collections import deque
import re
import select
import json
import os
MAX_PAYLOAD_BYTES = int(os.environ.get("QD_MAX_PAYLOAD_BYTES", 50 * 1024 * 1024))  # 50MB limit
import ipaddress
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import qoder_accounts
import qoder_catalog
import qoder_settings
import qoder_sign
from qoder_sign import qoder_encode, SESSIONS
from qoder_accounts import get_realm_config, CLIENT_UA
from pathlib import Path

VERSION = "1.0.0"

CURRENT_REALM = os.environ.get("QD_PROXY_DEFAULT_REALM", "cn")


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

    与 qoder_accounts.validate_public_http_url 同逻辑、独立实现防同错：
    本文件的 urlopen 调用点必须经过本文件的边界校验（签名链路上的 URL
    在 sess.headers() 之后再校验一次，确保进入 Request 的字符串是洁净的）。
    allow_local 仅供显式面向本机网关的开发/验证脚本使用。
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


def detect_model_realm(model_id):
    """模型 -> 出口区域。区域独占模型强制路由到其归属出口，其余跟随全局开关。"""
    owner = exclusive_realm(model_id)
    if owner:
        return owner
    if not model_id:
        return CURRENT_REALM
    return CURRENT_REALM


# 目前双区模型清单不同（源自官方 catalog 快照差集），独占表给区域特供模型。
INTL_EXCLUSIVE_PREFIXES = getattr(qoder_catalog, "INTL_EXCLUSIVE_PREFIXES", ())
CN_EXCLUSIVE_PREFIXES = getattr(qoder_catalog, "CN_EXCLUSIVE_PREFIXES", ())
INTL_EXCLUSIVE = getattr(qoder_catalog, "INTL_EXCLUSIVE", set())
CN_EXCLUSIVE = getattr(qoder_catalog, "CN_EXCLUSIVE", set())


def exclusive_realm(model_id):
    """"intl"/"cn" when only that exit serves the model, else "".

    先把人类可读别名解析成上游 key 再判独占（glm-5.2 -> gm51model 是国内独占）。
    """
    if not model_id:
        return ""
    m = str(model_id).lower()
    resolved = qoder_catalog.resolve_upstream_key(model_id).lower()
    for cand in (resolved, m):
        if cand in INTL_EXCLUSIVE or cand.startswith(INTL_EXCLUSIVE_PREFIXES):
            return "intl"
        if cand in CN_EXCLUSIVE or cand.startswith(CN_EXCLUSIVE_PREFIXES):
            return "cn"
    return ""


from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def install_console_close_handler():
    """Release the port when the console window is closed by the user.

    Windows does not kill child processes when a console window closes, so
    the proxy (started by the .bat as a child of cmd.exe) would survive and
    keep the port bound - the next launch then wrongly reports "another
    proxy is already running". Registering an event-driven handler for
    CTRL_CLOSE_EVENT is the reliable signal. Harmless without a console.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        CTRL_CLOSE_EVENT = 2
        CTRL_LOGOFF_EVENT = 5
        CTRL_SHUTDOWN_EVENT = 6

        def _handler(event):
            if event in (CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT):
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
                os._exit(0)
            return False

        handler = PHANDLER_ROUTINE(_handler)   # keep the callback referenced
        if not ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True):
            return None
        return handler
    except Exception:
        return None


CHAT_PATH = ("/algo/api/v2/service/pro/sse/agent_chat_generation"
             "?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1")
MODELS_PATH = "/algo/api/v2/model/list?Encode=1"
DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant."

# 官方 baseprompt 模板（与桌面端一致的请求体骨架）
BASEPROMPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "baseprompt.json")
try:
    with open(BASEPROMPT_PATH, encoding="utf-8") as _bp_fh:
        BASEPROMPT = json.load(_bp_fh)
except Exception:
    BASEPROMPT = {}

NOISE_KEYS = ("extra_fields", "refusal", "reasoning_content")


class BodyTooLarge(Exception):
    """Raised when a request body exceeds the configured cap."""

    def __init__(self, length):
        super(BodyTooLarge, self).__init__(length)
        self.length = length


class BadJSON(Exception):
    """Raised when a request body is present but not a JSON object."""


class UpstreamStatus(Exception):
    """Raised when the upstream SSE envelope carries a non-200 status."""

    def __init__(self, status, detail=""):
        super(UpstreamStatus, self).__init__("upstream status %s" % status)
        self.status = status
        self.detail = str(detail or "")


# CORS is only needed by browser-based chat clients that call the OpenAI-style
# API from another origin. Management routes serve the dashboard (same-origin)
# and get no ACAO header - that keeps a stray LAN page from reading them.
CORS_PATH_PREFIXES = ("/v1", "/chat", "/completions", "/models", "/responses")
MANAGEMENT_PATH_PREFIXES = ("/v1/usage", "/usage", "/accounts", "/settings",
                            "/tasks", "/scheduler", "/panel", "/logs")


def cors_origin_allowed(path):
    """True when the OpenAI-style API path should advertise CORS."""
    path = (path or "").split("?")[0]
    if path.startswith(MANAGEMENT_PATH_PREFIXES):
        return False
    return path.startswith(CORS_PATH_PREFIXES)


_lock = threading.Lock()
_login_lock = threading.Lock()
_login_attempts = {}  # ip -> list of timestamp


def _prune_login_attempts(now=None, window=60):
    """Drop stale per-IP entries so the dict cannot grow without bound.

    Caller must hold _login_lock.
    """
    now = now or time.time()
    for ip in list(_login_attempts.keys()):
        recent = [t for t in _login_attempts[ip] if now - t < window]
        if recent:
            _login_attempts[ip] = recent
        else:
            del _login_attempts[ip]


_models_cache = {"intl": {"at": 0.0, "data": None}, "cn": {"at": 0.0, "data": None}}

# Usage accounting: every upstream response carries a usage block, and the
# proxy also records one JSONL line per request.
USAGE_DIR = os.environ.get("QD_PROXY_USAGE_DIR") \
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage")
USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
USAGE_SUMMARY = os.path.join(USAGE_DIR, "usage-summary.json")
DASHBOARD_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "dashboard.html")
USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "reasoning_tokens",
                "cached_tokens", "total_tokens", "credit")

# Web-panel access control. The panel is gated by its own password (default
# "admin"), independent of the /v1 API key. Sessions live in memory only.
PANEL = qoder_settings.PanelSessions()
API_KEY_FILE_SET = False


def configured_keys():
    """Panel-managed API keys, always read fresh so panel edits apply at once."""
    try:
        return qoder_settings.api_keys(ACCOUNTS_DIR)
    except Exception as exc:
        log("could not read api keys: %s" % exc)
        return []


def auth_required():
    """Whether /v1 calls must present a key at all."""
    if qoder_settings.auth_disabled(ACCOUNTS_DIR):
        return False
    if any(entry.get("enabled") for entry in configured_keys()):
        return True
    return bool(API_KEY)


def identify_key(supplied):
    """Return the key entry a caller used, or None when nothing matches.

    Once the panel has at least one key, those keys are the only accepted
    credentials - otherwise a launcher key left in a .bat file would silently
    keep working after the panel was locked down.
    """
    extra = () if configured_keys() else (API_KEY,)
    return qoder_settings.match_api_key(ACCOUNTS_DIR, supplied, extra_keys=extra)


def _empty_stats():
    return {"requests": 0, "errors": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "reasoning_tokens": 0, "cached_tokens": 0,
            "total_tokens": 0, "credit": 0.0, "started": time.time(),
            "by_model": {},
            "ttft_ms_sum": 0, "ttft_samples": 0,
            "gen_ms_sum": 0, "gen_samples": 0,
            "wall_ms_sum": 0, "wall_samples": 0}


_usage = _empty_stats()


def _extract_usage(usage):
    """Normalize the upstream usage block into the fields we track."""
    if not usage:
        return {}
    details = usage.get("completion_tokens_details") or {}
    prompt_details = usage.get("prompt_tokens_details") or {}
    return {
        "prompt_tokens": usage.get("prompt_tokens") or 0,
        "completion_tokens": usage.get("completion_tokens") or 0,
        "reasoning_tokens": details.get("reasoning_tokens") or 0,
        "cached_tokens": usage.get("prompt_cache_hit_tokens")
        or details.get("cached_tokens") or prompt_details.get("cached_tokens") or 0,
        "total_tokens": usage.get("total_tokens") or 0,
        "credit": usage.get("credit") or 0,
    }


def row_matches_realm(row, realm):
    if not realm:
        return True
    r = row.get("realm")
    if r:
        return r == realm
    acct_uid = row.get("account")
    if acct_uid and POOL:
        acc = POOL.get(acct_uid)
        if acc:
            return acc.realm == realm
    model = row.get("model")
    if model:
        return detect_model_realm(model) == realm
    return realm == "cn"


def record_usage(model, usage, stream=None, elapsed_ms=None, ttft_ms=None,
                 gen_ms=None, fp=None, account=None, finish=None,
                 refusal=None, finish_raw=None):
    """Accumulate stats, append a JSONL row, and persist the summary.

    **即使上游未返回 usage 也必落一行并发 request.end**：模型拒绝、空响应
    等情形往往不带 usage，早退会让这类请求在 usage.jsonl 与 events.jsonl
    里完全不存在（实测：一次 refusal 响应事后无法在任何日志中定位）。
    """
    fields = _extract_usage(usage)
    row = {
        "at": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "stream": bool(stream),
        "elapsed_ms": elapsed_ms,
        "ttft_ms": ttft_ms,
        "gen_ms": gen_ms,
    }
    row.update(fields)
    # 口径统一：finish_reason 恒为**归一后**的值（与客户端所见一致）；
    # 上游原值不同时另记 finish_raw —— 流式路径此前记原始值、非流式记归一
    # 值，同一 refusal 用例两边字段不一致。
    _fin = normalize_finish_reason(finish) if finish else finish
    if _fin:
        row["finish_reason"] = _fin
    if finish_raw and finish_raw != _fin:
        row["finish_raw"] = str(finish_raw)[:60]
    if refusal:
        row["refusal"] = str(refusal)[:300]
    if fp:
        row.update(fp)
    if account:
        row["account"] = account
    acc = POOL.get(account) if (account and POOL) else None
    row["realm"] = acc.realm if acc else CURRENT_REALM
    # 请求级溯源字段：req_id + 排队/重试/换号遥测（仅在确有值时写入）。
    _ctx = current_ctx()
    if _ctx is not None:
        row["req_id"] = _ctx.req_id
        if _ctx.queue_waits:
            row["queue_waits"] = _ctx.queue_waits
            row["queue_ms"] = _ctx.queue_ms
            row["queue_max_hint_s"] = _ctx.queue_max_hint
        if _ctx.attempts:
            row["attempts"] = _ctx.attempts
        if _ctx.switches:
            row["account_switches"] = _ctx.switches
        if _ctx.retry_reasons:
            row["retry_reasons"] = ",".join(_ctx.retry_reasons)
        if _ctx.client_gone:
            row["client_gone"] = True
        # 每次落盘的终态行同时产出一条 request.end 事件，便于按 req 追溯。
        _write_event("request.end", status=200, stream=bool(stream),
                     account=account or "", finish=finish or "",
                     **(_ctx.to_fields()))
        _ctx.finished = True      # 防止重复闭合
    if gen_ms and gen_ms > 0 and fields.get("completion_tokens"):
        row["tokens_per_sec"] = round(
            fields["completion_tokens"] / (gen_ms / 1000.0), 2)
    if fields.get("prompt_tokens", 0) > 0:
        row["cache_hit_pct"] = round(
            fields["cached_tokens"] * 100.0 / fields["prompt_tokens"], 1)
    with _lock:
        _usage["requests"] += 1
        for k in USAGE_FIELDS:
            if k in fields:
                _usage[k] += fields[k]
        if ttft_ms is not None:
            _usage["ttft_ms_sum"] += ttft_ms
            _usage["ttft_samples"] += 1
        if gen_ms is not None:
            _usage["gen_ms_sum"] += gen_ms
            _usage["gen_samples"] += 1
        if elapsed_ms is not None:
            _usage["wall_ms_sum"] += elapsed_ms
            _usage["wall_samples"] += 1
        per = _usage["by_model"].setdefault(
            model, {"requests": 0, **{k: 0 for k in USAGE_FIELDS}})
        per["requests"] += 1
        for k in USAGE_FIELDS:
            if k in fields:
                per[k] += fields[k]
        summary = json.loads(json.dumps(_usage))
    _persist_usage(row, summary, "usage persist failed")
    # 低余额保护：成功后按估算成本扣减该账号内存余额（上游不逐请求报积分）。
    if acc is not None:
        try:
            cost, crossed = acc.deduct_credits(fields.get("total_tokens", 0))
            if crossed:
                log("account %s credits est. -%d crossed accel line %d - "
                    "probe in %ds"
                    % (acc.uid[:8], cost, qoder_accounts.LOW_BALANCE_ACCEL,
                       qoder_accounts.LOW_BALANCE_PROBE_DELAY_S),
                    level="WARN", tag="credits")
        except Exception:
            pass
    try:
        t_tokens = fields.get("total_tokens", 0)
        dur = " %dms" % elapsed_ms if elapsed_ms is not None else ""
        acc_tag = " acct=%s" % account[:8] if account else ""
        speed_tag = " %st/s" % row.get("tokens_per_sec", 0) \
            if row.get("tokens_per_sec") else ""
        log("chat done: model=%s%s%s tokens=%d (in=%d out=%d)%s"
            % (model, acc_tag, dur, t_tokens, fields.get("prompt_tokens", 0),
               fields.get("completion_tokens", 0), speed_tag), tag="chat")
    except Exception:
        pass
    return row


def _persist_usage(row, summary, fail_label):
    """Append one JSONL row and atomically rewrite the summary.

    The temp file carries a unique suffix: two threads writing the same
    "<summary>.tmp" race, and the loser's os.replace() fails with ENOENT
    because the winner already renamed the file away.
    """
    try:
        usage_dir = Path(USAGE_DIR).resolve()
        usage_dir.mkdir(parents=True, exist_ok=True)
        log_path = usage_dir / os.path.basename(USAGE_LOG)
        summary_path = usage_dir / os.path.basename(USAGE_SUMMARY)
        if not (log_path.is_relative_to(usage_dir)
                and summary_path.is_relative_to(usage_dir)):
            raise ValueError("usage path escapes base directory")
        # 走轮转写入：排队预算已是 15 分钟量级，usage.jsonl 必须按大小轮转，
        # 否则长期运行会把磁盘写满（原实现只 append，无任何上限）。
        _rotating_append(str(log_path),
                         json.dumps(row, ensure_ascii=False) + "\n")
        tmp_summary = usage_dir / (
            os.path.basename(USAGE_SUMMARY)
            + ".%d.%d.tmp" % (os.getpid(), threading.get_ident()))
        if not tmp_summary.is_relative_to(usage_dir):
            raise ValueError("usage path escapes base directory")
        try:
            tmp_summary.write_text(json.dumps(summary, ensure_ascii=False,
                                              indent=2), encoding="utf-8")
            os.replace(tmp_summary, summary_path)
        except Exception:
            try:
                os.unlink(tmp_summary)
            except Exception:
                pass
            raise
    except Exception as exc:
        log("%s: %s" % (fail_label, exc))


def record_error(model, status, message, elapsed_ms=None):
    """Count a failed request and append it to the log so errors are visible."""
    row = {
        "at": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "error": True,
        "status": status,
        # 保留更完整的上游错误（provider_error 的内层 details 常在 200+ 字节）
        "message": str(message)[:400],
        "elapsed_ms": elapsed_ms,
    }
    _ctx = current_ctx()
    if _ctx is not None:
        row["req_id"] = _ctx.req_id
        if _ctx.queue_waits:
            row["queue_waits"] = _ctx.queue_waits
            row["queue_ms"] = _ctx.queue_ms
            row["queue_max_hint_s"] = _ctx.queue_max_hint
        if _ctx.retry_reasons:
            row["retry_reasons"] = ",".join(_ctx.retry_reasons)
        _write_event("request.end", status=status, error=True,
                     message=str(message)[:200], **(_ctx.to_fields()))
        _ctx.finished = True      # 防止重复闭合
    with _lock:
        _usage["errors"] += 1
        if elapsed_ms is not None:
            _usage["wall_ms_sum"] += elapsed_ms
            _usage["wall_samples"] += 1
        summary = json.loads(json.dumps(_usage))
    _persist_usage(row, summary, "error persist failed")
    dur = " %dms" % elapsed_ms if elapsed_ms is not None else ""
    log("request error: model=%s%s status=%s msg=%s"
        % (model, dur, status, str(message)[:360]),
        level="ERROR", tag="chat")
    return row


def _pct(values, q):
    """Nearest-rank percentile (no interpolation) - good enough for latency."""
    if not values:
        return None
    ordered = sorted(values)
    idx = int(round((q / 100.0) * (len(ordered) - 1)))
    return ordered[max(0, min(len(ordered) - 1, idx))]


_perf_cache = {}
_perf_lock = threading.Lock()


def perf_stats(sample=5000, realm=None, ttl=10):
    """Cached wrapper: parsing thousands of rows is CPU-heavy, and the
    dashboard polls this endpoint every few seconds."""
    r = realm or CURRENT_REALM
    try:
        key = (int(sample), r)
    except Exception:
        key = (5000, r)
    now = time.time()
    with _perf_lock:
        hit = _perf_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _perf_stats_uncached(sample, realm)
    with _perf_lock:
        _perf_cache[key] = (time.time(), data)
    return data


def _perf_stats_uncached(sample=5000, realm=None):
    """Latency percentiles + derived rates, computed from the JSONL log."""
    ttfts, gens, walls, rates, hits, tok_rates = [], [], [], [], [], []
    total = ok = err = 0
    m_buckets = {}
    # 排队统计：直接回答"平时排队多久、能不能等到"。
    queue_ms_all = []      # 每次"排过队"的请求的累计等待
    queued_ok = queued_err = 0
    retry_counter = {}
    # 只读日志末尾 sample 行：readlines() 会把整个日志读成字符串列表。
    rows = [raw.decode("utf-8", "replace") for raw in _tail_lines(USAGE_LOG, sample)]
    for line in rows:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if realm and not row_matches_realm(r, realm):
            continue
        total += 1
        _qms = r.get("queue_ms")
        if _qms:
            queue_ms_all.append(_qms)
            if r.get("error"):
                queued_err += 1
            else:
                queued_ok += 1
        for _rr in (r.get("retry_reasons") or "").split(","):
            if _rr:
                retry_counter[_rr] = retry_counter.get(_rr, 0) + 1
        if r.get("error"):
            err += 1
            if r.get("elapsed_ms"):
                walls.append(r["elapsed_ms"])
            continue
        ok += 1
        if r.get("ttft_ms") is not None:
            ttfts.append(r["ttft_ms"])
        if r.get("gen_ms") is not None:
            gens.append(r["gen_ms"])
        if r.get("elapsed_ms") is not None:
            walls.append(r["elapsed_ms"])
        if r.get("tokens_per_sec"):
            tok_rates.append(r["tokens_per_sec"])
        if r.get("cache_hit_pct") is not None:
            hits.append(r["cache_hit_pct"])
        m_id = r.get("model") or "unknown"
        mb = m_buckets.setdefault(m_id, {"total": 0, "ok": 0, "err": 0,
                                         "ttfts": [], "gens": [], "walls": [],
                                         "tok_rates": [], "hits": []})
        mb["total"] += 1
        if r.get("error"):
            mb["err"] += 1
        else:
            mb["ok"] += 1
        if r.get("ttft_ms") is not None:
            mb["ttfts"].append(r["ttft_ms"])
        if r.get("gen_ms") is not None:
            mb["gens"].append(r["gen_ms"])
        if r.get("elapsed_ms") is not None:
            mb["walls"].append(r["elapsed_ms"])
        if r.get("tokens_per_sec"):
            mb["tok_rates"].append(r["tokens_per_sec"])
        if r.get("cache_hit_pct") is not None:
            mb["hits"].append(r["cache_hit_pct"])

    def block(vals):
        if not vals:
            return None
        return {
            "avg": round(sum(vals) / len(vals), 1),
            "p50": _pct(vals, 50),
            "p90": _pct(vals, 90),
            "p99": _pct(vals, 99),
            "max": max(vals),
            "samples": len(vals),
        }

    _queued_total = queued_ok + queued_err
    queue_block = {
        "requests_that_queued": _queued_total,
        "succeeded_after_queue": queued_ok,
        "failed_after_queue": queued_err,
        "queue_success_rate_pct": round(queued_ok * 100.0 / _queued_total, 1)
        if _queued_total else None,
        "wait_ms": block(queue_ms_all) if queue_ms_all else None,
        "retry_reasons": dict(sorted(retry_counter.items(),
                                     key=lambda kv: -kv[1])),
    }
    return {
        "sampled": total,
        "success": ok,
        "errors": err,
        "success_rate_pct": round(ok * 100.0 / total, 1) if total else None,
        "queue": queue_block,
        "ttft_ms": block(ttfts),
        "generation_ms": block(gens),
        "wall_ms": block(walls),
        "tokens_per_sec": block(tok_rates),
        "cache_hit_pct": block(hits),
        "by_model": {
            mid: {
                "requests": mb["total"],
                "errors": mb["err"],
                "success_rate_pct": round(mb["ok"] * 100.0 / mb["total"], 1)
                if mb["total"] else None,
                "ttft_ms": block(mb["ttfts"]),
                "generation_ms": block(mb["gens"]),
                "wall_ms": block(mb["walls"]),
                "tokens_per_sec": block(mb["tok_rates"]),
                "cache_hit_pct": block(mb["hits"]),
            } for mid, mb in m_buckets.items()
        },
    }


_snap_cache = {}
_snap_lock = threading.Lock()


def usage_snapshot(realm=None, ttl=10):
    """Cached wrapper: the dashboard polls this every few seconds."""
    r = realm or CURRENT_REALM
    now = time.time()
    with _snap_lock:
        hit = _snap_cache.get(r)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _usage_snapshot_uncached(r)
    with _snap_lock:
        _snap_cache[r] = (time.time(), data)
    return data


def _usage_snapshot_uncached(realm=None):
    r = realm or CURRENT_REALM
    rep = POOL.representative(realm=r) if POOL else current_account()
    snap = _empty_stats()
    snap["started"] = _usage.get("started", time.time())
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if r and not row_matches_realm(row, r):
                    continue
                if row.get("error"):
                    snap["errors"] += 1
                else:
                    snap["requests"] += 1
                    for k in USAGE_FIELDS:
                        if k in row:
                            snap[k] += (row[k] or 0)
                    m = row.get("model") or "unknown"
                    per = snap["by_model"].setdefault(
                        m, {"requests": 0, "accounts": {},
                            **{k: 0 for k in USAGE_FIELDS}})
                    per["requests"] += 1
                    for k in USAGE_FIELDS:
                        if k in row:
                            per[k] += (row[k] or 0)
                    acct_id = row.get("account")
                    if acct_id:
                        per.setdefault("accounts", {})
                        per["accounts"][acct_id] = per["accounts"].get(acct_id, 0) + 1
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage snapshot read failed: %s" % exc)
    snap["since"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(snap.get("started", time.time())))
    snap["log_file"] = USAGE_LOG
    snap["realm"] = r
    snap["accounts_map"] = {a.uid: {"nickname": a.nickname, "realm": a.realm}
                            for a in POOL.accounts} if POOL else {}
    snap["account"] = {
        "uid": (rep.uid if rep else ""),
        "domain": (rep.domain if rep else ""),
        "issuer": ("qoder" if rep else ""),
        "credential_file": (os.path.basename(rep.path) if rep and rep.path else ""),
        "expires_at": (rep.expires_at if rep else 0),
        "accounts": (len(POOL.accounts) if POOL else 0),
        "accounts_ready": (POOL.count_ready() if POOL else 0),
    }
    return snap


def _tail_lines(path, max_lines, chunk=256 * 1024):
    """Return up to the last `max_lines` non-empty lines, oldest first.

    The usage log passes 20MB within a day. Scanning it end to end on every
    dashboard poll was the dominant cost behind slow /usage/* responses.
    """
    lines = []
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and len(lines) < max_lines:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                buf = parts[0]
                for raw in reversed(parts[1:]):
                    if not raw.strip():
                        continue
                    lines.append(raw)
                    if len(lines) >= max_lines:
                        break
            if len(lines) < max_lines and buf.strip():
                lines.append(buf)
    except FileNotFoundError:
        return []
    except Exception as exc:
        log("tail read failed: %s" % exc)
        return []
    lines.reverse()
    return lines


def count_usage_rows(realm=None):
    """Cheap row count - substring match instead of a full JSON parse."""
    needles = ()
    if realm:
        needles = ('"realm": "%s"' % realm, '"realm":"%s"' % realm)
    n = 0
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if not needles:
                    n += 1
                    continue
                if any(x in line for x in needles):
                    n += 1
                    continue
                if '"realm"' in line:
                    continue
                try:
                    if row_matches_realm(json.loads(line), realm):
                        n += 1
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return n


def recent_usage(limit=100, realm=None, page=1):
    """Paginated rows from the tail of the log (page 1 is latest)."""
    try:
        limit = max(1, int(limit))
    except Exception:
        limit = 100
    try:
        page = max(1, int(page))
    except Exception:
        page = 1
    total = count_usage_rows(realm)
    total_pages = max(1, (total + limit - 1) // limit) if total > 0 else 1
    page = min(page, total_pages)
    target_count = page * limit
    matching = []
    chunk = 256 * 1024
    try:
        with open(USAGE_LOG, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and len(matching) < target_count:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                buf = parts[0]
                for raw in reversed(parts[1:]):
                    st = raw.strip()
                    if not st:
                        continue
                    try:
                        item = json.loads(st.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    if realm and not row_matches_realm(item, realm):
                        continue
                    matching.append(item)
                    if len(matching) >= target_count:
                        break
            if len(matching) < target_count and buf.strip():
                try:
                    item = json.loads(buf.strip().decode("utf-8", "replace"))
                    if not realm or row_matches_realm(item, realm):
                        matching.append(item)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("recent_usage read failed: %s" % exc)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_rows = matching[start_idx:end_idx]
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "rows": page_rows,
    }


POOL = None
SCHEDULER = None
ACCOUNTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts")
REALM_STATE_FILE = os.path.join(ACCOUNTS_DIR, "active_realm.json")


def load_persisted_realm():
    global CURRENT_REALM
    if os.path.isfile(REALM_STATE_FILE):
        try:
            with open(REALM_STATE_FILE, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                r = d.get("realm")
                if r in ("intl", "cn"):
                    CURRENT_REALM = r
                    return CURRENT_REALM
        except Exception as e:
            log("could not load active realm: %s" % e)
    return CURRENT_REALM


def save_persisted_realm(realm):
    global CURRENT_REALM
    if realm in ("intl", "cn"):
        CURRENT_REALM = realm
        try:
            state_dir = Path(ACCOUNTS_DIR).resolve()
            state_dir.mkdir(parents=True, exist_ok=True)
            state_file = state_dir / os.path.basename(REALM_STATE_FILE)
            if not state_file.is_relative_to(state_dir):
                raise ValueError("realm state path escapes base directory")
            state_file.write_text(
                json.dumps({"realm": realm, "updated_at": time.time(),
                            "updated_iso": time.strftime("%Y-%m-%d %H:%M:%S")},
                           indent=2),
                encoding="utf-8")
            log("persisted active realm '%s' to disk" % realm)
        except Exception as exc:
            log("failed to persist active realm: %s" % exc)
    return CURRENT_REALM


API_KEY = None
SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT


def account_views(realm=None):
    """List view of every account, including a live readiness flag."""
    if not POOL:
        return []
    return POOL.list_public(realm=realm)


_byacct_cache = {"at": 0.0, "data": None}
_byacct_lock = threading.Lock()


def usage_by_account(ttl=10):
    """Cached wrapper: full aggregation over the whole log is expensive."""
    now = time.time()
    with _byacct_lock:
        if _byacct_cache["data"] is not None and (now - _byacct_cache["at"]) < ttl:
            return _byacct_cache["data"]
    data = _usage_by_account_uncached()
    with _byacct_lock:
        _byacct_cache["at"] = time.time()
        _byacct_cache["data"] = data
    return data


def _usage_by_account_uncached():
    """Aggregate the JSONL log per account id."""
    buckets = {}
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("error"):
                    continue
                key = row.get("account") or "(unattributed)"
                bucket = buckets.setdefault(key, {
                    "account": key, "requests": 0, "prompt_tokens": 0,
                    "completion_tokens": 0, "reasoning_tokens": 0,
                    "cached_tokens": 0, "total_tokens": 0, "models": {},
                })
                bucket["requests"] += 1
                for field in ("prompt_tokens", "completion_tokens",
                              "reasoning_tokens", "cached_tokens",
                              "total_tokens"):
                    bucket[field] += row.get(field) or 0
                model = row.get("model") or "?"
                bucket["models"][model] = bucket["models"].get(model, 0) + 1
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage_by_account failed: %s" % exc)
    out = sorted(buckets.values(), key=lambda b: -b["total_tokens"])
    for item in out:
        item["models"] = sorted(item["models"].items(), key=lambda kv: -kv[1])[:5]
    return out


def compute_usage_analytics():
    """Detailed analytics for Token, Cache, and Reasoning metrics page."""
    now = time.localtime()
    today_ts = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, -1))

    def new_stat():
        return {
            "requests": 0, "errors": 0,
            "prompt_tokens": 0, "completion_tokens": 0,
            "reasoning_tokens": 0, "cached_tokens": 0, "total_tokens": 0,
            "ttft_sum": 0.0, "ttft_n": 0,
            "speed_sum": 0.0, "speed_n": 0,
            "elapsed_sum": 0.0, "elapsed_n": 0,
        }

    all_summary = new_stat()
    today_summary = new_stat()
    acct_map = {}
    model_map = {}
    if os.path.exists(USAGE_LOG):
        try:
            with open(USAGE_LOG, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    is_err = bool(r.get("error"))
                    at = r.get("at", 0)
                    is_today = (at >= today_ts)
                    acct_uid = r.get("account") or "(unattributed)"
                    m_id = r.get("model") or "(unknown)"

                    def feed(stat_obj, is_error):
                        if is_error:
                            stat_obj["errors"] += 1
                        else:
                            stat_obj["requests"] += 1
                            stat_obj["prompt_tokens"] += (r.get("prompt_tokens") or 0)
                            stat_obj["completion_tokens"] += (r.get("completion_tokens") or 0)
                            stat_obj["reasoning_tokens"] += (r.get("reasoning_tokens") or 0)
                            stat_obj["cached_tokens"] += (r.get("cached_tokens") or 0)
                            stat_obj["total_tokens"] += (r.get("total_tokens") or 0)
                            if r.get("ttft_ms"):
                                stat_obj["ttft_sum"] += r["ttft_ms"]
                                stat_obj["ttft_n"] += 1
                            if r.get("tokens_per_sec"):
                                stat_obj["speed_sum"] += r["tokens_per_sec"]
                                stat_obj["speed_n"] += 1
                            if r.get("elapsed_ms"):
                                stat_obj["elapsed_sum"] += r["elapsed_ms"]
                                stat_obj["elapsed_n"] += 1

                    feed(all_summary, is_err)
                    if is_today:
                        feed(today_summary, is_err)
                    if acct_uid not in acct_map:
                        acct_map[acct_uid] = {
                            "uid": acct_uid,
                            "nickname": acct_uid,
                            "realm": r.get("realm", ""),
                            "domain": "",
                            "today": new_stat(),
                            "all_time": new_stat(),
                            "today_models": {},
                            "all_models": {},
                        }
                    feed(acct_map[acct_uid]["all_time"], is_err)
                    if is_today:
                        feed(acct_map[acct_uid]["today"], is_err)
                    if not is_err:
                        tm = acct_map[acct_uid]["all_models"].setdefault(
                            m_id, {"requests": 0, "tokens": 0, "reasoning": 0})
                        tm["requests"] += 1
                        tm["tokens"] += (r.get("total_tokens") or 0)
                        tm["reasoning"] += (r.get("reasoning_tokens") or 0)
                        if is_today:
                            tdm = acct_map[acct_uid]["today_models"].setdefault(
                                m_id, {"requests": 0, "tokens": 0, "reasoning": 0})
                            tdm["requests"] += 1
                            tdm["tokens"] += (r.get("total_tokens") or 0)
                            tdm["reasoning"] += (r.get("reasoning_tokens") or 0)
                    if m_id not in model_map:
                        model_map[m_id] = {"model": m_id, "today": new_stat(),
                                           "all_time": new_stat()}
                    feed(model_map[m_id]["all_time"], is_err)
                    if is_today:
                        feed(model_map[m_id]["today"], is_err)
        except Exception as exc:
            log("compute_usage_analytics failed: %s" % exc)
    if POOL:
        for a in POOL.accounts:
            if a.uid in acct_map:
                acct_map[a.uid]["nickname"] = a.nickname
                acct_map[a.uid]["realm"] = a.realm
                acct_map[a.uid]["domain"] = a.domain
                acct_map[a.uid]["credits"] = getattr(a, "credits", None) or {}
            else:
                acct_map[a.uid] = {
                    "uid": a.uid,
                    "nickname": a.nickname,
                    "realm": a.realm,
                    "domain": a.domain,
                    "credits": getattr(a, "credits", None) or {},
                    "today": new_stat(),
                    "all_time": new_stat(),
                    "today_models": {},
                    "all_models": {},
                }

    def finalize(stat_obj):
        p = stat_obj["prompt_tokens"]
        c = stat_obj["cached_tokens"]
        out = stat_obj["completion_tokens"]
        reas = stat_obj["reasoning_tokens"]
        stat_obj["cache_hit_pct"] = round((c / p * 100), 1) if p > 0 else 0.0
        stat_obj["reasoning_ratio"] = round((reas / out * 100), 1) if out > 0 else 0.0
        stat_obj["ttft_ms_avg"] = round(stat_obj["ttft_sum"] / stat_obj["ttft_n"]) \
            if stat_obj["ttft_n"] > 0 else 0
        stat_obj["speed_avg"] = round(stat_obj["speed_sum"] / stat_obj["speed_n"], 1) \
            if stat_obj["speed_n"] > 0 else 0.0
        stat_obj["elapsed_ms_avg"] = round(stat_obj["elapsed_sum"] / stat_obj["elapsed_n"]) \
            if stat_obj["elapsed_n"] > 0 else 0
        return stat_obj

    finalize(all_summary)
    finalize(today_summary)
    for a in acct_map.values():
        finalize(a["today"])
        finalize(a["all_time"])
    for m in model_map.values():
        finalize(m["today"])
        finalize(m["all_time"])
    accts_list = sorted(acct_map.values(),
                        key=lambda a: (-a["today"]["total_tokens"],
                                       -a["all_time"]["total_tokens"]))
    models_list = sorted(model_map.values(),
                         key=lambda m: (-m["today"]["total_tokens"],
                                        -m["all_time"]["total_tokens"]))
    return {
        "today_ts": today_ts,
        "summary": {"today": today_summary, "all_time": all_summary},
        "accounts": accts_list,
        "models": models_list,
    }


def runtime_settings_view():
    """Current panel-visible settings (never returns the password or the key)."""
    key = API_KEY or ""
    if len(key) > 8:
        masked = key[:4] + "*" * 6 + key[-4:]
    else:
        masked = "*" * len(key)
    keys = []
    for entry in configured_keys():
        raw = entry.get("key") or ""
        keys.append({
            "id": entry.get("id") or "",
            "name": entry.get("name") or "",
            "realm": entry.get("realm") or "",
            "enabled": entry.get("enabled", True) is not False,
            "masked": (raw[:4] + "*" * 6 + raw[-4:]) if len(raw) > 8
            else "*" * len(raw),
            "source": entry.get("source") or "panel",
            "created_at": entry.get("created_at") or "",
        })
    return {
        "panel_password_is_default":
            qoder_settings.panel_password_is_default(ACCOUNTS_DIR),
        "api_key_set": bool(key),
        "api_key_set_by_panel": API_KEY_FILE_SET,
        "api_key_masked": masked,
        "auth_required": auth_required(),
        "api_keys": keys,
        "accounts_dir": ACCOUNTS_DIR,
        "usage_dir": USAGE_DIR,
        "settings_file": qoder_settings.settings_path(ACCOUNTS_DIR),
        "version": VERSION,
    }


def current_account():
    """Account used for display purposes (health / usage summaries)."""
    return POOL.representative() if POOL else None


# ---------------------------------------------------------------------------
# 前缀会话亲和（同一对话固定同一账号，命中上游按账号的 prompt 缓存）
# ---------------------------------------------------------------------------
AFFINITY_BY_PREFIX = os.environ.get("QD_AFFINITY_BY_PREFIX", "1").lower() not in (
    "0", "false", "no", "off")
AFFINITY_DEBUG = os.environ.get("QD_AFFINITY_DEBUG", "0").lower() in (
    "1", "true", "yes", "on")


def derive_affinity_key(messages):
    """Derive a stable affinity key from a conversation's stable prefix.

    前两条消息（system + 首轮 user）在整段对话生命周期内不变，因此同一对话
    每一轮都落到同一上游账号 —— 正是 prompt 缓存需要的；不同对话首轮不同，
    依旧分散到各账号，负载均衡不受影响。
    """
    if not AFFINITY_BY_PREFIX:
        return None
    try:
        msgs = messages or []
        if not msgs:
            return None
        head = msgs[:2]
        blob = json.dumps(head, ensure_ascii=False,
                          sort_keys=True).encode("utf-8")
        return "pfx-" + hashlib.sha256(blob).hexdigest()[:16]
    except Exception:
        return None


def prompt_fingerprint(messages):
    """Privacy-safe fingerprint of the outgoing prompt.

    Cache hits need a byte-identical prefix, so these hashes answer "is my
    prefix stable / is my conversation continuous?" without storing any text.
    """
    try:
        def h(obj):
            blob = json.dumps(obj, ensure_ascii=False,
                              sort_keys=True).encode("utf-8")
            return hashlib.sha256(blob).hexdigest()[:12]
        msgs = messages or []
        out = {"msgs_sha": h(msgs), "n_msgs": len(msgs)}
        if msgs:
            out["system_sha"] = h(msgs[0]) if msgs[0].get("role") == "system" else ""
            out["prefix_sha"] = h(msgs[:-1]) if len(msgs) > 1 else ""
        return out
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 结构化事件日志 + 请求上下文（可溯源排查的基础设施）
# ---------------------------------------------------------------------------
# 设计目标：一次请求的**全链路**可在事后重建 —— 谁发的、走哪个号、排了几轮队、
# 每次重试的原因、最终结果。做法：
#   1) RequestContext（threading.local）：一次 HTTP 请求一个 req_id，所有 log()
#      与落盘行自动带上它 —— 并发时能把散落的日志行串成一条链。
#   2) 结构化事件日志 events.jsonl：机器可读，含排队/重试/换号/断线/生命周期。
#   3) 轮转：events.jsonl 与 usage.jsonl 按大小轮转，文本日志同理 —— 排队预算
#      已是 15 分钟量级，无轮转会无界增长。
EVENTS_LOG_NAME = "events.jsonl"
SERVER_LOG_NAME = "server.log"
CREDITS_LOG_NAME = "credits.jsonl"
_EVENTS_LOCK = threading.Lock()

# 单个日志文件上限与保留份数（纯标准库轮转，不引依赖）。
_LOG_ROTATE_BYTES = int(os.environ.get("QD_LOG_ROTATE_MB") or 8) * 1024 * 1024
_LOG_ROTATE_KEEP = int(os.environ.get("QD_LOG_ROTATE_KEEP") or 5)


def _rotate_if_needed(path, max_bytes=None, keep=None):
    """按大小轮转：path -> path.1 -> path.2 ...，超出 keep 份丢弃最旧的。

    必须在调用方持锁时使用（本函数不加锁）。Windows 上 os.replace 可覆盖已存在
    目标，故从最旧往新逐级重命名。
    """
    max_bytes = max_bytes or _LOG_ROTATE_BYTES
    keep = keep or _LOG_ROTATE_KEEP
    try:
        if not os.path.exists(path) or os.path.getsize(path) < max_bytes:
            return
        oldest = "%s.%d" % (path, keep)
        if os.path.exists(oldest):
            os.unlink(oldest)
        for i in range(keep - 1, 0, -1):
            src, dst = "%s.%d" % (path, i), "%s.%d" % (path, i + 1)
            if os.path.exists(src):
                os.replace(src, dst)
        os.replace(path, "%s.1" % path)
    except Exception:
        pass          # 轮转失败绝不能影响主流程


def _rotating_append(path, line, max_bytes=None, keep=None):
    """向 path 追加一行，必要时先轮转。返回 True 表示写入成功。"""
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        _rotate_if_needed(path, max_bytes, keep)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
        return True
    except Exception:
        return False


def _events_path():
    return os.path.join(USAGE_DIR, EVENTS_LOG_NAME)


def _credits_path():
    return os.path.join(USAGE_DIR, CREDITS_LOG_NAME)


# 积分快照的最小间隔（秒）：巡检/面板刷新可能密集触发，去重避免刷屏。
_CREDITS_SNAPSHOT_MIN_GAP = int(os.environ.get("QD_CREDITS_SNAPSHOT_GAP") or 60)
_credits_snap_state = {"at": 0.0}
_credits_snap_lock = threading.Lock()


def record_credits_snapshot(reason="manual", force=False):
    """把每个账号的额度快照追加进 usage/credits.jsonl。

    上游**不逐请求报积分**（usage.credit 恒为 0），也无按天用量接口 ——
    所以「某时段消耗」只能靠快照差值还原。本函数就是那个差值的数据源：
    每个时间点写一行，之后首末相减即得该时段消耗。
    """
    if not POOL:
        return None
    now = time.time()
    with _credits_snap_lock:
        if not force and (now - _credits_snap_state["at"]
                          < _CREDITS_SNAPSHOT_MIN_GAP):
            return None
        _credits_snap_state["at"] = now
    rows = []
    for a in list(POOL.accounts):
        c = getattr(a, "credits", None) or {}
        if not c:
            continue
        rows.append({
            "uid": a.uid,
            "realm": a.realm,
            "plan": a.plan or "",
            "remain": c.get("remain"),
            "used": c.get("used"),
            "size": c.get("size"),
            "exceeded": bool(c.get("exceeded")),
        })
    if not rows:
        return None
    snap = {
        "at": round(now, 3),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "reason": reason,
        "totals": {
            "remain": sum((r["remain"] or 0) for r in rows),
            "used": sum((r["used"] or 0) for r in rows),
            "size": sum((r["size"] or 0) for r in rows),
            "accounts": len(rows),
        },
        "accounts": rows,
    }
    try:
        with _EVENTS_LOCK:
            _rotating_append(_credits_path(),
                             json.dumps(snap, ensure_ascii=False) + "\n")
    except Exception:
        return None
    return snap


def _credit_snapshot_targets():
    """需要采样的账号（有凭证即可；额度接口两个 realm 都支持）。"""
    if not POOL:
        return []
    return [a for a in list(POOL.accounts) if a.access_token]


def _fetch_all_credits():
    """刷新全部账号额度（失败静默）。返回成功刷新的数量。"""
    ok = 0
    for a in _credit_snapshot_targets():
        try:
            a.fetch_credits()
            ok += 1
        except Exception:
            pass
    return ok


# 每日采样时刻（本地时间 "HH:MM"）。默认 08:00 —— 按天统计时，每日定点采样
# 正好给出「这一天」的起点，与次日 08:00 的采样相减即得当日消耗。
# 设为空串可关闭定时采样（仍保留启动补采与面板刷新）。
_CREDITS_SNAPSHOT_AT = (os.environ.get("QD_CREDITS_SNAPSHOT_AT") or "08:00").strip()


def _parse_snapshot_at(spec):
    """解析 "HH:MM" -> (hour, minute)；非法返回 None。"""
    try:
        parts = str(spec).split(":")
        hh, mm = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            return hh, mm
    except Exception:
        pass
    return None


def _today_has_snapshot(now=None):
    """当日是否已有快照（用于启动补采去重，避免重启就多记一条）。"""
    now = time.time() if now is None else now
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    try:
        with io.open(_credits_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                if str(o.get("iso") or "").startswith(day):
                    return True
    except Exception:
        pass
    return False


def _startup_credit_snapshot():
    """启动时补采一次：当日尚无快照才记，作为当日起点。

    重启不该在一天里插进第二条基线（否则「当日首末」被扰动）。
    """
    try:
        time.sleep(5)
        if not _credit_snapshot_targets():
            return
        if _today_has_snapshot():
            return
        _fetch_all_credits()
        record_credits_snapshot(reason="startup", force=True)
    except Exception:
        pass


def _credits_daily_loop():
    """每天到点采一次（独立线程，失败静默、绝不拖垮主流程）。"""
    spec = _parse_snapshot_at(_CREDITS_SNAPSHOT_AT)
    if spec is None:
        return
    hh, mm = spec
    while True:
        try:
            now = time.localtime()
            nxt = time.mktime((now.tm_year, now.tm_mon, now.tm_mday,
                               hh, mm, 0, 0, 0, -1))
            if nxt <= time.time():
                nxt += 86400          # 今天已过 -> 明天同一时刻
            # 分片休眠：便于随进程退出，且时钟跳变后能重新对齐。
            while True:
                remain = nxt - time.time()
                if remain <= 0:
                    break
                time.sleep(min(remain, 300))
            if not _credit_snapshot_targets():
                continue
            _fetch_all_credits()
            record_credits_snapshot(reason="daily", force=True)
        except Exception:
            time.sleep(60)


# 余额守护线程：扫描周期 30s；"活跃"= 有未过期亲和绑定 或 近 10 分钟用过。
_CREDIT_GUARD_SCAN_S = 30
_CREDIT_GUARD_ACTIVE_S = 600


def _credit_guard_active(account, now):
    if not account.enabled or not account.access_token:
        return False
    if now - getattr(account, "last_used_at", 0.0) <= _CREDIT_GUARD_ACTIVE_S:
        return True
    return bool(POOL) and POOL.affinity.has_uid(account.uid)


def _credit_guard_scan(now=None):
    """扫一遍活跃账号，到点即探测（串行、小睡间隔）。

    正常间隔 CREDIT_PROBE_NORMAL_S；remain < LOW_BALANCE_ACCEL 的活跃号缩到
    CREDIT_PROBE_LOW_S。扣减跨过加速线时 probe_due_at 会安排一次提前探测。
    余额回升后无需复活逻辑——pick 的低余额过滤是无状态现算。
    """
    if not POOL:
        return
    now = time.time() if now is None else now
    for a in list(POOL.accounts):
        if not _credit_guard_active(a, now):
            continue
        remain = a.credit_remain()
        interval = qoder_accounts.CREDIT_PROBE_LOW_S \
            if remain is not None and remain < qoder_accounts.LOW_BALANCE_ACCEL \
            else qoder_accounts.CREDIT_PROBE_NORMAL_S
        last = (a.credits or {}).get("updated_at") or 0.0
        due = last + interval
        if a.probe_due_at:
            due = min(due, a.probe_due_at)
        if now < due:
            continue
        a.probe_due_at = 0.0
        try:
            a.fetch_credits()
        except Exception:
            pass
        time.sleep(0.5)


def _credit_guard_loop():
    """余额守护（独立线程，失败静默、绝不拖垮主流程）。"""
    time.sleep(15)
    while True:
        try:
            _credit_guard_scan()
        except Exception:
            pass
        time.sleep(_CREDIT_GUARD_SCAN_S)


def _local_day(ts):
    """时间戳 -> 本地自然日 "YYYY-MM-DD"。"""
    try:
        return time.strftime("%Y-%m-%d", time.localtime(float(ts)))
    except Exception:
        return ""


def credits_daily(days=14, realm=None):
    """按**自然日**统计积分消耗（相邻采样点差值）。

    每天定点（默认 08:00）采一条快照，故：
        日期 D 的消耗 = D 当天采样点的 used − 前一天采样点的 used
    即「昨日 08:00 → 今日 08:00」这一天的用量。**不是**取当天首末 ——
    一天只有一条快照，首末会永远缺一端。

    首个采样点没有前驱，无法算消耗，标记 pending。返回按日期升序、最新在最后。
    """
    try:
        days = max(1, min(365, int(days)))
    except (TypeError, ValueError):
        days = 14
    path = _credits_path()
    empty = {"days": [], "window_days": days, "snapshots": 0,
             "first": None, "last": None}
    if not os.path.exists(path):
        return empty
    snaps = []
    try:
        with io.open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                snaps.append(o)
    except Exception:
        return empty
    snaps.sort(key=lambda o: o.get("at") or 0)

    def _idx(snap):
        return {r["uid"]: r for r in (snap.get("accounts") or [])
                if (realm is None or r.get("realm") == realm)}

    # 每天取一个**代表采样点**：优先用定点采样（reason=daily），因为它才是
    # 「08:00 那一刻」的值，与相邻日的同刻值可比。面板刷新/启动补采只是副产品，
    # 若拿它们当代表会把锚点挪走（例如 20:00 刷新会让当日值偏晚、次日差值失真）。
    # 同一天有多条 daily 时取最后一条（重复触发无妨，值相同）。
    by_day = {}
    for o in snaps:
        d = _local_day(o.get("at"))
        if not d:
            continue
        cur = by_day.get(d)
        if cur is None:
            by_day[d] = o
            continue
        # daily 优先；同为 daily 或同为非 daily 时取更晚的一条。
        # （snaps 已按时间升序，故「更晚」即直接覆盖。）
        if o.get("reason") == "daily" or cur.get("reason") != "daily":
            by_day[d] = o
    days_sorted = sorted(by_day)

    out = []
    for i, d in enumerate(days_sorted):
        cur = by_day[d]
        prev = by_day[days_sorted[i - 1]] if i > 0 else None
        if prev is None:
            out.append({"date": d, "samples": 1, "pending": True,
                        "at": cur.get("iso"), "used_delta": None,
                        "remain_delta": None, "per_account": [],
                        "note": "首个采样点，无前驱可比"})
            continue
        ci, pi = _idx(cur), _idx(prev)
        per = []
        for uid in sorted(set(ci) | set(pi)):
            c, p = ci.get(uid) or {}, pi.get(uid) or {}
            per.append({
                "uid": uid,
                "plan": (c.get("plan") or p.get("plan") or ""),
                "used_delta": (c.get("used") or 0) - (p.get("used") or 0),
                "remain_delta": (p.get("remain") or 0) - (c.get("remain") or 0),
                "remain_now": c.get("remain"),
            })
        per.sort(key=lambda r: -r["used_delta"])
        out.append({
            "date": d,
            "samples": 1,
            "pending": False,
            "at": cur.get("iso"),
            "since": prev.get("iso"),
            "used_delta": sum(r["used_delta"] for r in per),
            "remain_delta": sum(r["remain_delta"] for r in per),
            "per_account": per,
        })
    return {"days": out[-days:], "window_days": days,
            "snapshots": len(snaps),
            "first": (snaps[0].get("iso") if snaps else None),
            "last": (snaps[-1].get("iso") if snaps else None)}

class RequestContext(object):
    """一次 HTTP 请求的上下文（threading.local 持有，随线程生灭）。

    ThreadingHTTPServer 每请求一个线程，故 thread-local 天然等价于请求作用域：
    该线程内任何位置的 log()/record_* 都能自动带上 req_id 与累计遥测。
    """

    __slots__ = ("req_id", "started", "tag", "path", "model", "account",
                 "queue_waits", "queue_ms", "queue_max_hint", "attempts",
                 "switches", "retry_reasons", "client_gone", "finished")

    def __init__(self, tag="chat", path="", model=""):
        self.req_id = uuid.uuid4().hex[:12]
        self.started = time.time()
        self.tag = tag
        self.path = path
        self.model = model
        self.account = ""
        self.queue_waits = 0          # 排队等待轮数
        self.queue_ms = 0             # 排队累计等待毫秒
        self.queue_max_hint = 0       # 上游给出的最大 retryAfterSeconds
        self.attempts = 0             # 上游尝试次数（含重开）
        self.switches = 0             # 换号次数
        self.retry_reasons = []       # 去重后的重试原因（queue/418/transport…）
        self.client_gone = False      # 等待期间探测到客户端断开
        self.finished = False

    def note_queue(self, wait_s):
        self.queue_waits += 1
        self.queue_ms += int(max(0.0, float(wait_s)) * 1000)
        try:
            self.queue_max_hint = max(self.queue_max_hint, int(wait_s))
        except Exception:
            pass

    def note_retry(self, reason):
        if reason and reason not in self.retry_reasons:
            self.retry_reasons.append(reason)

    def to_fields(self):
        """展开为落盘字段（只保留有值的，避免污染每一行）。"""
        out = {"req_id": self.req_id,
               "elapsed_ms": int((time.time() - self.started) * 1000)}
        if self.queue_waits:
            out["queue_waits"] = self.queue_waits
            out["queue_ms"] = self.queue_ms
            out["queue_max_hint_s"] = self.queue_max_hint
        if self.attempts:
            out["attempts"] = self.attempts
        if self.switches:
            out["account_switches"] = self.switches
        if self.retry_reasons:
            out["retry_reasons"] = ",".join(self.retry_reasons)
        if self.client_gone:
            out["client_gone"] = True
        return out


_CTX = threading.local()


def current_ctx():
    return getattr(_CTX, "ctx", None)


def current_req_id():
    c = getattr(_CTX, "ctx", None)
    return c.req_id if c else ""


def _write_event(kind, tag=None, **fields):
    """写一行结构化事件（events.jsonl）。失败静默 —— 日志绝不拖垮主流程。"""
    try:
        ctx = getattr(_CTX, "ctx", None)
        row = {"at": round(time.time(), 3),
               "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "kind": kind,
               "req": ctx.req_id if ctx else "",
               "tag": tag or (ctx.tag if ctx else "system")}
        row.update(fields)
        line = json.dumps(row, ensure_ascii=False, default=str) + "\n"
        with _EVENTS_LOCK:
            _rotating_append(_events_path(), line)
    except Exception:
        pass


def begin_request(tag="chat", path="", model=""):
    """开启一次请求的上下文。返回 RequestContext（同时写入 thread-local）。"""
    ctx = RequestContext(tag=tag, path=path, model=model)
    _CTX.ctx = ctx
    _write_event("request.start", path=path, model=model)
    return ctx


def end_request(status=None, note=None):
    """结束请求上下文：写一条 request.end 事件（含全部遥测）。"""
    ctx = getattr(_CTX, "ctx", None)
    if ctx is None or ctx.finished:
        return
    ctx.finished = True
    _write_event("request.end", status=status, note=note, **ctx.to_fields())
    _CTX.ctx = None


def note_queue_wait(wait_s, hint=None):
    """记录一次排队等待（供 open_upstream / 流式 handler 调用）。"""
    ctx = getattr(_CTX, "ctx", None)
    if ctx is None:
        return
    ctx.note_queue(hint if hint is not None else wait_s)
    _write_event("queue.wait", wait_s=round(float(wait_s), 2),
                 hint_s=hint, waits=ctx.queue_waits, queue_ms=ctx.queue_ms)


def note_retry(reason, **extra):
    ctx = getattr(_CTX, "ctx", None)
    if ctx is not None:
        ctx.note_retry(reason)
        if reason == "switch":
            ctx.switches += 1
    _write_event("retry", reason=reason, **extra)


def note_attempt():
    ctx = getattr(_CTX, "ctx", None)
    if ctx is not None:
        ctx.attempts += 1


def note_client_gone(where=""):
    ctx = getattr(_CTX, "ctx", None)
    if ctx is not None:
        ctx.client_gone = True
    _write_event("client.gone", where=where)


LOG_BUFFER = deque(maxlen=2000)
_LOG_LOCK = threading.Lock()
_LOG_COUNTER = 0


def add_log_entry(msg, level=None, tag=None):
    global _LOG_COUNTER
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    t_short = time.strftime("%H:%M:%S")
    msg_str = str(msg).rstrip()
    if not level:
        lower = msg_str.lower()
        if any(k in lower for k in ("error", "exception", "failed", "traceback",
                                    "errno", "fatal", "token_expire", "12153")):
            level = "ERROR"
        elif any(k in lower for k in ("warn", "warning", "retry", "timeout")):
            level = "WARN"
        else:
            level = "INFO"
    if not tag:
        lower = msg_str.lower()
        if "chat:" in lower or "chat done" in lower or "/v1/chat" in lower \
                or "/chat/completions" in lower or "responses" in lower:
            tag = "chat"
        elif "scheduler" in lower or "调度器" in lower:
            tag = "scheduler"
        elif "task" in lower or "任务" in lower or "签到" in lower \
                or "checkin" in lower or "福利" in lower:
            tag = "tasks"
        elif "account" in lower or "账号" in lower or "pool" in lower \
                or "imported" in lower:
            tag = "accounts"
        elif "model" in lower or "catalog" in lower or "模型" in lower:
            tag = "catalog"
        elif "auth" in lower or "token" in lower or "oauth" in lower:
            tag = "auth"
        elif "settings" in lower or "设置" in lower:
            tag = "settings"
        else:
            tag = "system"
    with _LOG_LOCK:
        _LOG_COUNTER += 1
        entry = {
            "id": _LOG_COUNTER,
            "ts": ts,
            "time": t_short,
            "level": level,
            "tag": tag,
            "req": current_req_id(),
            "msg": msg_str,
        }
        LOG_BUFFER.append(entry)
    return entry


def log(msg, level=None, tag=None):
    """写日志。若当前线程处于请求上下文，自动加 [req_id] 前缀 —— 并发时
    可把散落的日志行按 req_id 串成一次请求的完整链路。

    三处落地：stderr（前台可见）、server.log（**按大小轮转**，无需外部
    重定向；VBS/服务方式启动时 stderr 可能被丢弃，文本日志不能只靠它）、
    内存环形缓冲（看板 /logs）。
    """
    rid = current_req_id()
    prefix = "[%s] " % rid if rid else ""
    line = "[qd-proxy] %s %s%s" % (time.strftime("%H:%M:%S"), prefix, msg)
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass          # 无控制台/已被重定向时 stderr 可能不可写
    try:
        _rotating_append(os.path.join(USAGE_DIR, SERVER_LOG_NAME),
                         line + "\n")
    except Exception:
        pass
    add_log_entry((prefix + str(msg)) if rid else msg, level=level, tag=tag)


def get_logs(limit=200, level="", tag="", search="", since_id=0, req=""):
    with _LOG_LOCK:
        items = list(LOG_BUFFER)
    if since_id > 0:
        items = [x for x in items if x["id"] > since_id]
    if req:
        # 按 req_id 过滤：把一次请求的散落日志行串起来（可溯源排查的核心）。
        items = [x for x in items if x.get("req") == req]
    if level:
        items = [x for x in items if x["level"] == level.upper()]
    if tag:
        items = [x for x in items if x["tag"].lower() == tag.lower()]
    if search:
        s = search.lower()
        items = [x for x in items if s in x["msg"].lower() or s in x["tag"].lower()]
    total = len(items)
    if limit and limit > 0 and since_id == 0:
        items = items[-limit:]
    max_id = items[-1]["id"] if items else since_id
    return {"total": total, "logs": items, "max_id": max_id}


def clear_logs():
    with _LOG_LOCK:
        LOG_BUFFER.clear()


# ---------------------------------------------------------------------------
# 模型目录（动态 COSY model/list + 静态兜底）
# ---------------------------------------------------------------------------
NON_CHAT_MODELS = {"lite"}
NON_CHAT_PREFIXES = ("codewise-", "completion-")
NON_CHAT_SUFFIXES = ("-image-alpha", "-image-alpha-edit", "-taco-completion")


def is_chat_model(mid):
    if not mid:
        return False
    if mid in NON_CHAT_MODELS:
        return False
    if mid.startswith(NON_CHAT_PREFIXES):
        return False
    if mid.endswith(NON_CHAT_SUFFIXES):
        return False
    return True


CN_UI_ORDER = [m["key"] for m in qoder_catalog.STATIC_CN_MODELS]
INTL_UI_ORDER = [m["key"] for m in qoder_catalog.STATIC_INTL_MODELS]


def merge_catalog(primary, realm=None):
    """静态目录打底（补元数据），按官方 UI 顺序输出。

    **清单以 primary（动态接口或本机官方目录）为准**：桌面版此刻显示什么
    这里就显示什么（如动态返回 15 条就不额外塞静态独有的 2 条）；
    primary 为空时回退静态快照全量。enable/strategies 等状态不做任何裁剪。
    """
    r = realm or CURRENT_REALM
    merged = {}
    source_static = getattr(qoder_catalog, "STATIC_CN_MODELS" if r == "cn"
                            else "STATIC_INTL_MODELS", qoder_catalog.STATIC_MODELS)
    for item in source_static:
        mid = item.get("key") or item.get("id")
        if mid and is_chat_model(mid):
            merged[mid] = dict(item)
    primary = list(primary or [])
    primary_keys = None
    for mid, meta in primary:
        if not is_chat_model(mid):
            continue
        if meta:
            base = merged.get(mid) or {}
            # None 值不覆盖：动态接口对部分条目返回 null（如 context_config/
            # thinking_config/description），静默 null 会把静态快照里的真实
            # 值抹掉——只用有值字段做增量覆盖。
            base.update({k: v for k, v in meta.items() if v is not None})
            merged[mid] = base
        elif mid not in merged:
            merged[mid] = {}
    if primary:
        primary_keys = {mid for mid, _ in primary if is_chat_model(mid)}
    order = CN_UI_ORDER if r == "cn" else INTL_UI_ORDER
    out = []
    seen = set()

    def wanted(mid):
        if not is_chat_model(mid):
            return False
        if primary_keys is not None and mid not in primary_keys:
            return False      # 静态独有、官方此刻未列出的条目不外塞
        return True

    for mid in order:
        if mid in merged and wanted(mid):
            out.append((mid, merged[mid]))
            seen.add(mid)
    for mid, meta in merged.items():
        if mid not in seen and wanted(mid):
            out.append((mid, meta))
    return out


def read_local_models(realm=None):
    """读取本机官方客户端的模型目录缓存（QMC 解密），无网络也能跟官方对齐。

    路径：~/.qoder/.models/<uid>/catalog-v6（intl）/ ~/.qoder-cn/...（cn）
    返回 [(key, meta)]；任何失败返回 []（回退静态快照）。
    """
    r = realm or CURRENT_REALM
    home = os.path.join(os.path.expanduser("~"),
                        get_realm_config(r)["home_dir"], ".models")
    try:
        default_path = os.path.join(home, "default")
        uid = ""
        with open(default_path, encoding="utf-8") as fh:
            uid = str(json.load(fh).get("uid") or "")
        subdirs = [uid] if uid and os.path.isdir(os.path.join(home, uid)) else \
            [d for d in os.listdir(home) if os.path.isdir(os.path.join(home, d))]
        for sub in subdirs:
            cat = os.path.join(home, sub, "catalog-v6")
            if not os.path.isfile(cat):
                continue
            with open(cat, "rb") as fh:
                blob = fh.read().decode("ascii", "replace")
            from qoder_sign import qmc_decrypt
            plain = json.loads(qmc_decrypt(blob, sub).decode("utf-8"))
            chat = plain.get("chat") or []
            out = []
            for m in chat:
                if not isinstance(m, dict) or not m.get("key"):
                    continue
                # 官方本地目录条目全字段原样
                row = dict(m)
                row["id"] = m["key"]
                row.setdefault("name", m.get("display_name") or m["key"])
                row.setdefault("display_name", m.get("display_name") or m["key"])
                out.append((m["key"], row))
            if out:
                log("model catalog read from local client cache: %d models (%s)"
                    % (len(out), r))
                return out
    except Exception as exc:
        log("local model catalog read skipped: %s" % exc)
    return []


def fetch_models(realm=None):
    r = realm or CURRENT_REALM
    with _lock:
        c = _models_cache.get(r) or {"at": 0.0, "data": None}
        if c["data"] and time.time() - c["at"] < 300:
            return c["data"]
    # 1) 动态接口（需要账号） 2) 本机官方目录缓存 3) 内嵌静态快照
    live = read_dynamic_models(realm=r)
    if not live:
        live = read_local_models(realm=r)
    entries = merge_catalog(live, realm=r)
    with _lock:
        _models_cache[r] = {"at": time.time(), "data": entries}
    return entries


def read_dynamic_models(realm=None):
    """COSY 签名拉取 /algo/api/v2/model/list（chat scene）。失败返回 []。

    注意：签名的 body 是 qoder_encode("{}")，请求必须**带同款 body**发出
    （服务端校验签名与 body 一致，裸 GET 会 403）。
    """
    r = realm or CURRENT_REALM
    account = POOL.pick(realm=r) if POOL else None
    if account is None:
        return []
    cfg = get_realm_config(r)
    raw_url = cfg["gateway"] + MODELS_PATH
    # 签名以 qoder_encode("{}") 作为 body 参与 MD5；请求同样携带该 body。
    sign_body = qoder_encode(b"{}")
    try:
        sess = SESSIONS.get(account)
        headers = sess.headers(sign_body, raw_url, model_key="", sse=False,
                               accept="application/json")
        headers["User-Agent"] = CLIENT_UA
        url = validate_public_http_url(raw_url)
        req = urllib.request.Request(url, data=sign_body.encode("utf-8"),
                                     method="GET", headers=headers)
        with qoder_accounts.open_url(
                req, timeout=15, **account.egress_kwargs()) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        log("model discovery failed: %s" % exc)
        return []
    chat = payload.get("chat") or []
    out = []
    for m in chat:
        if not isinstance(m, dict):
            continue
        mid = m.get("key")
        if not mid:
            continue
        # 官方原始条目**全字段原样**透传（enable/strategies/is_editable/
        # minimal_version/... 一律不裁剪），仅补 id/name 兼容键。
        row = dict(m)
        row["id"] = mid
        row.setdefault("name", m.get("display_name") or mid)
        row.setdefault("display_name", m.get("display_name") or mid)
        out.append((mid, row))
    if out:
        log("model discovery ok: %d chat models from %s" % (len(out), r))
    return out


def _parse_hhmm(value):
    """'22:00' -> 1320 分钟数；解析失败返回 None。"""
    try:
        parts = str(value).split(":")
        return int(parts[0]) * 60 + int(parts[1])
    except Exception:
        return None


def off_peak_active_now(window_start, window_end, tz=None, now=None):
    """判断当前时刻是否处于官方低谷（Off-Peak）时段。

    官方 promotion.window 为 22:00-08:00（跨午夜），文案标注 UTC+8；
    官方时区 Asia/Shanghai / Asia/Singapore 均为 UTC+8，因此按固定 +8
    计算（无 tzdata 依赖），未知时区也按官方标注的 UTC+8 兜底。
    返回 True（窗口内）/ False（窗口外）/ None（无有效窗口）。
    """
    s = _parse_hhmm(window_start)
    e = _parse_hhmm(window_end)
    if s is None or e is None:
        return None
    if now is None:
        now = time.time()
    import datetime
    offset_hours = 8
    if isinstance(tz, str):
        if tz.upper().startswith("UTC"):
            m = re.search(r"UTC([+-]\d{1,2})", tz.upper())
            if m:
                offset_hours = int(m.group(1))
        # Asia/Shanghai / Asia/Singapore -> +8（默认即 8）
    utc = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    local = utc + datetime.timedelta(hours=offset_hours)
    cur = local.hour * 60 + local.minute
    if s == e:
        return True
    if s < e:
        return s <= cur < e
    return cur >= s or cur < e      # 跨午夜窗口（22:00-08:00）


def model_entry(mid, meta):
    """Build a rich /v1/models entry.

    - `id` = **官方模型名 display_name**（如 `Qwen3.8-Max`）——客户端唯一需要
      填的值，与官方桌面版选择器显示一致；`upstream_key` 保留缩写 key，
      `aliases` 列出所有可接受形式（key / 「key (Name)」/ 人类别名）。
    - `description` = 官方桌面版介绍文案（dynamic-text zh.detail）。
    - `name_local` = 官方本地化名（zh.label 与 display_name 不同时，如
      Ultimate -> 极致、旧文案 Kimi-K2.7-Code）。
    - 上下文窗口来自官方 context_config；思考档位来自 thinking_config。
    - 峰谷价来自 promotion（peak -> valley + 时段窗口与官方错峰文案）。
    - `enabled=false` 时给出 `disabled_reason`（官方原文：需要升级或购买
      千问官方套餐开放）与上游 `disabled_message_key`。
    - **最大输出**：官方（catalog / 动态接口原始响应）均无此字段，因此
      仅当来源真实携带时才输出，绝不编造。
    """
    meta = meta or {}
    display_name = meta.get("name") or meta.get("display_name") or mid
    item = {
        "id": display_name,
        "object": "model",
        "created": int(time.time()),
        "owned_by": "qoder",
        "upstream_key": mid,
        "enabled": meta.get("enable", True) is not False,
    }
    item["name"] = display_name
    # 描述：来源自带动态/本地 description，否则取官方桌面版文案
    desc = meta.get("description") or ""
    if not desc:
        try:
            desc = qoder_catalog.official_description(mid)
        except Exception:
            desc = ""
    if desc:
        item["description"] = desc
    # 官方本地化显示名（与 display_name 不同时透出）
    try:
        local = qoder_catalog.official_local_name(mid)
    except Exception:
        local = ""
    if local:
        item["name_local"] = local
    # 所有可接受的填写形式
    aliases = [mid, "%s (%s)" % (mid, display_name)] if display_name != mid else [mid]
    for ak, av in qoder_catalog.MODEL_ALIASES.items():
        if av == mid and ak not in aliases:
            aliases.append(ak)
    item["aliases"] = aliases
    # 禁用态：官方原因文案（未开通千问套餐时官方桌面版所示）
    if not item["enabled"]:
        item["disabled_reason"] = getattr(
            qoder_catalog, "OFFICIAL_DISABLED_REASON",
            "需要升级或购买千问官方套餐开放")
        strategies = meta.get("strategies")
        if isinstance(strategies, list):
            for st in strategies:
                if isinstance(st, dict) and st.get("disabled_message_key"):
                    item["disabled_message_key"] = st["disabled_message_key"]
                    break
            item["strategies"] = strategies
    vision = bool(meta.get("is_vl") or meta.get("supportsImages")) \
        and not meta.get("disabledMultimodal")
    tools = bool(meta.get("supportsToolCall", True))
    thinking_cfg = meta.get("thinking_config") if isinstance(
        meta.get("thinking_config"), dict) else {}
    thinks = bool(meta.get("is_reasoning") or meta.get("supportsReasoning")
                  or isinstance(thinking_cfg.get("enabled"), dict))
    inputs = ["text"] + (["image"] if vision else [])
    item["capabilities"] = {"vision": vision, "tool_calls": tools,
                            "reasoning": thinks}
    item["supports_vision"] = vision
    item["supports_images"] = vision
    item["supports_tool_calls"] = tools
    item["supports_reasoning"] = thinks
    item["vision"] = vision
    item["multimodal"] = vision
    item["abilities"] = {"vision": vision, "functionCall": tools,
                         "function_call": tools, "reasoning": thinks}
    item["input_modalities"] = inputs
    item["output_modalities"] = ["text"]
    item["modalities"] = {"input": inputs, "output": ["text"]}
    item["architecture"] = {
        "input_modalities": inputs,
        "output_modalities": ["text"],
        "modality": "+".join(inputs) + "->text",
    }
    # ---- limits：官方 context_config 多窗口 + 默认输入上限 ----
    # 口径（对齐官方 App 的「上下文窗口」滑块）：
    #   context_length    = **最大可选窗口**（滑块右端，即「能调到多大」）
    #   context_window_default = 官方默认档位（is_default，未指定时用这个）
    #   max_input_tokens  = 与默认档位一致（它是「默认声明值」，**不是上限**）
    max_in = meta.get("maxInputTokens") or meta.get("max_input_tokens")
    ctx_cfg = meta.get("context_config") if isinstance(
        meta.get("context_config"), dict) else {}
    windows, labels, default_tok = [], [], None
    for label, conf in ctx_cfg.items():
        if not isinstance(conf, dict):
            continue
        try:
            tok = int(conf.get("token_count") or 0)
        except (TypeError, ValueError):
            tok = 0
        if tok:
            labels.append(str(label))
            windows.append(tok)
            if conf.get("is_default"):
                default_tok = tok
    # 标签随窗口一起排序，避免 "1M/200K/400K" 与数值不同序造成误读。
    if windows:
        _pairs = sorted(zip(windows, labels))
        windows = [p[0] for p in _pairs]
        labels = [p[1] for p in _pairs]
    _largest = windows[-1] if windows else None
    if _largest:
        # 客户端据此判断「能调到多大」——必须给最大档位，否则会像 180K 那样
        # 被误当成上限。
        item["context_length"] = _largest
        item["max_input_tokens"] = default_tok or _largest
    elif max_in:
        item["context_length"] = max_in
        item["max_input_tokens"] = max_in
    if windows:
        item["context_windows"] = windows
        item["context_window_labels"] = labels
        item["context_window_default"] = default_tok or windows[-1]
    # 最大输出：官方（catalog/动态接口）均无此字段——不输出、不展示（用户
    # 已确认不再测量该值）。
    max_out = meta.get("maxOutputTokens") or meta.get("max_output_tokens")
    if max_out:
        item["max_output_tokens"] = max_out
        item["max_completion_tokens"] = max_out
    # ---- 思考档位：官方 thinking_config ----
    enabled_think = thinking_cfg.get("enabled")
    if isinstance(enabled_think, dict):
        order = ["low", "medium", "high", "xhigh", "max"]
        eff_map = enabled_think.get("efforts") or {}
        efforts = [e for e in order if e in eff_map]
        if efforts:
            item["reasoning_efforts"] = efforts
        for e in efforts:
            if isinstance(eff_map.get(e), dict) and eff_map[e].get("is_default"):
                item["reasoning_default_effort"] = e
                break
    if "disabled" in thinking_cfg:
        item["reasoning_can_disable"] = True
    # ---- 兼容旧 catalog 形态 ----
    effort_fixed = (meta.get("reasoning") or {}).get("effort")
    if effort_fixed:
        item["reasoning_fixed_effort"] = effort_fixed
    efforts_old = (meta.get("reasoning") or {}).get("supportedEfforts")
    if efforts_old and "reasoning_efforts" not in item:
        item["reasoning_efforts"] = efforts_old
    if (meta.get("reasoning") or {}).get("defaultEffort") \
            and "reasoning_default_effort" not in item:
        item["reasoning_default_effort"] = meta["reasoning"]["defaultEffort"]
    # ---- 计费：峰谷价（官方 promotion） ----
    price_now = meta.get("price_factor")
    promo = meta.get("promotion") if isinstance(meta.get("promotion"), dict) else {}
    if price_now is not None:
        item["price_factor"] = price_now
        item["price_factor_valley"] = price_now
    peak = None
    if promo.get("before_promotion_price_factor") is not None:
        peak = promo.get("before_promotion_price_factor")
    elif meta.get("original_price_factor") is not None:
        peak = meta.get("original_price_factor")
    if peak is not None:
        item["price_factor_peak"] = peak
    if promo.get("active"):
        badge = promo.get("badge") or {}
        desc_p = promo.get("description") or {}
        link = promo.get("link_url") or {}
        item["off_peak"] = {
            "active": True,
            "window_start": promo.get("window_start"),
            "window_end": promo.get("window_end"),
            "timezone": promo.get("timezone"),
            "discount_factor": promo.get("discount_factor"),
            "badge": badge.get("zh") or badge.get("en") or "",
            "badge_en": badge.get("en") or "",
            "description": desc_p.get("zh") or desc_p.get("en") or "",
            "description_en": desc_p.get("en") or "",
            "link": link.get("zh") or link.get("en") or "",
        }
        item["off_peak_window"] = "%s-%s" % (promo.get("window_start"),
                                             promo.get("window_end"))
        item["promotion"] = promo
        # 当前是否正处于低谷时段（供看板做视觉高亮；前端亦会按本地时间复算）
        active = off_peak_active_now(promo.get("window_start"),
                                     promo.get("window_end"),
                                     tz=promo.get("timezone"))
        item["off_peak_active_now"] = bool(active)
    if meta.get("original_price_factor") is not None:
        item["original_price_factor"] = meta.get("original_price_factor")
    if meta.get("is_free") is not None:
        item["is_free"] = bool(meta.get("is_free"))
    if meta.get("is_new"):
        item["is_new"] = True
    if meta.get("icon"):
        item["icon"] = meta.get("icon")
    if meta.get("credits"):
        item["credits"] = meta["credits"]
    return item


# ---------------------------------------------------------------------------
# 请求清洗与归一化
# ---------------------------------------------------------------------------
def strip_data_prefix(line):
    line = line.strip()
    if not line or line.startswith(":"):
        return ""
    while line.startswith("data:"):
        line = line[5:].strip()
    if not line or line.startswith(":"):
        return ""
    return line


# 合法的 OpenAI finish_reason 取值。上游会返回规范外的值 —— 实测见到
# "refusal"（模型主动拒绝；其 system prompt 含安全条款）。规范外的值若原样
# 透传，客户端无法归类（实测表现为异常状态提示），故映射到语义最近的标准值，
# 同时写事件日志保留「原始值 -> 归一值」以便追溯。
_VALID_FINISH = ("stop", "length", "tool_calls", "content_filter",
                 "function_call")
_FINISH_ALIASES = {
    "refusal": "content_filter",
    "refused": "content_filter",
    "content_filtered": "content_filter",
    "sensitive": "content_filter",
    "safety": "content_filter",
    "error": "stop",
    # 上游若用这些词表达「达到长度上限」，必须归一到 length —— 否则截断防御
    # 的语义判断与客户端的「被截断」识别都会失准（审查 S3）。
    "max_tokens": "length",
    "max_output_tokens": "length",
    "length_limit": "length",
    "token_limit": "length",
}


def normalize_finish_reason(finish, model=None, refusal=None):
    """把上游 finish_reason 归一到 OpenAI 规范值（并留痕）。

    规范外值不原样透传：客户端拿到未知值无法归类。归一后写一条
    finish_reason.mapped 事件，保证原始值可追溯。
    """
    if not finish:
        return finish
    if finish in _VALID_FINISH:
        return finish
    # 纯函数：**不**在此写事件。事件由 iter_inner_sse 在拿到 model 与
    # 完整 refusal 上下文时统一写（此处调用点无上下文，写了会丢信息）。
    return _FINISH_ALIASES.get(str(finish).strip().lower(), "stop")


def clean_chunk(raw):
    """Drop the empty noise fields the gateway pads deltas with."""
    try:
        obj = json.loads(raw)
    except Exception:
        return raw
    changed = False
    _chs = obj.get("choices")
    if not isinstance(_chs, list):
        return raw          # 畸形帧（choices 非 list）原样透传，不因假设抛异常
    for choice in _chs:
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            continue
        fc = delta.get("function_call")
        if fc is not None:
            fc_empty = (not fc) if not isinstance(fc, dict) else (not fc.get("name"))
            if fc_empty:
                delta.pop("function_call", None)
                changed = True
        if isinstance(delta.get("tool_calls"), list) and not delta["tool_calls"]:
            delta.pop("tool_calls")
            changed = True
        for key in NOISE_KEYS:
            if key in delta and not delta.get(key):
                delta.pop(key)
                changed = True
        # 规范外的 finish_reason（如上游的 "refusal"）归一化后再发给
        # 客户端 —— 原样透传会让客户端无法归类。
        _fr = choice.get("finish_reason")
        if _fr and _fr not in _VALID_FINISH:
            choice["finish_reason"] = normalize_finish_reason(
                _fr, refusal=delta.get("refusal"))
            changed = True
        if not delta and not choice.get("finish_reason"):
            return ""
    return json.dumps(obj, ensure_ascii=False) if changed else raw


def _strip_empty_fc(obj):
    """递归剔除空 function_call 占位（Responses/chat 通用）。"""
    changed = False
    if isinstance(obj, dict):
        fc = obj.get("function_call")
        if isinstance(fc, dict) and not fc.get("name"):
            obj.pop("function_call", None)
            changed = True
        tc = obj.get("tool_calls")
        if isinstance(tc, list) and not tc:
            obj.pop("tool_calls")
            changed = True
        for v in list(obj.values()):
            if _strip_empty_fc(v):
                changed = True
    elif isinstance(obj, list):
        for v in obj:
            if _strip_empty_fc(v):
                changed = True
    return changed


def clean_responses_frame(frame):
    """清洗 Responses SSE 帧（bytes）。只改写 data: 行，event: 行原样保留。"""
    if not frame:
        return frame
    try:
        text = frame.decode("utf-8")
    except Exception:
        return frame
    out, changed = [], False
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("data:"):
            payload = st[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    obj = json.loads(payload)
                    if _strip_empty_fc(obj):
                        line = "data: " + json.dumps(obj, ensure_ascii=False)
                        changed = True
                except Exception:
                    pass
        out.append(line)
    return ("\n".join(out) + "\n\n").encode("utf-8") if changed else frame


def normalize_roles(messages):
    """Map role names the upstream rejects onto ones it accepts.

    Qoder 只认识 system / user / assistant（+ 模板自带）。OpenAI 新的
    "developer" 角色等价于 "system"。
    """
    out = []
    for m in messages or []:
        if not isinstance(m, dict):
            out.append(m)
            continue
        item = m
        if m.get("role") == "developer":
            item = dict(m)
            item["role"] = "system"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 出站提示词脱敏（防御性保留：过滤常见客户端指纹串）
# ---------------------------------------------------------------------------
SANITIZE_FEATURES = (
    "x-anthropic-billing-header",
    "cc_entrypoint=",
    "You are Claude Code, Anthropic's official CLI for Claude",
    "You are a coding agent running in the Codex CLI",
    "github.com/anthropics/",
)
SANITIZE_REWRITES = (
    ("You are Claude Code, Anthropic's official CLI for Claude",
     "You are Claude Code, Anthropic's official CLI tool for Claude"),
    ("You are a coding agent running in the Codex CLI, a terminal-based coding assistant.",
     "You are a coding agent running in the Codex CLI tool, a terminal-based coding assistant."),
)
SANITIZE_HDR_RE = re.compile(r"(?i)x-anthropic-billing-header:[^;\r\n]*;?\s*")
SANITIZE_BARE_HDR_RE = re.compile(r"(?i)x-anthropic-billing-header")
SANITIZE_KV_RE = re.compile(r"(?i)\bcc_[a-z0-9_]+=[^;\r\n]*;?\s*")


def has_fingerprint(text):
    if not isinstance(text, str) or not text:
        return False
    for f in SANITIZE_FEATURES:
        if f in text:
            return True
    return bool(SANITIZE_BARE_HDR_RE.search(text))


def sanitize_text(text):
    if not isinstance(text, str) or not text:
        return text
    if not has_fingerprint(text):
        return text
    for old, new in SANITIZE_REWRITES:
        text = text.replace(old, new)
    text = SANITIZE_HDR_RE.sub("", text)
    if "cc_" in text:
        prev = ""
        while prev != text:
            prev = text
            text = SANITIZE_KV_RE.sub("", text)
    text = SANITIZE_BARE_HDR_RE.sub("x-anthropic-billing-hdr", text)
    return text.strip()


def sanitize_content(content):
    if isinstance(content, str):
        return sanitize_text(content)
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" \
                    and "text" in part:
                p = dict(part)
                p["text"] = sanitize_text(p["text"])
                out.append(p)
            else:
                out.append(part)
        return out
    return content


def sanitize_tool_calls(tool_calls):
    if not isinstance(tool_calls, list):
        return tool_calls
    out = []
    for tc in tool_calls:
        if isinstance(tc, dict):
            item = dict(tc)
            fn = item.get("function")
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                fn = dict(fn)
                fn["arguments"] = sanitize_text(fn["arguments"])
                item["function"] = fn
            out.append(item)
        else:
            out.append(tc)
    return out


def sanitize_messages(messages):
    out = []
    for m in messages or []:
        if isinstance(m, dict):
            item = dict(m)
            if "content" in item:
                item["content"] = sanitize_content(item["content"])
            if isinstance(item.get("reasoning_content"), str):
                item["reasoning_content"] = sanitize_text(item["reasoning_content"])
            if "tool_calls" in item:
                item["tool_calls"] = sanitize_tool_calls(item["tool_calls"])
            out.append(item)
        else:
            out.append(m)
    return out


def backfill_reasoning_content(messages, model):
    """DeepSeek 多轮一致性：assistant 历史补 reasoning_content。"""
    if not model or not str(model).lower().startswith("deepseek"):
        return messages
    has_trace = False
    for m in messages:
        if isinstance(m, dict):
            if m.get("reasoning") or "reasoning_content" in m:
                has_trace = True
                break
    if not has_trace:
        return messages
    out = []
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "assistant":
            item = dict(m)
            if "reasoning_content" not in item:
                if item.get("reasoning"):
                    item["reasoning_content"] = str(item["reasoning"])
                else:
                    item["reasoning_content"] = ""
            out.append(item)
        else:
            out.append(m)
    return out


def normalize_tool_choice(obj):
    """把 OpenAI tool_choice 归一成上游可接受的形态（避免 400）。"""
    if "tool_choice" not in obj:
        return
    tc = obj["tool_choice"]
    if isinstance(tc, str):
        val = tc.strip().lower()
        if val == "none":
            obj.pop("tool_choice", None)
            obj.pop("tools", None)
        return
    if isinstance(tc, dict):
        typ = (tc.get("type") or "").strip().lower()
        if typ == "none":
            obj.pop("tool_choice", None)
            obj.pop("tools", None)
        elif typ in ("auto", "required"):
            obj["tool_choice"] = typ
        elif typ == "function":
            name = (tc.get("function") or {}).get("name") or tc.get("name") or ""
            obj["tool_choice"] = name.strip() or "auto"
        else:
            obj.pop("tool_choice", None)
    else:
        obj.pop("tool_choice", None)


def normalize_tools(obj):
    """把顶层 name 型工具定义包成 Chat Completions function schema。"""
    tools = obj.get("tools")
    if not tools or not isinstance(tools, list):
        return
    norm = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        if "name" in t and "function" not in t and t.get("type") == "function":
            fn = {
                "name": t.get("name") or "",
                "description": t.get("description") or "",
                "parameters": t.get("parameters") or {},
            }
            if "strict" in t:
                fn["strict"] = t["strict"]
            norm.append({"type": "function", "function": fn})
        else:
            norm.append(t)
    obj["tools"] = norm


def translate_max_completion_tokens(obj):
    alias = obj.pop("max_completion_tokens", None)
    if alias is None:
        return
    if "max_tokens" in obj:
        return
    try:
        val = int(alias)
        if val > 0:
            obj["max_tokens"] = val
    except (TypeError, ValueError):
        pass


# ---------------------------------------------------------------------------
# DeepSeek DSML 工具调用回退解析
# ---------------------------------------------------------------------------
TAG_START = r"<[^>]*DSML[^>]*"
DSML_CALLS_RE = re.compile(TAG_START + r"calls>(.*?)</[^>]*DSML[^>]*calls>",
                           re.DOTALL)
DSML_INVOKE_RE = re.compile(
    TAG_START + r"invoke\s+name=[\x22\x27]([^\x22\x27]+)[\x22\x27]>(.*?)</[^>]*invoke>",
    re.DOTALL)
DSML_PARAM_RE = re.compile(
    TAG_START + r"parameter\s+name=[\x22\x27]([^\x22\x27]+)[\x22\x27][^>]*>(.*?)</[^>]*parameter>",
    re.DOTALL)


def parse_dsml_tool_calls(text):
    if not text or "DSML" not in text:
        return None, text
    match = DSML_CALLS_RE.search(text)
    if not match:
        return None, text
    calls_block = match.group(1)
    tool_calls = []
    for inv_match in DSML_INVOKE_RE.finditer(calls_block):
        func_name = inv_match.group(1)
        params_block = inv_match.group(2)
        params = {}
        for p_match in DSML_PARAM_RE.finditer(params_block):
            p_name = p_match.group(1)
            p_val = p_match.group(2).strip()
            params[p_name] = p_val
        tool_calls.append({
            "id": _new_id("call_"),
            "name": func_name,
            "arguments": json.dumps(params, ensure_ascii=False),
        })
    clean = (text[:match.start()].strip() + " " + text[match.end():].strip()).strip()
    return tool_calls, clean


# DSML 起始标签的**增量**探测（流式路径用）：完整标签 + 允许的未完成前缀。
# 模型把标签写成多帧（"<｜DS" 一帧、"ML｜calls>" 一帧）时，半截标签一旦透传
# 出去就无法撤回 —— 故必须逐字符判定「还可能吗」，而不是等完整标签出现。
# 竖线允许全角 ｜（官方形态）与半角 |（模型偶发手写）。
_DSML_OPEN_RE = re.compile(r"<[|｜]?DSML[|｜]?calls>")
_DSML_PARTIAL_RE = re.compile(r"<[|｜]?D?S?M?L?[|｜]?c?a?l?l?s?>?")


def _dsml_open_state(pending):
    """pending 以 "<" 开头时，判断它是否是（或可能长成）DSML 起始标签。

    返回 "match"（起始标签已完整）/ "maybe"（仍可能是前缀，需更多字符）/
    "no"（不可能 -> 立即按普通文本下发，不扣留内容）。
    """
    if not pending.startswith("<"):
        return "no"
    if _DSML_OPEN_RE.match(pending):
        return "match"
    m = _DSML_PARTIAL_RE.match(pending)
    if m and m.end() == len(pending):
        return "maybe"
    return "no"


def declared_tool_names(tools):
    """客户端声明的工具名集合（Chat 的 function 包裹形态 + 顶层 name 形态）。

    DSML 兜底据此白名单校验：解析出的 invoke 名必须**全部**在集合内才敢转成
    结构化 tool_calls —— 否则会把模型随手写的文本变成客户端不认识的工具调用。
    """
    names = set()
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function")
        name = (fn.get("name") if isinstance(fn, dict) else "") or t.get("name") or ""
        if name:
            names.add(str(name))
    return names


# ---------------------------------------------------------------------------
# 历史工具调用文本形态的「回读」（上游 issue #8/#9/#11/#16）
# ---------------------------------------------------------------------------
# 模型偶发把工具调用**按文本格式复述**进正文（而不是给结构化 tool_calls），
# 客户端就会把这段内部协议文本当正文显示、本轮调用不执行：
#   - issue #8 ：LEAK_MARKER + JSON 数组 [{name, arguments}, ...]
#   - issue #11：TOOL_RESULT_MARKER + 工具结果正文（回声块）
# 这里在严格守卫下还原成结构化 tool_calls，或按截断语义吞掉；chat 流式/非流式、
# Responses 流式/非流式四条出口共用同一套判据。
LEAK_MARKER = "[assistant 请求调用工具]"
TOOL_RESULT_MARKER = "[工具结果"
TOOL_RESULT_CLOSE = "[工具结果结束]"

# issue #16-B1：跨帧补全窗口 = 最长标记长度 - 1（LEAK_MARKER 18 字符 -> 17）。
# 只有帧/缓冲**末尾**的这 17 个字符内匹配到某个标记的真前缀时才暂留；
# 下一帧一旦证伪立即补发（fail-open），不会无限压住正常文本。
_MARKER_HOLD_WINDOW = max(len(LEAK_MARKER), len(TOOL_RESULT_MARKER)) - 1

# issue #16 兜底：hold 缓冲上限。正常文本长期"看起来仍是候选"时（模型写超长
# JSON/正则示例），hold 会持续增长 -> 内存与首字延迟风险。超限即 fail-open
# 放行并记一条 WARN：宁可漏一次，也不无限压住客户端。
_HOLD_MAX_CHARS = 32768            # 32KB（真实回声块远小于此）
_HOLD_MAX_FRAMES = 200             # 极端"每帧 1 字符"场景的二级兜底


def parse_leaked_tool_calls(text, allowed_names=None):
    """把模型复述的「marker + JSON 数组」还原成结构化 tool_calls。

    严格守卫（避免把"讨论该标记的普通回复"误判为工具调用）：
      1) 整段正文 strip 后必须**恰好**是 marker + JSON 数组（可带 ``` 围栏）；
      2) 数组非空，每项 name 为非空字符串、arguments 为合法 JSON（字符串或对象）；
      3) 本次请求声明了 tools 时，所有 name 必须命中声明集合。

    返回 (tool_calls|None, clean_text)：识别成功时 clean_text 为空串
    （整段都是该块）；未识别时原样返回 text。
    """
    t = (text or "").strip()
    # 整段被 ``` 围栏包裹时先剥壳（模型复述时常带围栏）
    if t.startswith("```") and t.endswith("```") and len(t) > 6:
        inner = t[3:]
        if inner[:4].lower() == "json":
            inner = inner[4:]
        t = inner[:-3].strip()
    if not t.startswith(LEAK_MARKER):
        return None, text
    rest = t[len(LEAK_MARKER):].strip()
    if not (rest.startswith("[") and rest.endswith("]")):
        return None, text
    try:
        arr = json.loads(rest)
    except Exception:
        return None, text
    if not isinstance(arr, list) or not arr:
        return None, text
    calls = []
    for item in arr:
        if not isinstance(item, dict):
            return None, text
        name = item.get("name")
        args = item.get("arguments")
        if not isinstance(name, str) or not name.strip():
            return None, text
        if isinstance(args, (dict, list)):
            args = json.dumps(args, ensure_ascii=False)
        if not isinstance(args, str):
            return None, text
        if args.strip():
            try:
                json.loads(args)
            except Exception:
                return None, text
        calls.append({
            "id": _new_id("call_"),
            "type": "function",
            "function": {"name": name.strip(), "arguments": args},
        })
    if allowed_names:
        if not all(c["function"]["name"] in allowed_names for c in calls):
            return None, text
    return calls, ""


def _leak_body_offset(text):
    """把「marker 之前的围栏前缀 / marker 之后的正文」解析出来。

    返回 (state, body)：state='pre'（还处在围栏/前缀区，未到 marker）、
    state='body'（已越过 marker，body 为其后文本）、state='no'（显然不是）。
    流式暂存与判真共用同一套前缀规则（含 ``` 与 ```json 围栏）。
    """
    t = (text or "").lstrip()
    if not t or LEAK_MARKER.startswith(t):
        return "pre", None
    if t.startswith(LEAK_MARKER):
        return "body", t[len(LEAK_MARKER):]
    if not t.startswith("`"):
        return "no", None
    if len(t) < 3:
        return ("pre", None) if "```".startswith(t) else ("no", None)
    if not t.startswith("```"):
        return "no", None
    rest = t[3:]
    low = rest.lstrip().lower()
    if low.startswith("json"):
        after = rest.lstrip()[4:].lstrip()
    elif LEAK_MARKER.startswith(low) or low.startswith(LEAK_MARKER):
        after = rest.lstrip()          # 无语言标记的 ``` 围栏
    elif "json".startswith(low):
        return "pre", None             # 语言标记还没打完（j/js/json）
    else:
        return "no", None
    if LEAK_MARKER.startswith(after):
        return "pre", None
    if after.startswith(LEAK_MARKER):
        return "body", after[len(LEAK_MARKER):]
    return "no", None


def _leak_prefix_hold(text):
    """文本仍可能是泄漏块的前缀？（流式 hold-back 用）"""
    return _leak_body_offset(text)[0] != "no"


def _json_array_prefix_ok(text):
    """text 是否仍可能扩展成合法 JSON 数组字面量（流式暂存判定用）。"""
    s = (text or "").strip()
    if not s:
        return True
    if not s.startswith("["):
        return False
    try:
        json.loads(s)
        return True
    except Exception as exc:
        msg = str(exc)
        # 未闭合字符串的报错位置在字符串开头，但仍可继续扩展
        if msg.startswith("Unterminated string"):
            return True
        pos = getattr(exc, "pos", None)
        if pos is None:
            return False
        if msg.startswith("Invalid \\uXXXX escape"):
            # issue #16-B3：截断落在未写完的转义里（"...\\u6" / "...\\u63a2"）。
            # json.loads 的报错位置在**反斜杠**处而非末尾，旧的
            # `pos >= len(s) - 1` 兜底会判 False -> 不吞 -> 泄漏。
            # 「未写完」（hex 不足）与「彻底非法」（如 \\uZZZZ）在异常消息层面
            # 无法区分，一律宽松 hold —— 流末仍会走吞掉/补发判定，宽松只影响
            # 延迟、不改变最终结论。实测（Python 3.13）pos 指向 'u' 本身
            # （如 s[pos-1] == "\\"）；为稳妥两种位置都检查。
            return (s[max(0, pos - 1):pos + 1] == "\\u"
                    or s[pos:pos + 2] == "\\u")
        if msg.startswith("Extra data"):
            # 数组已完整，尾随的只能是（可能还没打完的）``` 收尾围栏
            tail = s[pos:].strip()
            return (not tail) or "```".startswith(tail)
        # 语法错误点落在末尾（未闭合括号等）→ 还允许继续扩展
        return pos >= len(s) - 1


def _find_marker_split(text, allow_prefix=True):
    """把正文切成 (立即发出, 暂存候选)：在首个完整标记处切开（issue #16-B1）。

    - 命中完整标记 -> (标记之前的散文, 标记及其后)；
    - allow_prefix=True 且**末尾**是某标记的真前缀（长度 < 标记）时，把这段
      前缀留给下一帧（跨帧补全窗口 _MARKER_HOLD_WINDOW）；
    - 无命中 -> (text, "")。

    背景：服务端 delta 切分不可控，"散文 + marker" 可能落在同一帧，而
    _leak_prefix_hold 只认「整帧以标记开头」-> 整帧被透传 -> 泄漏。
    """
    t = text or ""
    if not t:
        return "", ""
    best = -1
    for mk in (LEAK_MARKER, TOOL_RESULT_MARKER):
        i = t.find(mk)
        if i != -1 and (best == -1 or i < best):
            best = i
    if best != -1:
        return t[:best], t[best:]
    if not allow_prefix:
        return t, ""
    tail = t[-_MARKER_HOLD_WINDOW:] if len(t) > _MARKER_HOLD_WINDOW else t
    for mk in (LEAK_MARKER, TOOL_RESULT_MARKER):
        for n in range(min(len(tail), len(mk) - 1), 0, -1):
            if tail.endswith(mk[:n]):
                return t[:-n], t[-n:]
    return t, ""


def _still_leak_candidate(text):
    """整段文本目前是否仍是「marker + JSON 数组」候选？（流式暂存判定用）"""
    state, body = _leak_body_offset(text)
    if state == "pre":
        return True
    if state == "no":
        return False
    rest = (body or "").lstrip()
    if not rest:
        return True
    if rest.endswith("```"):
        rest = rest[:-3]
    return _json_array_prefix_ok(rest)


def _leaked_partial_droppable(text, allowed_names=None):
    """issue #9：正文是网关自己写入历史的工具调用回声、但被截断（JSON 不完整/
    非法）时，应吞掉整段而不是透传给终端用户。三个条件同时成立才吞：
      1) strip 后以 LEAK_MARKER 开头（真实散文回复几乎不会这样开头）；
      2) 本次请求声明了 tools（allowed_names 非空）——与恢复路径同前置条件；
      3) marker 之后（剥掉围栏后）仍是 JSON 数组字面量的前缀
         （复用现成的 _json_array_prefix_ok）——即"本该是数组，只是没写完"。
    返回 True = 应吞掉正文（输出空 content）。

    完整且合法的 JSON 数组不算：那种情况下恢复失败另有原因（工具名未声明 /
    arguments 非法），保持既有 fail-open 透传语义（"未声明工具名 -> 不吞正文"），
    只有"数组本身没写完 / 非法"才吞。
    """
    if not text or not allowed_names:
        return False
    t = text.strip()
    if not t:
        return False
    if t == LEAK_MARKER:
        # 只有 marker、连数组都没开始写：判据 3 的退化情形，同样是回声。
        return True
    state, body = _leak_body_offset(t)
    if state != "body":
        return False
    rest = (body or "").strip()
    if rest.endswith("```"):
        rest = rest[:-3].strip()
    if not _json_array_prefix_ok(rest):
        return False
    try:
        json.loads(rest)
        return False
    except Exception:
        return True


def _tool_echo_head(text):
    """切分「[工具结果<name>]」开标记行 → (body, ok)；ok=False 表示不是合法开标记。"""
    t = (text or "").strip()
    if not t.startswith(TOOL_RESULT_MARKER):
        return None, False
    rest = t[len(TOOL_RESULT_MARKER):]
    close = rest.find("]")
    if close == -1 or "\n" in rest[:close]:
        return None, False          # 标记行未闭合 / 换行后才有 ]：非本网关形态
    return rest[close + 1:], True


def _tool_echo_droppable(text, allowed_names=None):
    """issue #11：正文是「[工具结果...]」回声块时吞掉整段（与 issue #9 同形态）。

    三个条件同时成立才吞：
      1) strip 后是合法开标记行（TOOL_RESULT_MARKER + 可选 name + ]）；
      2) 本次请求声明了 tools（allowed_names 非空）——与既有回读同一前置；
      3) 形态自洽：出现模型自造的闭标记 TOOL_RESULT_CLOSE，或标记之后（忽略空白）
         以 JSON/标签起始字符开头（含被截断、永不闭合的块）。

    为什么吞掉而不是还原成 tool 消息：还原需要把回声与历史上的 tool_call_id
    配对，本轮只做「不把内部协议文本交给终端用户」。

    不吞（fail-open）：不以标记开头；标记后跟自然语言散文；未声明 tools。
    """
    if not text or not allowed_names:
        return False
    body, ok = _tool_echo_head(text)
    if not ok:
        return False
    if TOOL_RESULT_CLOSE in body:
        return True
    rest = body.lstrip()
    if not rest:
        return True                 # 只有开标记：退化形态（与 #9 的纯 marker 一致）
    return rest[0] in "{[\"<"


def _tool_echo_prefix_hold(text):
    """流式 hold-back：这段缓冲仍可能是 issue #11 的回声块吗？（宽松版判据）"""
    t = (text or "").lstrip()
    if not t:
        return True
    if TOOL_RESULT_MARKER.startswith(t):
        return True                 # 标记本身还没打完
    body, ok = _tool_echo_head(t)
    if not ok:
        return False                # 不是标记形态 -> 证伪，立即放行
    if TOOL_RESULT_CLOSE in body:
        return True
    rest = body.lstrip()
    if not rest:
        return True
    return rest[0] in "{[\"<"


def _echo_hold_candidate(text):
    """统一暂存判定：仍可能是 #8 数组回声或 #11 工具结果回声？"""
    return _still_leak_candidate(text) or _tool_echo_prefix_hold(text)


def _leak_chunk_frame(meta, delta, finish_reason=None):
    """按流式 chat.completion.chunk 形态合成一帧（沿用上游的 id/model）。"""
    payload = {
        "id": meta.get("id") or "chatcmpl-qoder",
        "object": "chat.completion.chunk",
        "created": meta.get("created") or int(time.time()),
        "model": meta.get("model") or "",
        "choices": [{"index": 0, "delta": delta,
                     "finish_reason": finish_reason}],
    }
    return ("data: " + json.dumps(payload, ensure_ascii=False)
            + "\n\n").encode("utf-8")


def _frame_without_content(payload):
    """复制一帧并去掉 delta.content（保留 tool_calls/reasoning/收尾信息）。"""
    out = dict(payload)
    choices = []
    for ch in payload.get("choices") or []:
        if not isinstance(ch, dict):
            choices.append(ch)
            continue
        ch2 = dict(ch)
        delta = ch2.get("delta")
        if isinstance(delta, dict) and "content" in delta:
            d2 = dict(delta)
            d2.pop("content", None)
            ch2["delta"] = d2
        choices.append(ch2)
    out["choices"] = choices
    return out


def recover_leaked_tool_calls(frames, allowed_names=None):
    """流式回读（issue #8）：把模型逐块吐出的「marker + JSON 数组」正文恢复
    成结构化 tool_calls 增量帧；其余内容原样透传（fail-open）。

    与 parse_leaked_tool_calls 同一套严格守卫，另加：
      - 只有当已输出的正文仍是该块的「前缀/候选」时才暂存（期间不发正文）；
      - 候选被证伪（出现别的字 / JSON 非法）→ 立刻把暂存整段补发为正文；
      - 收尾帧暂存到流末，识别成功时改写 finish_reason=tool_calls；
      - 上游控制流异常（UpstreamStatus = 排队/额度重开信号）直接放行、不补发：
        补发会污染 handler 的 emitted，关掉流内排队与瞬时重开；
      - 其它中断（断连/超时）先把**非**泄漏候选的暂存补发（宁可多吐一段正文，
        也不闷掉正常文本），泄漏候选仍按截断语义丢弃。

    客户端**没声明任何工具**时整层直通（不暂存、不还原、不吞）——与本地 DSML
    兜底同一口径：没有声明集合就无从校验白名单，宁可 fail-open 把文本交给用户，
    也不凭空造出客户端不认识的 tool_calls。
    """
    if not allowed_names:
        for raw in frames:
            yield raw
        return
    hold = None          # 正在暂存的候选正文（None = 未暂存）
    hold_frames = 0      # hold 已累积的帧数（上限兜底用，issue #16）
    finished = None      # 暂存的收尾帧：(payload, 原 finish_reason)
    recovered = False
    meta = {"id": None, "model": None, "created": None}

    try:
        for raw in frames:
            text = (raw.decode("utf-8", "replace")
                    if isinstance(raw, bytes) else raw)
            data = strip_data_prefix(text)
            payload = None
            if data and data != "[DONE]":
                try:
                    payload = json.loads(data)
                except Exception:
                    payload = None
            if not isinstance(payload, dict):
                yield raw
                continue
            if payload.get("id"):
                meta["id"] = payload["id"]
            if payload.get("model"):
                meta["model"] = payload["model"]
            if payload.get("created"):
                meta["created"] = payload["created"]
            choices = payload.get("choices") or []
            choice = (choices[0] if choices and isinstance(choices[0], dict)
                      else {})
            delta = choice.get("delta") or {}
            piece_raw = delta.get("content")
            piece = piece_raw if isinstance(piece_raw, str) else ""
            fin = choice.get("finish_reason")
            if piece_raw is not None and not isinstance(piece_raw, str):
                # 非字符串 content（罕见）：不参与暂存判断，原样透传
                if hold is not None:
                    yield _leak_chunk_frame(meta, {"content": hold})
                    hold = None
                    hold_frames = 0
                yield raw
                continue
            if hold is not None:
                hold += piece
                hold_frames += 1
                if _echo_hold_candidate(hold):
                    # issue #16 兜底：超限即 fail-open 放行（内存 + 首字延迟）。
                    if len(hold) > _HOLD_MAX_CHARS \
                            or hold_frames > _HOLD_MAX_FRAMES:
                        log("released oversized leak hold (%d chars / %d frames) "
                            "- fail-open" % (len(hold), hold_frames),
                            level="WARN", tag="chat")
                        yield _leak_chunk_frame(meta, {"content": hold})
                        hold = None
                        hold_frames = 0
                        if fin:
                            finished = (_frame_without_content(payload), fin)
                        continue
                    if fin:
                        # 该帧 content 已进入 hold（可能被吞或稍后补发），收尾帧
                        # 必须去掉 content，否则同一段内容会被发两次（issue #16）。
                        finished = (_frame_without_content(payload), fin)
                    elif (delta.get("tool_calls")
                          or delta.get("reasoning_content")
                          or delta.get("refusal")
                          or delta.get("role")):
                        other = _frame_without_content(payload)
                        yield ("data: "
                               + json.dumps(other, ensure_ascii=False)
                               + "\n\n").encode("utf-8")
                    continue
                # 证伪：暂存整段补发为普通正文
                yield _leak_chunk_frame(meta, {"content": hold})
                hold = None
                hold_frames = 0
                if fin:
                    # 该帧 content 已进入 hold（可能被吞或稍后补发），收尾帧必须
                    # 去掉 content，否则同一段内容会被发两次（issue #16）。
                    finished = (_frame_without_content(payload), fin)
                continue
            if fin and not piece:
                finished = (payload, fin)
                continue
            if piece:
                # issue #16-B1：散文与 marker 落在同一帧时，_leak_prefix_hold
                # 对整帧判 False（它要求 lstrip 后以标记开头）-> 整帧透传 -> 泄漏。
                # 这里先按标记切分：标记之前的散文**立即发出**（不拖首字延迟），
                # 标记及其后进既有 hold 流程；帧尾的真前缀也在这里被暂留。
                _emit16, _hold16 = _find_marker_split(piece)
                if _hold16:
                    if _emit16:
                        yield _leak_chunk_frame(meta, {"content": _emit16})
                    hold = _hold16
                    hold_frames = 1
                    if fin:
                        finished = (_frame_without_content(payload), fin)
                    continue
                if _leak_prefix_hold(piece) or _tool_echo_prefix_hold(piece):
                    hold = piece
                    hold_frames = 1
                    if fin:
                        finished = (_frame_without_content(payload), fin)
                    continue
                # 未改动：原帧透传。**不要**重建帧 —— 同一帧可能还带
                # reasoning_content / refusal / tool_calls 等字段，重建会丢。
                yield raw
                continue
            yield raw
    except (UpstreamStatus, GeneratorExit):
        raise
    except BaseException:
        # 断连/超时等：先把**非**泄漏候选的暂存按普通正文补发（本地口径：
        # 中断不闷掉正常文本），泄漏候选/回声块按截断语义丢弃；随后原样放行
        # 异常，交给上层 iter_client_sse 补发它自己的 tool_calls 缓冲。
        if hold is not None and not _leaked_partial_droppable(
                hold, allowed_names) and not _tool_echo_droppable(
                hold, allowed_names):
            try:
                yield _leak_chunk_frame(meta, {"content": hold})
            except Exception:
                pass
        hold = None
        raise

    if hold is not None:
        calls, clean = parse_leaked_tool_calls(hold, allowed_names)
        if calls:
            recovered = True
            for i, call in enumerate(calls):
                yield _leak_chunk_frame(meta, {"tool_calls": [{
                    "index": i,
                    "id": call.get("id"),
                    "type": call.get("type") or "function",
                    "function": call.get("function") or {},
                }]})
            if clean:
                yield _leak_chunk_frame(meta, {"content": clean})
        elif _leaked_partial_droppable(hold, allowed_names):
            # issue #9：截断的 marker+JSON 回声无法还原成结构化调用，吞掉整段，
            # 绝不把网关内部协议文本透传给终端用户。
            log("dropped truncated leaked tool-call echo (%d chars) - issue #9"
                % len(hold), level="WARN", tag="chat")
        elif _tool_echo_droppable(hold, allowed_names):
            # issue #11：模型把 [工具结果...] 回声块当正文吐出（自造闭标记或
            # 未闭合的截断块）——吞掉，不还原（需 tool_call_id 配对）。
            log("dropped leaked tool-result echo (%d chars) - issue #11"
                % len(hold), level="WARN", tag="chat")
        else:
            yield _leak_chunk_frame(meta, {"content": hold})
    if finished is not None:
        payload, fin = finished
        if recovered:
            payload = json.loads(json.dumps(payload))
            for ch in payload.get("choices") or []:
                if isinstance(ch, dict) and ch.get("finish_reason"):
                    ch["finish_reason"] = "tool_calls"
        yield ("data: " + json.dumps(payload, ensure_ascii=False)
               + "\n\n").encode("utf-8")
    elif recovered:
        yield _leak_chunk_frame(meta, {}, "tool_calls")


# ---------------------------------------------------------------------------
# Qoder 数据面：请求体构造
# ---------------------------------------------------------------------------
def _flatten_content_text(content):
    """把 OpenAI content（str 或 parts 列表）压成纯文本；图片另行收集。"""
    if content is None:
        return "", []
    if isinstance(content, str):
        return content, []
    if not isinstance(content, list):
        return str(content), []
    texts, images = [], []
    for piece in content:
        if isinstance(piece, str):
            texts.append(piece)
            continue
        if not isinstance(piece, dict):
            continue
        ptype = piece.get("type") or ""
        if ptype in ("text", "input_text", "output_text", "summary_text"):
            texts.append(piece.get("text") or "")
        elif ptype in ("image_url", "image", "input_image") or "image_url" in piece:
            url = piece.get("image_url") or piece.get("url")
            if isinstance(url, dict):
                url = url.get("url")
            if not url and piece.get("data"):
                mime = piece.get("mimeType") or piece.get("mime_type") or "image/png"
                url = "data:%s;base64,%s" % (mime, piece["data"])
            if url:
                images.append(url)
    return "\n".join(t for t in texts if t), images


def is_truncated_arguments(raw):
    """工具参数字符串是否因分片丢失而残缺（区别于「该工具本就无参数」）。

    SSE 流被截断（连接中断 / finish_reason==length / 上游超时）时，工具调用的
    arguments 会只剩半截 JSON。若原样交给客户端，客户端解析会报
    `Tool call arguments are not valid JSON. Parse Error: Unterminated string`
    并卡死会话 —— 实测复现过该错误串。

    判定（与 workbuddy 网关 truncation.go 的 isTruncatedArguments 同语义）：
      - 空串 / 纯空白 -> False（合法的无参工具）
      - 非空但 JSON 解析失败 -> True（截断）
      - 能解析（含 null / 标量 / 数组等任意合法 JSON）-> False

    注意：`NaN`/`Infinity` 在 Python 的 json 里可解析，但客户端 `JSON.parse`
    会拒绝 —— 故显式把这三个非标量视为不可解析（与 Go 的 json.Unmarshal 对齐）。
    """
    if not isinstance(raw, str):
        return False
    trimmed = raw.strip().lstrip("﻿")     # 容忍 BOM
    if not trimmed:
        return False
    try:
        json.loads(
            trimmed,
            parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        return False
    except Exception:
        return True


def drop_truncated_tool_calls(calls, custom_names=None):
    """过滤出 arguments 完整的 tool_call（返回新列表）。

    只依据 is_truncated_arguments 判定，不改动任何保留的调用（正例零改动）。
    **custom freeform 工具例外**：其载荷本就是自由文本（非 JSON），按「能否
    解析 JSON」判会误杀合法调用，故名单内的工具一律保留。
    """
    if not isinstance(calls, list):
        return calls
    kept = []
    for call in calls:
        if not isinstance(call, dict):
            kept.append(call)
            continue
        fn = call.get("function")
        if not isinstance(fn, dict):
            kept.append(call)
            continue
        _nm = fn.get("name")
        if isinstance(_nm, str) and _nm in (custom_names or ()):
            kept.append(call)
            continue
        if is_truncated_arguments(fn.get("arguments")):
            continue
        kept.append(call)
    return kept


def cleanup_orphan_tool_calls(messages):
    """剔除「孤儿」tool_calls / tool 结果，返回 (清洗后列表, 是否有改动)。

    上游对**配对不完整**的 tool_calls 会直接 400：
        "The provided messages input is invalid. The error info is
         [Can only get item pairs from a mapping.]"
    即 assistant 声明调用了某 id，却缺少对应的 role=tool 结果（客户端截断历史、
    子代理被取消、或工具执行中断都会造成）。

    单条孤儿会让**整次请求**失败，而客户端每轮都带完整历史 —— 于是该会话之后
    每一轮都 400，表现为「工具调用持续失败」而非偶发。故必须先行剔除。

    规则（与 workbuddy 网关的 cleanupOrphanToolCalls 同语义）：
      - 只保留**双侧齐全**的 id（既有 assistant 调用、又有 tool 结果）；
      - assistant.tool_calls 里只要有任一 id 未配对（或条目畸形）→ **整个
        tool_calls 键删掉**；
      - 未配对的 role=tool 结果消息**整条删除**。

    注：删除「反向孤儿」（有 tool 结果、无对应调用）是**保守选择** —— 实测
    上游接受该形态（HTTP 200），保留它本可多留一点上下文；此处与参考实现
    对齐以确保两网关行为一致，避免出现只在一边复现的诡异问题。
    """
    if not isinstance(messages, list) or not messages:
        return messages, False

    call_ids, result_ids = set(), set()
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "tool":
            tid = m.get("tool_call_id")
            if isinstance(tid, str) and tid:
                result_ids.add(tid)
        elif role == "assistant":
            tcs = m.get("tool_calls")
            if isinstance(tcs, list):
                for tc in tcs:
                    if isinstance(tc, dict):
                        tid = tc.get("id")
                        if isinstance(tid, str) and tid:
                            call_ids.add(tid)

    if not call_ids and not result_ids and not any(
            isinstance(m, dict) and (m.get("role") == "tool" or m.get("tool_calls"))
            for m in messages):
        # 早退只看「是否完全无工具痕迹」：只要出现 tool 角色或 tool_calls 键，
        # 就必须走第二遍 —— 否则 id 为空串/缺失/非字符串的**畸形** tool_calls
        # 会因两个集合都为空而原样透传（上游可能同样 400）。
        return messages, False

    paired = call_ids & result_ids
    changed = False
    out = []
    for m in messages:
        if not isinstance(m, dict):
            out.append(m)
            continue
        role = m.get("role")
        if role == "tool":
            tid = m.get("tool_call_id")
            if not (isinstance(tid, str) and tid in paired):
                changed = True          # 孤儿结果：整条删除
                continue
            out.append(m)
            continue
        if role == "assistant":
            tcs = m.get("tool_calls")
            if isinstance(tcs, list) and tcs:
                # 批内任一「非 dict / id 非法 / id 未配对」-> 整个 tool_calls
                # 删除（保留 content）。与 workbuddy 参考实现一致：畸形条目
                # 同样视为未配对，不放行整批。
                bad = False
                for tc in tcs:
                    if not isinstance(tc, dict):
                        bad = True
                        break
                    tid = tc.get("id")
                    if not (isinstance(tid, str) and tid in paired):
                        bad = True
                        break
                if bad:
                    m = dict(m)
                    m.pop("tool_calls", None)
                    changed = True
            out.append(m)
            continue
        out.append(m)

    return (out, True) if changed else (messages, False)


def flatten_messages(messages):
    """把客户端会话压平成 Qoder 上游可接受的 {role, content} 序列。

    返回 (system_text, flat_msgs, images)：
      - 首个 system/developer 消息抽为 system_text（模板 system 的替换源）
      - user/assistant 原位保留（content 压平为字符串）
      - tool 结果保留 tool 角色与 tool_call_id（上游实测能读到其内容）
      - assistant 的 tool_calls 保留结构，不序列化进 content
      - **孤儿 tool_calls / tool 结果先剔除**（否则上游对整次请求返 400）
    """
    # 先清理孤儿配对：上游对不完整配对直接 400（见 cleanup_orphan_tool_calls）。
    messages, _cleaned = cleanup_orphan_tool_calls(messages)
    if _cleaned:
        log("dropped orphan tool_calls/tool results before upstream "
            "(unpaired id -> upstream 400)", level="WARN", tag="chat")
    system_text = None
    flat, images = [], []
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        text, imgs = _flatten_content_text(m.get("content"))
        images.extend(imgs)
        text = sanitize_text(text) if isinstance(text, str) else text
        if role in ("system", "developer"):
            if system_text is None and text:
                system_text = text
            continue
        if role == "tool":
            # 保留 tool 角色与 tool_call_id：上游实测接受该结构（HTTP 200）。
            # 曾降级为 "[工具结果 (name)]" 文本 —— 那会污染模型上下文。
            item = {"role": "tool", "content": text or ""}
            if m.get("tool_call_id"):
                item["tool_call_id"] = m["tool_call_id"]
            if m.get("name"):
                item["name"] = m["name"]
            flat.append(item)
            continue
        if role == "assistant" and m.get("tool_calls"):
            # **保留结构化 tool_calls**，不降级为自造文本。
            # 实测：上游接受该结构；且结构化历史下模型能正确继续调用工具，
            # 而文本降级会让模型模仿那段 JSON、把工具调用当纯文本吐出来。
            flat.append({"role": "assistant", "content": text or "",
                         "tool_calls": sanitize_tool_calls(m["tool_calls"])})
            continue
        if role in ("user", "assistant"):
            flat.append({"role": role, "content": text or ""})
        elif role:  # 未知角色一律降级为 user，不静默丢弃
            flat.append({"role": "user", "content": text or ""})
    return system_text, flat, images


# 客户端可用这两个字段之一按请求指定上下文窗口（OpenAI 规范外的扩展）。
# 官方 App 的「上下文窗口」滑块即对应此语义。
_CTX_WINDOW_FIELDS = ("context_window", "max_input_tokens")


def _model_window_options(catalog_meta):
    """该模型允许的窗口档位（升序）与其官方默认值。

    context_config 形如 {'1M': {token_count: 1000000}, '200K': {token_count:
    200000, is_default: true}, ...} —— 官方 App 的滑块档位就来自这里。
    返回 (options, default)；无配置时返回 ([], None)。
    """
    cfg = (catalog_meta or {}).get("context_config")
    if not isinstance(cfg, dict):
        return [], None
    options, default = [], None
    for _label, conf in cfg.items():
        if not isinstance(conf, dict):
            continue
        try:
            tok = int(conf.get("token_count") or 0)
        except (TypeError, ValueError):
            tok = 0
        if tok > 0:
            options.append(tok)
            if conf.get("is_default"):
                default = tok
    options = sorted(set(options))
    return options, default


def resolve_context_window(catalog_meta, requested=None):
    """决定本次请求向上游声明的窗口。

    优先级：客户端显式指定（夹到合法档位）> 官方默认档位 > max_input_tokens
    > 180000 兜底。**注意 180000 只是默认值而非上限** —— 官方 App 对同模型
    提供 200K/400K/1M，历史实证 GLM-5.3 实际吃过 466K 输入。
    """
    options, default = _model_window_options(catalog_meta)
    if requested:
        try:
            want = int(requested)
        except (TypeError, ValueError):
            want = 0
        if want > 0:
            if options:
                # 夹到不超过 want 的最大档位；want 比最小档还小则取最小档。
                le = [o for o in options if o <= want]
                return le[-1] if le else options[0]
            return want
    if default:
        return default
    try:
        _m = int((catalog_meta or {}).get("max_input_tokens") or 0)
    except (TypeError, ValueError):
        _m = 0
    return _m or 180000


def pop_context_window(payload):
    """取出并**移除**客户端的窗口字段（避免污染转发给上游的体）。"""
    want = None
    if isinstance(payload, dict):
        for k in _CTX_WINDOW_FIELDS:
            if k in payload:
                if want is None:
                    want = payload.get(k)
                payload.pop(k, None)
    return want


def build_qoder_body(payload, account, model_key, realm=None):
    """构造 agent_chat_generation 上游请求体（返回 dict，随后 qoder_encode）。

    以官方 baseprompt.json 为骨架：每次覆写 request/session id、时间戳、
    模型配置（按出口区域的官方清单取元数据）、系统提示词与会话、工具、
    参数与 business 会话名。
    """
    r = realm or (account.realm if account else CURRENT_REALM)
    body = json.loads(json.dumps(BASEPROMPT))   # deep copy
    messages = normalize_roles(payload.get("messages") or [])
    messages = sanitize_messages(messages)
    model = payload.get("model") or ""
    messages = backfill_reasoning_content(messages, model)

    system_text, flat, images = flatten_messages(messages)
    # 模板只保留 system 基座（其自带的示例 user 轮次是样例内容，必须丢弃），
    # 真实会话随后追加。
    tmpl_system = [m for m in (body.get("messages") or [])
                   if (m or {}).get("role") == "system"]
    if system_text is None:
        # 客户端没给 system：优先用 --system-prompt 覆盖值（非默认时）；
        # 其次看客户端是否自带工具 —— 带工具（edit/Bash/...）的客户端**绝不能**
        # 继承模板自带的 Qoder CLI 系统提示词：那 12KB 里教的是 Qoder 桌面端
        # 内置工具的用法（Task/TodoWrite/Edit/...）与桌面端语境（Working
        # directory: D:/Projects/Qoder 等），模型会照着它写 Qoder 形态的调用，
        # 与客户端实际声明的工具 schema 不符（实测表现为非法工具 payload、
        # 半截/错位的 arguments）。此时用 SYSTEM_PROMPT（默认值也可）作中性
        # 基座，工具定义完全以客户端 tools 为准。
        if SYSTEM_PROMPT and SYSTEM_PROMPT != DEFAULT_SYSTEM_PROMPT:
            system_text = SYSTEM_PROMPT
        elif payload.get("tools"):
            system_text = SYSTEM_PROMPT or DEFAULT_SYSTEM_PROMPT
        else:
            # 既无 system 也无工具：保持原行为（保留模板的 Qoder 提示词）
            body["messages"] = tmpl_system
    if system_text is not None:
        body["messages"] = [{"role": "system", "content": system_text}]
    # 追加真实会话
    body["messages"].extend(flat)

    # 最新用户提示词（上游 chat_context 高亮 + business 会话名）
    prompt = ""
    for m in reversed(flat):
        if m["role"] == "user" and m.get("content"):
            prompt = m["content"]
            break

    nid = str(uuid.uuid4())
    body["request_id"] = nid
    body["chat_record_id"] = nid
    body["request_set_id"] = str(uuid.uuid4())
    body["session_id"] = str(uuid.uuid4())
    body["stream"] = True
    body["agent_id"] = "agent_common"
    body["aliyun_user_type"] = getattr(account, "user_type", "") or \
        qoder_sign.DEFAULT_USER_TYPE

    # model_config（按出口区域的官方清单取元数据 + 动态 key）
    catalog_meta = {}
    for m in qoder_catalog.models_for_realm(r):
        if m.get("key") == model_key:
            catalog_meta = m
            break
    if not catalog_meta:
        for m in qoder_catalog.STATIC_INTL_MODELS + qoder_catalog.STATIC_CN_MODELS:
            if m.get("key") == model_key:
                catalog_meta = m
                break
    mc = body.get("model_config") or {}
    mc["key"] = model_key
    mc["display_name"] = catalog_meta.get("display_name") or model_key
    mc["model"] = ""
    mc["format"] = "openai"
    mc["is_vl"] = bool(catalog_meta.get("is_vl"))
    mc["is_reasoning"] = bool(catalog_meta.get("is_reasoning"))
    mc["api_key"] = ""
    mc["url"] = ""
    mc["source"] = "system"
    # 窗口：客户端可指定；否则用官方默认档位。**不是**硬写 180000 ——
    # 那只是默认值，官方 App 对同模型提供 200K/400K/1M。
    _want_window = pop_context_window(payload)
    mc["max_input_tokens"] = resolve_context_window(catalog_meta, _want_window)
    body["model_config"] = mc

    # chat_context 高亮与模型配置副本
    cc = body.get("chat_context") or {}
    txt = cc.get("text") or {}
    txt["text"] = prompt
    cc["text"] = txt
    extra = cc.get("extra") or {}
    oc = extra.get("originalContent") or {}
    oc["text"] = prompt
    extra["originalContent"] = oc
    extra["modelConfig"] = dict(mc)
    cc["extra"] = extra
    if images:
        cc["imageUrls"] = images
        body["image_urls"] = images
    body["chat_context"] = cc

    # parameters：max_tokens / reasoning_effort
    params = body.get("parameters") or {}
    max_tokens = payload.get("max_tokens") or payload.get("max_completion_tokens")
    if max_tokens:
        try:
            params["max_tokens"] = int(max_tokens)
        except (TypeError, ValueError):
            pass
    effort = payload.get("reasoning_effort")
    if not effort and isinstance(payload.get("reasoning"), dict):
        effort = (payload.get("reasoning") or {}).get("effort")
    if effort:
        params["reasoning_effort"] = str(effort)
    body["parameters"] = params

    # tools：客户端给了就用客户端的（custom freeform 已降级），否则置空，
    # 避免把 Qoder 桌面端自带的 agent 工具（Bash/Edit/...）泄漏给普通客户端。
    tools = payload.get("tools")
    if tools:
        body["tools"] = tools
    else:
        body["tools"] = []

    # business 会话卡片
    biz = body.get("business") or {}
    biz["id"] = str(uuid.uuid4())
    biz["begin_at"] = int(time.time() * 1000)
    biz["name"] = (prompt[:30] if prompt else "chat")
    biz.setdefault("product", "cli")
    biz.setdefault("type", "agent")
    biz.setdefault("stage", "start")
    body["business"] = biz
    return body


# ---------------------------------------------------------------------------
# Qoder 数据面：上游打开与 SSE 信封解包
# ---------------------------------------------------------------------------
class RateLimited(Exception):
    """Upstream throttled this request (429 / 频控)。"""

    def __init__(self, http_error=None, detail="", wait=60):
        self.http_error = http_error
        self.detail = detail or ""
        self.wait = max(1, int(wait or 60))
        super(RateLimited, self).__init__(
            "upstream rate limit: %s" % (self.detail[:200] or "429"))


# 账号级错误短冷却的“等待续上”上限：单账号池在传输/瞬时故障后只有
# 3s（多账号 15s）冷却，此时**等待**比报 429 更正确——429 只留给真正的
# 上游频控（model_cooldowns，由上游 HTTP 429 设置）。
ERROR_COOLDOWN_WAIT_MAX = 10.0


def _short_error_cooldown_wait(realm, model, exclude=None):
    """账号级（错误/传输）短冷却的最短剩余秒数；不适用则返回 0。

    - 只看 cooldown_until（错误冷却）；若该模型正被上游频控
      （model_cooldowns）则返回 0，交给429路径处理——两者语义严格分开。
    - exclude（本请求已试过的账号）中的冷却账号**不算**：等它冷却好了也
      不会再被本请求使用，纯属浪费。
    """
    if not POOL:
        return 0.0
    exclude = exclude or set()
    now = time.time()
    waits = []
    for a in POOL.accounts:
        if a.realm != realm or not a.enabled or not a.access_token:
            continue
        if a.uid in exclude:
            continue
        if a.model_cooldowns.get(model, 0.0) > now:
            return 0.0          # 上游频控生效中 -> 正当429，不等待
        remain = a.cooldown_until - now
        if 0 < remain <= ERROR_COOLDOWN_WAIT_MAX:
            waits.append(remain)
    return min(waits) if waits else 0.0


def retry_after_seconds(model, realm):
    """上游频控的最短等待（仅 model_cooldowns——429 的正当语义）。"""
    if not POOL:
        return 60
    now = time.time()
    waits = [a.model_cooldowns.get(model, 0.0) - now
             for a in POOL.accounts
             if a.realm == realm and a.enabled and a.access_token]
    active = [w for w in waits if w > 0]
    return int(min(active)) if active else 60


# ---------------------------------------------------------------------------
# failgate：连续失败熔断（经验②：快速失败 + 无背压 = 重试放大器）
# ---------------------------------------------------------------------------
# 零成本失败 = 无限重试率。全池不可用时秒回 503 会让客户端 1 秒一发地打，
# 把"偶发限流"放大成"持续滥用"——这是账号被打标的关键放大器。因此：
#   1) 连续失败达到阈值 -> 直接 429 + Retry-After（把重复失败从廉价变昂贵）
#   2) 退避随连续失败次数递增（2s -> 30s 封顶）
#   3) 按「域|模型」隔离，一个模型的风暴不拖垮另一个
FAILGATE_THRESHOLD = 5
FAILGATE_BACKOFF = (2.0, 5.0, 10.0, 20.0, 30.0)
FAILGATE_MAX_ENTRIES = 256      # 上限：model 名来自客户端，必须防撑爆
_failgate = {}          # key -> [streak, open_until, last_seen]
_failgate_lock = threading.Lock()


def _failgate_key(realm, model):
    return "%s|%s" % (realm or "", model or "")


def _failgate_evict_locked():
    """调用方需持锁。超过上限时清掉未熔断且最久未见的条目。

    key 含客户端可控的 model 名，不设上限就是内存放大面（每个新 model 名
    一条）。只淘汰"未处于熔断窗"的条目，保证正在退避的模型不被误清。
    """
    if len(_failgate) <= FAILGATE_MAX_ENTRIES:
        return
    now = time.time()
    evictable = [(v[2], k) for k, v in _failgate.items() if v[1] <= now]
    evictable.sort()
    for _, k in evictable[:len(_failgate) - FAILGATE_MAX_ENTRIES]:
        _failgate.pop(k, None)
    # 极端情况：全部都在熔断窗内，仍超限则按 last_seen 淘汰最旧的
    if len(_failgate) > FAILGATE_MAX_ENTRIES:
        for _, k in sorted((v[2], k) for k, v in _failgate.items())[
                :len(_failgate) - FAILGATE_MAX_ENTRIES]:
            _failgate.pop(k, None)


def failgate_check(realm, model):
    """若该「域|模型」正在熔断，返回剩余等待秒数（>0），否则 0。"""
    with _failgate_lock:
        ent = _failgate.get(_failgate_key(realm, model))
        if not ent:
            return 0.0
        ent[2] = time.time()
        remain = ent[1] - time.time()
        return remain if remain > 0 else 0.0


def failgate_note_failure(realm, model):
    """记一次失败；连续失败达阈值则打开熔断窗，返回打开的等待秒数。"""
    with _failgate_lock:
        ent = _failgate.setdefault(_failgate_key(realm, model),
                                   [0, 0.0, time.time()])
        ent[0] += 1
        ent[2] = time.time()
        _failgate_evict_locked()
        if ent[0] >= FAILGATE_THRESHOLD:
            idx = min(ent[0] - FAILGATE_THRESHOLD, len(FAILGATE_BACKOFF) - 1)
            ent[1] = time.time() + FAILGATE_BACKOFF[idx]
            return FAILGATE_BACKOFF[idx]
        return 0.0


def failgate_note_success(realm, model):
    with _failgate_lock:
        _failgate.pop(_failgate_key(realm, model), None)


def _clamp_retry_after(wait):
    return max(1, min(60, int(wait or 1)))


def realm_model_throttled(realm, model):
    """True 仅当该区域账号全部被**上游频控**（model_cooldowns）挡住。

    账号级错误冷却（cooldown_until）不算频控——否则传输故障后客户端会连续
    收到误导性的 `429 usage exceeds frequency limit`。
    """
    if not POOL:
        return (False, 0)
    existing = [a for a in POOL.accounts
                if a.realm == realm and a.enabled and a.access_token]
    if not existing:
        return (False, 0)
    now = time.time()
    waits = [a.model_cooldowns.get(model, 0.0) - now for a in existing]
    if waits and all(w > 0 for w in waits):
        return (True, max(1, int(min(waits))))
    return (False, 0)


def extract_session_key(headers, payload):
    key = (
        headers.get("X-Conversation-Id") or
        headers.get("Conversation-Id") or
        headers.get("X-Session-Id") or
        headers.get("Session-Id") or
        payload.get("conversation_id") or
        payload.get("session_id") or
        (payload.get("metadata") or {}).get("conversation_id")
    )
    if key:
        return str(key).strip()
    return None


# 上游瞬时故障（与客户端参数无关，值得同账号快速重试）
TRANSIENT_HTTP_CODES = (418, 500, 502, 503, 504)
TRANSIENT_MAX_RETRIES = 2          # 同账号额外重试次数（1s、2s 退避）
_CLIENT_FAULT_MARKERS = (
    "invalid_parameter_error",     # 如 Range of max_tokens 校验失败
    "invalid_request_error",
    "authentication_error",
    "permission_error",
    '"Range of ',
    # 上游内容安全审核：确定性拒绝，重试无效（本轮日志实证
    # InternalError.Algo.DataInspectionFailed: Input text data may contain
    # inappropriate content.）
    "DataInspectionFailed",
    "inappropriate content",
    "input text data may contain",
    "ContentFilter",
    "SensitiveContent",
)

# 内容审核类错误（用户输入侧问题，需专门的中文解释）
_CONTENT_POLICY_MARKERS = (
    "DataInspectionFailed",
    "inappropriate content",
    "input text data may contain",
    "ContentFilter",
    "SensitiveContent",
)


# 上游排队（10605）：容量门控，不是凭证问题也不是常规频控。
#
# 上游把「低优先级队列暂不放行」包在 HTTP 403 里返回，载荷形如：
#   {"code":"10605","message":"{\"isQueued\":true,...,\"retryAfterSeconds\":30,...}"}
#
# 注意 queueCount 常为 0 而 serviceAvailable=false —— 这不是「队列满了」，
# 而是该优先级（p3 = 免费/低档模型）当前不被放行。上游明确给了重试间隔，
# 照它等即可；把它当凭证错误去冷却账号是错的（账号本身完全正常）。
_QUEUE_RETRY_CAP = 45         # 单轮等待上限（秒）
# 单请求内因「账号额度耗尽（110/112）」换号的次数上限。额度是账号级状态，
# 换号立刻有效且无需等待；上限只为防全池耗尽时无限打转（池规模通常 <10）。
_QUOTA_ROTATE_MAX = 8
# 排队等待总预算（秒，`QD_QUEUE_WAIT_BUDGET` 可调）。上游对低优先级模型排队
# 时会给 retryAfterSeconds（通常 30s），实测一次排队可持续 2 分钟以上 —— 等，是
# **唯一**能在网关内拿到结果的途径。代价有且只有一个：**预算必须小于客户端
# 超时**，否则客户端会在我们还在等的时候先断开，看到的是超时而非结果。
# 默认 300s（尽量在网关内等到放行）；客户端超时较短的部署请调小（如 40）。
try:
    _QUEUE_RETRY_BUDGET = max(5, int(os.environ.get("QD_QUEUE_WAIT_BUDGET") or 900))
except ValueError:
    _QUEUE_RETRY_BUDGET = 900

# 排队轮数上限**由预算推导，不能写死**：单轮最少 5s（见 queue_backoff_seconds
# 的下限），故 budget/5+2 足以覆盖全部等待。写死小值会让大预算**静默失效**
# （实测：预算 300s 而轮数上限 2 时，HTTP 路径实际只等 ~60s 就放弃）。
_QUEUE_WAIT_MAX = max(2, _QUEUE_RETRY_BUDGET // 5 + 2)
_QUEUE_RETRY_MAX = _QUEUE_WAIT_MAX    # 同义别名：open_upstream 的 HTTP-403 路径


def client_disconnected(conn):
    """客户端是否已断开（用户在客户端点了停止 / 客户端自身超时）。

    排队预算调大后**必须**探测这个：用户取消后若网关仍傻等满预算，
    会每 30s 向上游重试一次 —— 几十次无人接收的请求，正是要避免的
    流量特征。用 MSG_PEEK 非破坏性探测，不消费数据：客户端若流水线发
    了下一个请求，这里读到数据 -> 判定为未断开，交给正常流程处理。
    """
    if conn is None:
        return False
    try:
        r, _, _ = select.select([conn], [], [], 0)
        if not r:
            return False          # 无数据可读 => 连接仍开着
        return conn.recv(1, socket.MSG_PEEK) == b""   # 读到 EOF => 已断开
    except Exception:
        return True               # 探测本身失败：保守当作已断开


def parse_queue_hint(detail):
    """从上游错误体解析排队信息，返回 (is_queued, retry_after_seconds)。

    上游把真正的载荷多包了一层 JSON 字符串，所以逐层尝试解析。
    非排队错误返回 (False, 0)。
    """
    text = str(detail or "")
    if "10605" not in text and "isQueued" not in text:
        return False, 0

    def walk(node, depth=0):
        if depth > 6:
            return None
        if isinstance(node, dict):
            if node.get("isQueued") or str(node.get("code")) == "10605":
                try:
                    wait = int(float(node.get("retryAfterSeconds")
                                       or node.get("waitTime") or 0))
                except (TypeError, ValueError):
                    wait = 0
                if wait > 0:
                    return wait
                # 命中排队标记但本层没带等待秒数：继续下钻 —— 上游常把
                # retryAfterSeconds 放在内层 message 里（外层只有 code）。
                for value in node.values():
                    deeper = walk(value, depth + 1)
                    if deeper:
                        return deeper
                return 0
            for value in node.values():
                found = walk(value, depth + 1)
                if found is not None:
                    return found
        elif isinstance(node, str) and node.strip().startswith("{"):
            try:
                return walk(json.loads(node), depth + 1)
            except (ValueError, TypeError):
                return None
        elif isinstance(node, (list, tuple)):
            for value in node:
                found = walk(value, depth + 1)
                if found is not None:
                    return found
        return None

    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        m = re.search(r"retryAfterSeconds\D{0,4}(\d+)", text)
        if m:
            return True, int(m.group(1))
        return ("10605" in text), 0

    wait = walk(payload)
    if wait is None:
        return False, 0
    return True, max(0, min(wait, _QUEUE_RETRY_CAP))



def queue_backoff_seconds(exc):
    """排队错误建议等待秒数：上游 retryAfterSeconds，兜底 30s，带上限。"""
    _queued, wait = parse_queue_hint(getattr(exc, "detail", "") or "")
    return min(max(5, wait or 30), _QUEUE_RETRY_CAP)


def _is_transient_upstream(code, detail):
    """判断一次上游 HTTP 错误是否属于瞬时故障（可重试）。

    - 客户端参数/权限类错误（invalid_parameter_error 等）→ 永不重试
    - 418（上游把自己的 provider 故障包装成 418+provider_error）与 5xx → 瞬时
    - 其余 4xx 带 provider_error（"Error in upstream response"）→ 瞬时
    """
    detail = detail or ""
    if code in (401, 403, 429):
        return False        # 凭证/频控各自有专门处理路径，不属瞬时重试类
    if any(m in detail for m in _CLIENT_FAULT_MARKERS):
        return False
    if code in TRANSIENT_HTTP_CODES or code >= 500:
        return True
    if 400 <= code < 500 and "provider_error" in detail:
        return True
    return False


def _is_transient_transport(exc):
    """传输层瞬时故障（对 qoder.sh 的 TLS/连接抖动很常见）：可同账号重试。

    覆盖 SSL EOF/重置、连接重置/中止、超时、以及 URLError 包装的上述原因
    （含按字符串描述判断的情形，如 "SSL: UNEXPECTED_EOF_WHILE_READING"）。
    """
    if isinstance(exc, urllib.error.URLError):
        return _is_transient_transport(getattr(exc, "reason", None))
    if isinstance(exc, (ssl.SSLError, ConnectionResetError,
                        ConnectionAbortedError, TimeoutError,
                        ConnectionError, OSError)):
        return True
    if isinstance(exc, str):
        low = exc.lower()
        return any(k in low for k in ("ssl", "eof", "reset", "timed out",
                                      "broken pipe", "connection"))
    return False


def friendly_upstream_error(code, detail):
    """把上游错误转成对客户端可读的消息；瞬时故障给出重试指引。

    返回 (message, err_type)。
    """
    detail = (detail or "").strip()
    try:
        code_i = int(code)
    except Exception:
        code_i = 502
    # 0) 账号额度耗尽（110/112）：确定性、账号级；网关会换号，若持续出现
    #    说明池内额度已集体用尽。绝不能落到下面的 "provider_error" 瞬时分支
    #    （那是"稍后重试"，会误导客户端把额度问题当抖动反复重试）。
    if qoder_accounts.quota_exhausted(detail):
        return ("本账号额度已耗尽 (上游 %s)：网关已自动换用其它账号。若持续出现，"
                "说明池内账号当日额度均已用尽，请等待次日额度重置或补充账号。"
                "上游详情：%s" % (code_i, detail[:300]),
                "account_quota_exhausted")
    # 1) 上游内容安全审核（确定性拒绝，先于瞬时判断——重试无效）
    if any(m in detail for m in _CONTENT_POLICY_MARKERS):
        return ("上游内容安全审核未通过 (DataInspectionFailed)：输入可能含不当内容，"
                "属确定性拒绝、重试无效。请检查/缩短输入（系统提示词、超长历史、"
                "工具定义或粘贴的代码/文本）后重试。上游详情：%s"
                % detail[:300],
                "content_policy_rejected")
    if _is_transient_upstream(code_i, detail) or (
            "provider_error" in detail and "invalid_" not in detail):
        return ("上游瞬时故障 (HTTP %s)：网关已对同账号自动重试仍失败，"
                "请稍后重试。上游详情：%s"
                % (code_i, detail[:300] or "(无详情)"),
                "upstream_transient_error")
    return ("upstream %s: %s" % (code_i, detail)), "upstream_error"


def _to_int_status(status):
    """信封 statusCodeValue 可能是 int 或 str，统一成 int（失败回 502）。"""
    try:
        return int(status)
    except Exception:
        return 502


def should_retry_envelope(exc, emitted_bytes, attempt):
    """流内错误信封是否值得**重开上游**再试。

    关键前提（access log 记 200 而业务错 418 的根因）：上游先以 HTTP200
    建流，provider 故障以 SSE 信封 statusCodeValue=418 投递——此时 urlopen
    层重试覆盖不到。只要 **尚未向客户端发出任何字节**、未超预算、且错误属
    瞬时类（418/5xx/provider_error，且非客户端参数错），就值得重开。
    """
    if emitted_bytes:
        return False
    detail = getattr(exc, "detail", "") or ""
    # 排队（10605）**不在这里处理**：两个调用方都有专门的 queue 分支负责
    # 等待与预算判定。若此处再返回 True，队列预算耗尽后会从这里用另一个
    # 计数器再重试一轮 —— 曾实测出 (try 4/3)(try 5/3) 的越界重试与重复等待。
    if parse_queue_hint(detail)[0]:
        return False
    # 账号额度耗尽（110/112）：**值得换号重开**。它是账号级、非请求级问题，
    # 换到池中其它账号即可继续服务。曾因 403 早退而直接失败——池里另有 7 个
    # 额度充足的账号却让整个请求报废（实测 2026-10-02 15:54）。
    if qoder_accounts.quota_exhausted(detail):
        return True
    if attempt >= TRANSIENT_MAX_RETRIES:
        return False
    return _is_transient_upstream(_to_int_status(getattr(exc, "status", 502)),
                                  detail)


def aggregate_with_envelope_retry(resp, payload, session_key, realm, model,
                                  holder, account, queue_deadline=None,
                                  abort_conn=None):
    """非流式：流内瞬时错误信封 / 传输抖动 -> 重开上游重新聚合。

    仅用于客户端尚未收到任何字节的非流式路径。返回 (chat_obj, account)：
      - 最终信封错误以 UpstreamStatus 抛出（调用方既有分支处理：记账+友好提示）
      - 重开时 open_upstream 的 RateLimited/HTTPError 记日志后仍以**原信封**
        错误上抛（原错误才是本次请求的真实结果，且其分支已具备友好映射）
      - 传输层瞬时错误（TLS EOF 等）同样触发重开
    传入的 resp 由调用方的 with/finally 关闭；本函数只负责关闭重开的新连接。
    """
    cur = resp
    # 调用方若已有一轮排队预算（handler 的 req_queue_deadline），沿用同一个
    # 截止时间，避免「初开 40s + 信封重开 40s」叠加。
    queue_deadline = queue_deadline or (time.time() + _QUEUE_RETRY_BUDGET)
    try:
        # 上界取三者最大：排队等待、瞬时信封重试、额度换号各自独立计数。
        quota_rot = 0
        for attempt in range(max(_QUEUE_WAIT_MAX,
                                  _QUOTA_ROTATE_MAX) + 1):
            try:
                obj = aggregate_stream(cur, model, None, holder=holder)
                return obj, account
            except UpstreamStatus as exc:
                queued, _qw = parse_queue_hint(exc.detail or "")
                if queued:
                    # 排队：换号优先（别的账号往往没被排队）；预算耗尽后
                    # 以 429 + Retry-After 交给客户端，而不是晦涩的 403。
                    if attempt >= _QUEUE_WAIT_MAX or \
                            time.time() >= queue_deadline:
                        log("upstream queue not released on model '%s' "
                            "(account healthy, not cooling)" % model,
                            level="WARN", tag="chat")
                        raise RateLimited(
                            None, "upstream queue busy for model '%s'" % model,
                            wait=int(queue_backoff_seconds(exc)))
                    nap = queue_backoff_seconds(exc)
                    # 夹到剩余预算内，避免最后一次等待越界超时。
                    nap = max(1, min(nap, int(queue_deadline - time.time())))
                    # 排队是模型级容量门控：同池账号会一起排队，换号拿不到服务
                    # 却会把整池标记成不可用。等待放行后重开，不换号、不标记。
                    log("in-stream queue (10605) on model '%s' (wait %d/%d) "
                        "- waiting %ds"
                        % (model, attempt + 1, _QUEUE_WAIT_MAX, nap),
                        level="WARN", tag="chat")
                    # 等待前先关掉当前流：排队可长达 30s，抱着在途名额睡觉会
                    # 把本号并发额度占满（close 幂等，外层 with 再关一次也安全）。
                    try:
                        cur.close()
                    except Exception:
                        pass
                    if client_disconnected(abort_conn):
                        log("client gone while queued on '%s' - "
                            "abandoning wait" % model,
                            level="WARN", tag="chat")
                        note_client_gone("aggregate.queue")
                        raise exc
                    time.sleep(nap)
                    note_queue_wait(nap, hint=_qw)
                    try:
                        new_resp, account, _ = open_upstream(
                            payload, session_key=session_key,
                            target_realm=realm,
                            queue_deadline=queue_deadline,
                            abort_conn=abort_conn)
                    except Exception as reopen_exc:
                        log("reopen after queue failed: %s"
                            % str(reopen_exc)[:160], level="WARN", tag="chat")
                        # 重开失败时：已是 RateLimited（全池冷却/预算耗尽）直接
                        # 透传；否则原信封是排队错误，也要给**干净的 429 +
                        # Retry-After**，而不是当普通 403 信封抛回客户端 ——
                        # 那是"晦涩 403"（本函数注释承诺要避免），客户端学不到
                        # 该退避，且会立刻重试（重试放大器）。
                        if isinstance(reopen_exc, RateLimited):
                            raise reopen_exc
                        raise RateLimited(
                            None, "upstream queue busy for model '%s'" % model,
                            wait=int(queue_backoff_seconds(exc)))
                    if cur is not resp:
                        try:
                            cur.close()
                        except Exception:
                            pass
                    cur = new_resp
                    continue
                if qoder_accounts.quota_exhausted(exc.detail or ""):
                    # 账号额度耗尽（110/112）：换号重开。额度是账号级状态，
                    # 换号立刻有效；不换号则整个请求报废（池里其它号额度充足）。
                    log("in-stream account quota exhausted (status %s) on "
                        "'%s' - rotating: %s"
                        % (exc.status, account.uid[:8],
                           str(exc.detail)[:120]), level="WARN", tag="chat")
                    note_retry("quota_exhausted", account=account.uid[:8])
                    account.note_quota_exhausted(
                        "HTTP %s %s" % (exc.status, str(exc.detail)[:80]))
                    if session_key and POOL:
                        POOL.affinity.unbind(session_key)
                    if quota_rot >= _QUOTA_ROTATE_MAX:
                        # 轮换预算耗尽（池内额度集体用尽）：429 + Retry-After，
                        # 让客户端按额度重置时间退避，而不是拿 403 盲重试。
                        raise RateLimited(
                            None, "all accounts quota exhausted (110/112) "
                            "for model '%s'" % model,
                            wait=min(3600, int(max(60, (account.quota_until - time.time()) if account is not None else 60))))
                    quota_rot += 1
                    try:
                        new_resp, account, _ = open_upstream(
                            payload, session_key=session_key,
                            target_realm=realm,
                            queue_deadline=queue_deadline,
                            abort_conn=abort_conn)
                    except RateLimited:
                        raise          # 已是规范的 429，直接透传
                    except Exception as reopen_exc:
                        log("reopen after quota exhausted failed: %s"
                            % str(reopen_exc)[:160], level="WARN", tag="chat")
                        raise RateLimited(
                            None, "all accounts quota exhausted (110/112) "
                            "for model '%s'" % model,
                            wait=min(3600, int(max(60, (account.quota_until - time.time()) if account is not None else 60))))
                    if cur is not resp:
                        try:
                            cur.close()
                        except Exception:
                            pass
                    cur = new_resp
                    continue
                if attempt >= TRANSIENT_MAX_RETRIES or not _is_transient_upstream(
                        _to_int_status(exc.status), exc.detail or ""):
                    raise
                log("in-stream envelope status %s on model '%s' "
                    "(try %d/%d), reopening upstream"
                    % (exc.status, model, attempt + 1,
                       TRANSIENT_MAX_RETRIES + 1), level="WARN", tag="chat")
                time.sleep(attempt + 1)
                try:
                    new_resp, account, _ = open_upstream(
                        payload, session_key=session_key, target_realm=realm,
                        queue_deadline=queue_deadline, abort_conn=abort_conn)
                except Exception as reopen_exc:
                    log("reopen after envelope error failed: %s"
                        % str(reopen_exc)[:160], level="WARN", tag="chat")
                    raise exc      # 以原信封错误进入既有处理路径
                if cur is not resp:
                    try:
                        cur.close()
                    except Exception:
                        pass
                cur = new_resp
            except Exception as exc:
                if attempt >= TRANSIENT_MAX_RETRIES or \
                        not _is_transient_transport(exc):
                    raise
                log("in-stream transport error on model '%s' (try %d/%d): "
                    "%s - reopening upstream"
                    % (model, attempt + 1, TRANSIENT_MAX_RETRIES + 1,
                       str(exc)[:120]), level="WARN", tag="chat")
                time.sleep(attempt + 1)
                try:
                    new_resp, account, _ = open_upstream(
                        payload, session_key=session_key, target_realm=realm,
                        queue_deadline=queue_deadline, abort_conn=abort_conn)
                except Exception as reopen_exc:
                    log("reopen after transport error failed: %s"
                        % str(reopen_exc)[:160], level="WARN", tag="chat")
                    raise exc
                if cur is not resp:
                    try:
                        cur.close()
                    except Exception:
                        pass
                cur = new_resp
    finally:
        if cur is not resp:
            try:
                cur.close()
            except Exception:
                pass


class _TrackedResponse(object):
    """包装上游响应：关闭时自动归还账号的并发名额。

    经验③：单号并发上限要真正生效，名额必须在响应消费完毕时归还。用包装
    而非散落在各调用点手工 release，避免"漏一处就永久占名额"（另有超时自愈
    兜底）。除 close/上下文管理外，其余属性/方法全部透传。
    """

    __slots__ = ("_resp", "_account", "_token", "_released")

    def __init__(self, resp, account, token):
        self._resp = resp
        self._account = account
        self._token = token
        self._released = False

    def _release(self):
        if not self._released:
            self._released = True
            try:
                if self._account is not None and self._token:
                    self._account.release(self._token)
            except Exception:
                pass

    def close(self):
        try:
            self._resp.close()
        finally:
            self._release()

    def __enter__(self):
        enter = getattr(self._resp, "__enter__", None)
        if enter is not None:
            enter()
        return self

    def __exit__(self, *exc):
        try:
            exit_ = getattr(self._resp, "__exit__", None)
            if exit_ is not None:
                exit_(*exc)
        finally:
            self._release()
        return False

    def __getattr__(self, name):
        return getattr(self._resp, name)

    def __iter__(self):
        return iter(self._resp)


def open_upstream(payload, session_key=None, target_realm=None,
                  queue_deadline=None, abort_conn=None):
    """构造 COSY 签名请求并打开上游 SSE。返回 (resp, account, encoded)。

    账号轮换规则：
      - 401/403：凭证被拒 -> 冷却该账号（单账号池时短冷却）换号
      - 429    ：模型粒度频控 -> 解析 reset 时间做模型冷却换号
      - 418/5xx/provider_error（瞬时上游故障）-> 同账号快速重试 2 次
                （1s/2s 退避），仍失败短冷却(15s/单账号3s)换号
      - 其他 4xx（含客户端参数错）-> 快速失败，冷却换号，不重试
    全部账号失败后抛 RateLimited 或最后一个错误。
    """
    realm = target_realm or detect_model_realm(payload.get("model")) or CURRENT_REALM
    model = str(payload.get("model") or "")
    model_key = qoder_catalog.resolve_upstream_key(model, realm=realm)

    # 排队等待的**绝对截止时间**。调用方若已在等待循环里（流内信封排队重开），
    # 必须把它的 deadline 传进来 —— 否则每次重开都会新开一轮预算，一次请求的
    # 总等待层层叠加（初开 40s + 信封重开 40s ≈ 80s+，超过常见客户端超时）。
    _qdl = time.time() + _QUEUE_RETRY_BUDGET
    if queue_deadline:
        _qdl = min(_qdl, float(queue_deadline))

    # 模板选号：只为取默认字段值（aliyun_user_type 等随后被真实账号覆写）。
    # 必须用**不推进游标**的访问器：若这里调 pick()，每次请求会推进两次游标
    # （此处一次 + pick_for_session 一次），步长 2 会让偶数号池的新会话只落在
    # 同奇偶的一半账号上，另一半长期空转——正是"谁被用得多谁先死"的成因。
    representative = POOL.representative(realm=realm) if POOL else None
    body_obj = build_qoder_body(payload, representative, model_key, realm=realm)
    encoded = qoder_encode(json.dumps(body_obj, ensure_ascii=False).encode("utf-8"))

    if not session_key:
        session_key = derive_affinity_key(body_obj.get("messages"))
        if session_key and AFFINITY_DEBUG:
            log("affinity: derived %s for %d msgs"
                % (session_key, len(body_obj.get("messages") or [])))

    total = max(1, POOL.count_ready(realm, model=model)) if POOL else 1
    tried = set()
    last_error = None
    last_429 = None
    last_429_detail = ""
    # 全池额度耗尽（110/112）：最后一个此类错误与撞上它的账号，
    # 用于在全部轮换失败后给出 429 + Retry-After（而非无退避提示的 403）。
    last_quota = None
    last_quota_account = None
    waited_cool = False
    # 因上游排队（10605）累计等待的秒数，用于给排队设总预算：
    # 上游要是一直不放行，等满预算就如实报错，不能无限等下去拖死客户端。
    queue_waited = 0
    # 记录"因满员而跳过"的账号数：全部账号只是忙（而非故障）时，不能把它
    # 记成上游失败，否则高负载会把健康池的 failgate streak 喂满（误熔断）。
    at_capacity = 0

    # 额外 +2 次迭代预算：只供“短错误冷却等待续上”使用（正常轮换仍由
    # tried 集合自然终止）。
    for _ in range(total + 2):
        account = POOL.pick_for_session(realm=realm, session_key=session_key,
                                        exclude=tried, model=model) if POOL else None
        if account is None:
            if not waited_cool:
                wait = _short_error_cooldown_wait(realm, model,
                                                  exclude=tried)
                if wait > 0:
                    waited_cool = True
                    log("accounts in short error-cooldown for '%s' "
                        "(%.1fs left) - waiting instead of failing"
                        % (model, wait), level="WARN", tag="chat")
                    time.sleep(wait + 0.25)
                    continue     # 冷却到期后重新 pick，服务该请求
            break
        if account.realm != realm:
            if session_key and POOL:
                POOL.affinity.unbind(session_key)
            continue
        tried.add(account.uid)
        _c = current_ctx()
        if _c is not None:
            if _c.account and _c.account != account.uid:
                _c.switches += 1
                note_retry("switch", frm=_c.account[:8], to=account.uid[:8])
            _c.account = account.uid
        # 身份相关的 aliyun_user_type 需要真实账号
        slot = account.try_acquire()
        if slot is None:
            at_capacity += 1
            log("account %s at capacity (%s), trying another"
                % (account.uid[:8], account.load_stats()), tag="chat")
            continue
        # 占名额之后的准备代码若抛异常，必须归还名额——否则该账号会被这个
        # 泄漏的 token 占用到 660s 自愈为止（cap=2 时两次即饿死）。
        try:
            # 身份相关的 aliyun_user_type 需要真实账号
            body_obj["aliyun_user_type"] = account.user_type or \
                qoder_sign.DEFAULT_USER_TYPE
            encoded = qoder_encode(
                json.dumps(body_obj, ensure_ascii=False).encode("utf-8"))
            cfg = get_realm_config(account.realm)
            raw_url = cfg["gateway"] + CHAT_PATH
        except Exception:
            account.release(slot)
            raise

        # ---- 发起请求（瞬时上游故障同账号快速重试） ----
        resp = None
        last_exc = None
        detail = ""
        # 排队等待与瞬时重试**各自计数**：曾共用同一个 `tries`，排队会把
        # 瞬时重试的次数吃掉，而 range 只有 TRANSIENT_MAX_RETRIES+1=3 次
        # 迭代 —— 排队预算再大也会在 ~3s 后放弃（实测：300s 预算实际只等
        # 3.1s）。循环预算 = 两者之和 + 余量。
        transient_tries = 0
        queue_waits = 0
        for _ in range(TRANSIENT_MAX_RETRIES + _QUEUE_WAIT_MAX + 2):
            try:
                note_attempt()
                sess = SESSIONS.get(account)
                headers = sess.headers(encoded, raw_url, model_key=model_key,
                                       sse=True)
                headers["User-Agent"] = CLIENT_UA
                chat_url = validate_public_http_url(raw_url)
                req = urllib.request.Request(chat_url,
                                             data=encoded.encode("utf-8"),
                                             method="POST", headers=headers)
                resp = qoder_accounts.open_url(
                    req, timeout=600, **account.egress_kwargs())
                break
            except urllib.error.HTTPError as exc:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
                # 错误体只能读一次：把已读详情挂到异常上，处理器二次 read
                # 会拿到残缺/空内容，统一从 qoder_detail 取。
                try:
                    exc.qoder_detail = detail
                except Exception:
                    pass
                last_exc = exc
                # 上游排队（403 里包着 10605）：等它给的时间再试，不惩罚账号。
                # 必须在下面的 403 早退之前判断 —— 否则排队会被当成「凭证被拒」
                # 去冷却/轮换账号，客户端则直接收到 403 失败（agent 整轮报废）。
                if exc.code == 403:
                    _queued, _wait = parse_queue_hint(detail)
                    _allow = _qdl - time.time()      # 本次请求剩余排队预算
                    if _queued and _allow > 0 and queue_waits < _QUEUE_WAIT_MAX:
                        queue_waits += 1
                        _sleep = min(_wait or 5, _QUEUE_RETRY_CAP)
                        _sleep = min(_sleep, _allow)
                        log("upstream queued on '%s' model '%s' "
                            "(wait %d/%d), waiting %ds before retry"
                            % (account.uid[:8], model, queue_waits,
                               _QUEUE_WAIT_MAX, _sleep),
                            level="WARN", tag="chat")
                        # 等待期间**放掉在途名额**：抱着并发额度睡 30s，会让
                        # 本号在别的请求眼里变成 "at capacity" 而被换号，
                        # 一个排队请求就能把整号的并发额度占满。
                        account.release(slot)
                        if client_disconnected(abort_conn):
                            log("client gone while queued on '%s' - "
                                "abandoning wait (no upstream retries)"
                                % model, level="WARN", tag="chat")
                            note_client_gone("open_upstream.queue")
                            break
                        time.sleep(_sleep)
                        queue_waited += _sleep
                        note_queue_wait(_sleep, hint=_wait)
                        slot = account.try_acquire()
                        if slot is None:
                            break        # 名额已被别的请求占用，交给客户端稍后重试
                        continue
                # 429/401/403 与客户端参数错：立即进入分类，不重试
                if exc.code in (429, 401, 403):
                    break
                if _is_transient_upstream(exc.code, detail) \
                        and transient_tries < TRANSIENT_MAX_RETRIES:
                    transient_tries += 1
                    backoff = transient_tries    # 1s, 2s
                    log("transient upstream HTTP %d on '%s' model '%s' "
                        "(try %d/%d), retry in %ds"
                        % (exc.code, account.uid[:8], model, transient_tries,
                           TRANSIENT_MAX_RETRIES, backoff),
                        level="WARN", tag="chat")
                    note_retry("http_%d" % exc.code, account=account.uid[:8],
                               backoff_s=backoff)
                    time.sleep(backoff)
                    continue
                break
            except Exception as exc:
                last_exc = exc
                detail = ""
                # 传输层瞬时故障（TLS EOF / 连接重置 / 超时）同样原地重试
                if _is_transient_transport(exc) \
                        and transient_tries < TRANSIENT_MAX_RETRIES:
                    transient_tries += 1
                    backoff = transient_tries    # 1s, 2s
                    log("transient transport error on '%s' model '%s' "
                        "(try %d/%d): %s - retry in %ds"
                        % (account.uid[:8], model, transient_tries,
                           TRANSIENT_MAX_RETRIES,
                           str(exc)[:120], backoff),
                        level="WARN", tag="chat")
                    note_retry("transport", account=account.uid[:8],
                               detail=str(exc)[:120], backoff_s=backoff)
                    time.sleep(backoff)
                    continue
                break

        if resp is not None:
            account.clear_error(model=model)
            account.clear_session_dead()
            failgate_note_success(realm, model)
            return _TrackedResponse(resp, account, slot), account, encoded
        # 本账号失败：归还名额（成功路径由 _TrackedResponse 在关闭时归还）
        account.release(slot)

        exc = last_exc
        # ---- 错误分类（与原有轮换语义一致） ----
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code == 429:
                account.note_error("HTTP 429 (model throttled)", model=model,
                                   cooldown=60)
                log("account %s throttled on '%s' (429), retry in 60s"
                    % (account.uid[:8], model))
                if session_key and POOL:
                    POOL.affinity.unbind(session_key)
                last_error = exc
                last_429 = exc
                last_429_detail = detail
                continue
            # 账号额度耗尽（110/112）：与请求无关，换号即可继续。先给该号打
            # 跨日冷却（下次 pick 自然跳过），再轮换 —— 否则每个请求都会再撞
            # 一次同样的 403，白白浪费一次上游往返。
            if qoder_accounts.quota_exhausted(detail):
                log("account %s quota exhausted (HTTP %s) - rotating: %s"
                    % (account.uid[:8], exc.code, detail[:120]),
                    level="WARN", tag="chat")
                note_retry("quota_exhausted", account=account.uid[:8])
                account.note_quota_exhausted(
                    "HTTP %s %s" % (exc.code, detail[:80]))
                if session_key and POOL:
                    POOL.affinity.unbind(session_key)
                slot = None          # 名额已在上方释放，避免误用陈旧 token
                last_error = exc
                last_quota = exc
                last_quota_account = account
                continue
            if exc.code == 403:
                # 排队等到预算耗尽：账号没问题，别冷却它，给客户端一个明确的
                # 「稍后重试」而不是晦涩的 403（agent 侧可据此自动重试）。
                _queued, _wait = parse_queue_hint(detail)
                if _queued:
                    log("upstream queue not released after %ds on '%s' "
                        "model '%s' (account healthy, not cooling)"
                        % (queue_waited, account.uid[:8], model),
                        level="WARN", tag="chat")
                    account.release(slot)
                    slot = None
                    raise RateLimited(
                        None, "upstream queue busy for model '%s'" % model,
                        wait=max(5, _wait or 30))
            if exc.code in (401, 403):
                log("account %s rejected (HTTP %s), rotating"
                    % (account.uid[:8], exc.code))
                if session_key and POOL:
                    POOL.affinity.unbind(session_key)
                dead = qoder_accounts.session_dead(detail)
                account.note_error("HTTP %s %s" % (exc.code, detail[:80]),
                                   cooldown=300 if dead else 60,
                                   single_account=(total <= 1))
                if dead:
                    # 不可逆处置需多次证据（经验⑤）：先冷却，连续 N 次才禁用。
                    if account.note_session_dead():
                        account.enabled = False
                        if account.path:
                            account.save(ACCOUNTS_DIR)
                        log("account %s session dead x%d (>=%d) - disabled"
                            % (account.uid[:8], account.session_dead_streak,
                               qoder_accounts.SESSION_DEAD_THRESHOLD),
                            level="ERROR")
                    else:
                        log("account %s session-dead evidence %d/%d - "
                            "cooling instead of disabling"
                            % (account.uid[:8], account.session_dead_streak,
                               qoder_accounts.SESSION_DEAD_THRESHOLD),
                            level="WARN")
                last_error = exc
                continue
            if _is_transient_upstream(exc.code, detail):
                # 重试后仍是瞬时故障：上游侧问题，短冷却换号（不重罚账号）。
                # 经验⑥：瞬时/上游故障**不**解绑会话亲和——否则一次传输抖动
                # 就把整段对话打散到别的账号，制造对话级账号漂移。
                account.note_error(
                    "HTTP %s upstream transient: %s" % (exc.code, detail[:80]),
                    cooldown=15, single_account=(total <= 1))
                log("upstream still transient (HTTP %d) after %d tries on "
                    "'%s' - short cooldown, rotating"
                    % (exc.code, TRANSIENT_MAX_RETRIES + 1, account.uid[:8]),
                    level="WARN", tag="chat")
                last_error = exc
                continue
            # 其他 4xx（客户端参数/请求形态问题）：快速失败，冷却换号。
            # 客户端自身错误也**不**解绑亲和——参数写错的客户端不该被逐轮
            # 打散到不同账号（经验⑥）。
            if 400 <= exc.code < 500:
                account.note_error("HTTP %s: %s" % (exc.code, detail[:80]),
                                   cooldown=60, single_account=(total <= 1))
                last_error = exc
                continue
            raise
        else:
            if exc is not None:
                if _is_transient_transport(exc):
                    # 传输抖动重试耗尽：短冷却换号（不重罚账号、不解绑亲和）
                    account.note_error("transport transient: %s" % str(exc)[:100],
                                       cooldown=15, single_account=(total <= 1))
                    log("upstream transport still failing after %d tries on "
                        "'%s' - short cooldown"
                        % (TRANSIENT_MAX_RETRIES + 1, account.uid[:8]),
                        level="WARN", tag="chat")
                else:
                    account.note_error(str(exc)[:120], cooldown=60,
                                       single_account=(total <= 1))
                last_error = exc
            continue

    if last_error is not None:
        opened = failgate_note_failure(realm, model)
        if opened:
            log("failgate open for %s|%s: %d consecutive failures, "
                "backing off %.0fs"
                % (realm, model, FAILGATE_THRESHOLD, opened),
                level="WARN", tag="chat")
        if last_429 is not None:
            raise RateLimited(last_429, last_429_detail,
                              wait=retry_after_seconds(model, realm))
        # 全池额度耗尽：403 无退避提示会让客户端盲重试（实测 Reconnecting 1/5）。
        # 额度按自然日重置，故按该账号的 quota_until 给出明确的 Retry-After。
        if last_quota is not None:
            wait = 60
            if last_quota_account is not None:
                wait = int(max(60, last_quota_account.quota_until - time.time()))
            raise RateLimited(
                last_quota,
                "all accounts quota exhausted (110/112) for model '%s'" % model,
                wait=min(wait, 3600))
        raise last_error
    throttled, wait = realm_model_throttled(realm, model)
    if throttled:
        raise RateLimited(None, "usage exceeds frequency limit", wait=wait)
    # 全部账号只是"忙"（满员）而非故障：返回短 Retry-After，**不喂 failgate**。
    # 否则高并发会把健康池记成连续失败，误熔断整个模型。
    if at_capacity:
        raise RateLimited(None, "all accounts at capacity",
                          wait=min(5, max(1, at_capacity)))
    # 全池都被额度耗尽排除（110/112）：这不是"账号不可用"，而是"额度要等重置"。
    # 必须给 429 + Retry-After —— 落到下面的 RuntimeError 会变成 503
    # "no usable account"，客户端据此以为池子坏了并立刻重试（实测 Reconnecting 1/5）。
    _q_soonest = None
    if POOL:
        _now = time.time()
        for _a in POOL.accounts:
            if _a.realm == realm and _a.quota_until > _now:
                _q_soonest = (_a.quota_until if _q_soonest is None
                              else min(_q_soonest, _a.quota_until))
    if _q_soonest is not None:
        raise RateLimited(
            None, "all accounts quota exhausted (110/112) for model '%s'"
            % model,
            wait=min(3600, int(max(60, _q_soonest - time.time()))))
    opened = failgate_note_failure(realm, model)
    if opened:
        raise RateLimited(None, "no usable account (failgate open)", wait=opened)
    raise RuntimeError(
        "no usable account for realm '%s': all are disabled, cooling down, or expired"
        % realm)


# ---------------------------------------------------------------------------
# 上游 SSE 帧重组（社区实测：Qoder 网关会把一帧从 JSON 中间切断）
# ---------------------------------------------------------------------------
# agent 端点与 api2-v2 都实测到：约 3% 的事件被从 JSON 中间切断、注入裸换行，
# 续行可能没有 `data:` 前缀，甚至切在 `data:` 前缀内部（`data\n: {...}`）。
# 逐行读取时半截 JSON 解析失败 -> 整帧被静默丢弃；丢的若是带 id/name 的工具头
# 帧，客户端只剩参数增量，报 "tool call delta is missing id or name"。
# 参考实现：zenodinh/pi-provider-qoder#12（按空行分块、块内行先拼接再剥 data:
# 前缀 —— 依据是「合法 JSON 里不可能出现裸换行」，故块内拼接必须**无分隔符**）、
# saulgoodgirl/QoderGateway#12（载荷解析不了就缓存拼续行，始终闭合不了则丢弃）。
_SSE_BLOCK_MAX = 1024 * 1024        # 单块缓存上限：超限 fail-open，绝不无限缓存


def _sse_noise_line(line):
    """与载荷无关的帧行（注释/心跳、事件名、id/retry 提示）。"""
    t = (line or "").lstrip()
    return (not t or t.startswith(":")
            or t.startswith("event:") or t.startswith("id:")
            or t.startswith("retry:"))


def _sse_payload_ok(line):
    """这一行单独就是一条完整可用的数据帧？（JSON 载荷 / [DONE] / 心跳）"""
    data = strip_data_prefix(line)
    if not data or data == "[DONE]":
        return True
    try:
        json.loads(data)
        return True
    except Exception:
        return False


def _iter_sse_raw_lines(resp):
    """按**字节流**语义切行：跨 item 续接半行，保留真正的空行分隔符。

    不能对每个 item 直接 rstrip/split：行迭代器的切分点不可控，一个 item 里
    可能含多行、也可能是没有换行结尾的半行；item 末尾的那个 "\\n" 不产生
    空行（空行只在两个 "\\n" 相邻时才存在）。
    """
    carry = ""
    for raw in resp:
        if isinstance(raw, bytes):
            try:
                text = raw.decode("utf-8")
            except Exception:
                continue
        else:
            text = raw
        parts = (carry + text).split("\n")
        carry = parts.pop()          # 最后一段还没见到换行（可能是空串）
        for line in parts:
            yield line.rstrip("\r")
    if carry:
        yield carry.rstrip("\r")


def _reframe_sse_lines(resp):
    """把上游行流重组成「一帧一行」：断帧按空行分块、块内无分隔符拼接。

    为什么无分隔符：注入的裸换行不在原始载荷里（合法 JSON 不可能含裸换行），
    块内各行按原字节顺序直接相连才是原帧。分块依据是空行（SSE 事件分隔符），
    且**先拼接、后剥前缀**，所以切在 `data:` 前缀内部也能还原。

    解析不了的行不即时透传（半截 JSON 透传下去就是客户端解析失败）：缓存并
    拼后续行；始终闭合不了的按截断语义**丢弃**并记事件日志 —— 流末仍未决、
    超长、或新行自身已是完整帧（旧块再也不会闭合）三种情形都算。
    正常帧（能独立解析）逐行即时放行，不引入额外延迟。
    """
    buf = ""            # 未决块（块内多行已按原字节顺序拼接）
    repaired = 0        # 拼接修复次数
    dropped = 0         # 无法闭合而丢弃的块数
    try:
        for line in _iter_sse_raw_lines(resp):
            if not line.strip():
                # 空行 = 事件分隔符：交出当前块（未闭合的按截断语义丢弃）
                if buf:
                    if _sse_payload_ok(buf):
                        repaired += 1
                        yield buf
                    else:
                        dropped += 1
                        log("incomplete SSE frame dropped (%d chars)"
                            % len(buf), level="WARN", tag="chat")
                    buf = ""
                continue
            if not buf:
                if _sse_noise_line(line) or _sse_payload_ok(line):
                    yield line
                    continue
                buf = line               # 解析不了：先缓存，等续行
                continue
            # 已有未决块。新行自身若是完整数据帧，旧块再也不会闭合 -> 丢弃旧块。
            # 注释/事件名行不算（`data\n: {...}` 这种切在 data: 前缀内部的续行
            # 正是以 ":" 开头，必须当续行拼）。
            if _sse_payload_ok(line) and not _sse_noise_line(line):
                dropped += 1
                log("incomplete SSE frame dropped (%d chars)" % len(buf),
                    level="WARN", tag="chat")
                buf = ""
                yield line
                continue
            cand = buf + line
            if len(cand) > _SSE_BLOCK_MAX:
                dropped += 1
                log("oversized SSE frame dropped (%d chars)" % len(cand),
                    level="WARN", tag="chat")
                buf = ""
                continue
            buf = cand
            if _sse_payload_ok(buf):
                repaired += 1
                yield buf
                buf = ""
        if buf:
            if _sse_payload_ok(buf):
                # 流末刚好缺一个空行：块本身是完整帧，照常交出
                repaired += 1
                yield buf
            else:
                # 流末仍未决：按截断语义丢弃（半截 JSON 绝不透传）
                dropped += 1
                log("incomplete SSE frame dropped at end of stream (%d chars)"
                    % len(buf), level="WARN", tag="chat")
    finally:
        # 计数必须走 finally：下游 iter_inner_sse 见到 [DONE] 就 break，
        # 生成器被 close()（GeneratorExit），走不到函数末尾。
        if repaired or dropped:
            _write_event("sse.reframe", repaired=repaired, dropped=dropped)


def iter_inner_sse(resp, holder=None):
    """把上游 SSE 信封流解包成标准 OpenAI chunk 的 "data: ..." 行。

    上游帧形态：
        data:{"headers":{...},"body":"<内层 OpenAI chunk JSON 字符串>","statusCodeValue":200}
        data:{"body":"[DONE]"}
        event:finish{...}          <- 计时元数据，忽略

    规则：
      - statusCodeValue != 200 -> 抛 UpstreamStatus（body 为错误详情）
      - body == "[DONE]"       -> 结束迭代
      - 内层 chunk 里的 usage 记入 holder
      - 行先经 _reframe_sse_lines 重组（上游会把一帧从 JSON 中间切断）
    """
    for line in _reframe_sse_lines(resp):
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except Exception:
                continue
        data = strip_data_prefix(line)
        if not data:
            continue
        try:
            outer = json.loads(data)
        except Exception:
            continue
        if not isinstance(outer, dict):
            continue
        status = outer.get("statusCodeValue")
        body = outer.get("body")
        if status not in (None, 200, "200"):
            raise UpstreamStatus(status, body if isinstance(body, str)
                                 else json.dumps(outer, ensure_ascii=False)[:400])
        if not isinstance(body, str):
            continue
        if body == "[DONE]":
            break
        try:
            inner = json.loads(body)
        except Exception:
            continue
        if holder is not None:
            if inner.get("usage") and not holder.get("usage"):
                holder["usage"] = inner["usage"]
            # 拒绝原因与原始 finish_reason 必须留痕：它们不随 usage 出现，
            # 而拒绝类响应往往没有 usage 块。
            # 逐项 isinstance 守卫：畸形帧（choices 非 list / choice 非 dict /
            # delta 非 dict / refusal 非 str）一律跳过而非抛异常 —— 本层在
            # iter_inner_sse 内，抛异常会中断整条流（HEAD 会原样透传该帧）。
            _chs = inner.get("choices")
            if not isinstance(_chs, list):
                _chs = []
            for _ch in _chs:
                if not isinstance(_ch, dict):
                    continue
                _d = _ch.get("delta")
                if not isinstance(_d, dict):
                    _d = {}
                _rf = _d.get("refusal")
                if isinstance(_rf, str) and _rf:
                    holder["refusal"] = (
                        holder.get("refusal") or "") + _rf
                _fr = _ch.get("finish_reason")
                if _fr:
                    # 落盘口径：finish_reason 记**归一后**的值（与客户端所见一致），
                    # 原始值另存 finish_reason_raw。否则上游给 max_tokens 这类
                    # 别名时，看板会把「被截断」统计成普通结束（审查 S2）。
                    holder["finish_reason"] = normalize_finish_reason(_fr)
                    holder["finish_reason_raw"] = _fr
                    # 规范外值在此一次性留痕（此处才有 model 与累计 refusal）。
                    if _fr not in _VALID_FINISH:
                        try:
                            _write_event(
                                "finish_reason.mapped", raw=str(_fr)[:60],
                                mapped=normalize_finish_reason(_fr),
                                model=holder.get("model") or "",
                                refusal=str(holder.get("refusal") or "")[:200])
                        except Exception:
                            pass
        cleaned = clean_chunk(body)
        if not cleaned:
            continue
        yield ("data: " + cleaned + "\n\n").encode("utf-8")


def iter_client_sse(resp, holder=None, custom_names=None,
                    allowed_tool_names=None, inner_lines=None):
    """iter_inner_sse 的转发层：对 tool_calls 分片做**截断防护**后逐帧下发。

    为什么必须缓冲：SSE 分片一旦写出就无法撤回，而 arguments 是否完整只有到
    收尾才能判定。直接透传时，半截 JSON 会进入客户端的累积 buffer，客户端在
    流结束时严格解析失败（实测报错 `Tool call arguments are not valid JSON.
    Parse Error: Unterminated string`）并卡死会话。

    策略：tool_calls 分片按 index 缓冲，遇到 finish_reason 或流结束时统一决定
      - 拼接后 arguments 可解析 -> 按原顺序补发（内容与直接透传等价，仅到达
        时间推迟到收尾）；
      - 不可解析 -> 丢弃该 index 的全部分片（**不**补成 `{}` 伪造合法外观）。
    content / reasoning / role 等帧仍即时透传，流式体验不受影响。

    覆盖场景：`finish_reason==length`、上游断连、以及**任何**没有 finish_reason
    就结束的流 —— 判定只看「拼出的参数能否解析」，不依赖 finish_reason 取值。

    allowed_tool_names（DSML 兜底，与 /v1/responses 对齐）：客户端声明了工具
    名单时，模型若把调用写成 DeepSeek 风格的 `<｜DSML｜calls>` 文本而非结构化
    tool_calls，则在流收尾把该文本转成 tool_calls 分片下发（**仅当**解析出的
    invoke 名全在名单内）。content 在 DSML 起始候选之前即时透传，候选之后暂存
    到收尾；默认 None = 不做兜底（旧调用方行为不变）。

    inner_lines：已解包的上游 chunk 行迭代器（iter_inner_sse 的输出，可能已被
    recover_leaked_tool_calls 过滤）。给定时不再从 resp 解包 —— 泄漏回读必须
    在**本层之前**接上，这样它还原出的 tool_calls 同样过本层的截断校验与
    白名单；否则同一份上游流会被解包两次（内层 chunk 被当信封解析）。
    """
    buf = {}        # index -> [(line_bytes, args_fragment), ...]
    order = []      # index 首次出现顺序
    names = {}      # index -> 工具名（判定 custom freeform 用）
    dsml_names = set(allowed_tool_names or ())
    dsml_on = bool(dsml_names)      # 无声明工具 -> 不做 DSML 兜底
    tc_emitted = False              # 本轮是否已向客户端下发结构化 tool_calls
    dsml_pending = ""               # "<" 起、尚未确认的起始候选（暂存）
    dsml_mode = False               # 已确认起始标签，进入 DSML 累积模式
    dsml_buf = ""                   # 累积的 DSML 文本块（含起始标签）
    # 补发帧的信封：沿用上游最近一帧的 id/object/created/model（客户端按帧
    # 累积，缺字段会解析失败）。
    meta = {"id": "chatcmpl-qoder", "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": (holder or {}).get("model") or ""}

    def _chunk_frame(delta, finish=None):
        frame = dict(meta)
        frame["object"] = "chat.completion.chunk"   # 上游若是非 chunk 形态也纠正
        frame["choices"] = [{"index": 0, "delta": delta,
                             "finish_reason": finish}]
        return ("data: " + json.dumps(frame, ensure_ascii=False)
                + "\n\n").encode("utf-8")

    def _feed_content(piece):
        """喂入一段 content，返回**可立即下发**的普通文本。

        增量匹配器只做前缀相容判定：不相容立即补发（普通文本里的 "<" 最多
        延迟一个片段，不会被长期扣留）；相容则暂存等后续字符；起始标签一旦
        完整，转入累积模式 —— 该轮后续 content 全部暂存，收尾统一转换/补发。
        """
        nonlocal dsml_pending, dsml_mode, dsml_buf
        out = []
        while piece:
            if dsml_mode:
                dsml_buf += piece
                return "".join(out)
            if dsml_pending:
                dsml_pending += piece
                state = _dsml_open_state(dsml_pending)
                if state == "match":
                    dsml_mode = True
                    dsml_buf += dsml_pending
                    dsml_pending = ""
                elif state == "no":
                    out.append(dsml_pending)
                    dsml_pending = ""
                return "".join(out)
            idx = piece.find("<")
            if idx == -1:
                out.append(piece)
                return "".join(out)
            if idx:
                out.append(piece[:idx])
            piece = piece[idx:]
            state = _dsml_open_state(piece)
            if state == "match":
                dsml_mode = True
                dsml_buf += piece
                piece = ""
            elif state == "no":
                out.append(piece)
                piece = ""
            else:
                dsml_pending = piece
                piece = ""
        return "".join(out)

    def _dsml_finalize(convert=True):
        """DSML 暂存收尾：返回 (补发帧, 是否转成了 tool_calls)。

        convert=False（异常中断路径）只按普通文本补发 —— 断流时不再把文本
        当可信调用下发。本轮已有结构化 tool_calls 时同样只补文本。
        """
        nonlocal dsml_pending, dsml_mode, dsml_buf
        text = dsml_buf + dsml_pending
        dsml_buf, dsml_pending, dsml_mode = "", "", False
        if not text:
            return [], False
        if convert and not tc_emitted:
            calls, clean = parse_dsml_tool_calls(text)
            if calls and all((c.get("name") or "") in dsml_names
                             for c in calls):
                frames = []
                if clean:
                    frames.append(_chunk_frame({"content": clean}))
                for i, c in enumerate(calls):
                    frames.append(_chunk_frame({"tool_calls": [
                        {"index": i, "id": c.get("id") or _new_id("call_"),
                         "type": "function",
                         "function": {"name": c.get("name") or "",
                                      "arguments": ""}}]}))
                    frames.append(_chunk_frame({"tool_calls": [
                        {"index": i, "function": {
                            "arguments": c.get("arguments") or "{}"}}]}))
                log("DSML fallback: %d tool call(s) recovered from content"
                    % len(calls), tag="chat")
                return frames, True
        # 未命中（无块 / 名字不在客户端声明的工具集内）：原文补发，不吞内容
        return [_chunk_frame({"content": text})], False

    def _flush():
        """补发缓冲的 tool_calls 分片（逐 index 判定完整性）。"""
        nonlocal tc_emitted
        out = []
        for idx in order:
            frames = buf.get(idx) or []
            if not frames:
                continue
            # custom freeform 工具的载荷本就是自由文本（非 JSON），不能按
            # 「能否解析为 JSON」判截断 —— 否则会误杀合法调用。
            if names.get(idx) in (custom_names or ()):
                out.extend(ln for ln, _ in frames)
                continue
            args = "".join(a for _, a in frames)
            if is_truncated_arguments(args):
                log("dropped truncated tool_call (index %s) before client: "
                    "arguments is not valid JSON (stream cut short)"
                    % idx, level="WARN", tag="chat")
                _flush.dropped = True
                continue
            out.extend(ln for ln, _ in frames)
        buf.clear()
        del order[:]
        names.clear()
        if out:
            tc_emitted = True
        return out

    _flush.dropped = False

    _src = (inner_lines if inner_lines is not None
            else iter_inner_sse(resp, holder=holder))
    try:
        for line in _src:
            try:
                _txt = line.decode("utf-8", "replace")
                _data = strip_data_prefix(_txt)
                obj = json.loads(_data) if _data else None
            except Exception:
                obj = None
            # 畸形帧（choices 非 list / delta 非 dict 等）一律原样透传，绝不因
            # 解析假设抛出 —— 本层是新增代码面，必须比旧路径更稳。
            if not isinstance(obj, dict) or not isinstance(obj.get("choices"), list):
                yield line
                continue
            for _k in ("id", "object", "created", "model"):
                if obj.get(_k) is not None:
                    meta[_k] = obj[_k]
            _chs = obj.get("choices") or []
            choice = _chs[0] if _chs and isinstance(_chs[0], dict) else {}
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                yield line
                continue
            _fr = choice.get("finish_reason")
            _strip_tcs = False
            tcs = delta.get("tool_calls")
            if isinstance(tcs, list) and tcs:
                _buffered = False
                for tc in tcs:
                    if not isinstance(tc, dict):
                        continue
                    idx = tc.get("index")
                    if not isinstance(idx, (int, str)):
                        idx = 0
                    _fn = tc.get("function")
                    frag = (_fn or {}).get("arguments") if isinstance(_fn, dict) else ""
                    if not isinstance(frag, str):
                        frag = ""
                    _nm = _fn.get("name") if isinstance(_fn, dict) else ""
                    if idx not in buf:
                        buf[idx] = []
                        order.append(idx)
                    if _nm and idx not in names:
                        names[idx] = _nm      # 首片带 name；用于 custom 判定
                    buf[idx].append((line, frag))
                    _buffered = True
                if not _buffered:
                    yield line
                    continue
                if not _fr:
                    continue
                # 收尾帧自身携带 tool_calls（少见）：稍后剥离该帧的 tool_calls
                # 再补发缓冲 —— 否则同一 index 会下发两遍（追加式客户端会
                # 重复拼接）。
                _strip_tcs = True
            # ---- DSML 兜底：content 起始探测 / 暂存 ----
            _emit = None
            if dsml_on:
                _piece = delta.get("content")
                if isinstance(_piece, str) and _piece:
                    _emit = _feed_content(_piece)
            if _fr:
                # 收尾：先把所有暂存判定并补发，再下发收尾帧（必要时改写）。
                _override = None
                if buf:
                    for _ln in _flush():
                        yield _ln
                    # 本轮有调用因截断被丢弃 -> 收尾帧一律降级为 length（不只是
                    # tool_calls 时）。与非流式路径口径一致：残缺调用意味着这一轮
                    # 不可信，客户端应重试/续写，而非把 stop 当「正常结束」。
                    if _flush.dropped and _fr in ("tool_calls", "stop"):
                        _override = "length"
                if dsml_on and (dsml_mode or dsml_pending):
                    _frames, _converted = _dsml_finalize()
                    for _f in _frames:
                        yield _f
                    if _converted and not _override:
                        _override = "tool_calls"
                if _strip_tcs or _override or (
                        _emit is not None and _emit != _piece):
                    _fixed = json.loads(json.dumps(obj))
                    _c = (_fixed.get("choices") or [{}])[0]
                    if isinstance(_c, dict):
                        if _strip_tcs:
                            (_c.get("delta") or {}).pop("tool_calls", None)
                        if _emit is not None and isinstance(_c.get("delta"), dict):
                            _c["delta"]["content"] = _emit
                        if _override:
                            _c["finish_reason"] = _override
                    yield ("data: " + json.dumps(_fixed, ensure_ascii=False)
                           + "\n\n").encode("utf-8")
                    continue
                yield line
                continue
            # 非收尾帧：content 被裁剪时按裁剪后的内容重建（其余字段原样保留 ——
            # 同一帧可能还带 reasoning_content/refusal，不能整帧丢掉）
            if _emit is not None and _emit != _piece:
                _fixed = json.loads(json.dumps(obj))
                _c = (_fixed.get("choices") or [{}])[0]
                if isinstance(_c, dict) and isinstance(_c.get("delta"), dict):
                    _c["delta"]["content"] = _emit
                yield ("data: " + json.dumps(_fixed, ensure_ascii=False)
                       + "\n\n").encode("utf-8")
                continue
            yield line
    except (UpstreamStatus, GeneratorExit):
        # **控制流异常不得 flush**：
        #  - UpstreamStatus 是排队(10605)/额度/瞬时信封的控制流信号 —— 一旦
        #    先下发缓冲帧，handler 的 emitted 会变 True，于是 in-stream 排队
        #    等待与瞬时重开（should_retry_envelope）双双被关闭。
        #  - GeneratorExit 是生成器关闭信号：此时 yield 会抛
        #    "generator ignored GeneratorExit"，且本就无人消费。
        # 两者直接放行，交由上层按既有语义处理。
        raise
    except BaseException:
        # 上游断连/超时（IncompleteRead、ConnectionReset 等）会把异常抛到这里。
        # 必须先补发缓冲中**完整**的调用再放行异常 —— 否则已完整到达的工具调用
        # 会被整批吞掉（比不做缓冲更差）。残缺的仍按 _flush 的判定丢弃。
        # DSML 暂存同理不能闷掉：中断时只按普通文本补发（不再当可信调用）。
        try:
            for _ln in _flush():
                yield _ln
            if dsml_mode or dsml_pending:
                for _f in _dsml_finalize(convert=False)[0]:
                    yield _f
        except Exception:
            pass
        raise
    # 流正常结束但仍有缓冲（上游没发 finish_reason 就收了）：同样判定后补发。
    if buf:
        for _ln in _flush():
            yield _ln
    if dsml_mode or dsml_pending:
        for _f in _dsml_finalize()[0]:
            yield _f


def aggregate_stream(resp, model, resp_id=None, holder=None, allowed_names=None):
    """把上游信封流折叠成一个非流式 chat.completion 对象。

    allowed_names：本次请求声明的工具名集合（默认取 holder 里的
    allowed_tool_names）；用于「泄漏文本回读」的守卫（见
    parse_leaked_tool_calls）—— 名字不在集合内一律不还原（fail-open）。
    """
    if allowed_names is None:
        allowed_names = (holder or {}).get("allowed_tool_names")
    content, reasoning, refusal, finish = [], [], [], "stop"
    tool_calls_map = {}
    usage = holder.get("usage") if holder else None
    started = time.time()
    first_chunk_at = None
    created = None

    for line in iter_inner_sse(resp, holder=holder):
        data = strip_data_prefix(line.decode("utf-8", "replace"))
        if not data or data == "[DONE]":
            continue
        try:
            chunk = json.loads(data)
        except Exception:
            continue
        if first_chunk_at is None:
            first_chunk_at = time.time()
        if chunk.get("id"):
            resp_id = chunk["id"]
        if chunk.get("model"):
            model = chunk["model"]
        if chunk.get("created"):
            created = chunk["created"]
        if chunk.get("usage"):
            usage = chunk["usage"]
            if holder is not None:
                holder["usage"] = usage
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            if delta.get("content"):
                content.append(delta["content"])
            if delta.get("reasoning_content"):
                reasoning.append(delta["reasoning_content"])
            if delta.get("refusal"):
                refusal.append(delta["refusal"])
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index")
                if idx is None:
                    idx = len(tool_calls_map)
                fn = tc.get("function") or {}
                call_id = tc.get("id")
                fn_name = fn.get("name") or ""
                fn_args = fn.get("arguments") or ""
                if idx not in tool_calls_map:
                    tool_calls_map[idx] = {
                        "id": call_id or _new_id("call_"),
                        "type": tc.get("type") or "function",
                        "function": {"name": fn_name, "arguments": fn_args},
                    }
                else:
                    entry = tool_calls_map[idx]
                    if call_id:
                        entry["id"] = call_id
                    if fn_name:
                        entry["function"]["name"] = \
                            (entry["function"]["name"] or "") + fn_name
                    if fn_args:
                        entry["function"]["arguments"] = \
                            (entry["function"]["arguments"] or "") + fn_args
            fc = delta.get("function_call")
            if fc and isinstance(fc, dict) and fc.get("name"):
                idx = 0
                if idx not in tool_calls_map:
                    tool_calls_map[idx] = {
                        "id": _new_id("call_"),
                        "type": "function",
                        "function": {"name": fc.get("name") or "",
                                     "arguments": fc.get("arguments") or ""},
                    }
                else:
                    entry = tool_calls_map[idx]
                    if fc.get("name") and not entry["function"]["name"]:
                        entry["function"]["name"] = fc["name"]
                    if fc.get("arguments"):
                        entry["function"]["arguments"] += fc["arguments"]
            if choice.get("finish_reason"):
                finish = normalize_finish_reason(
                    choice["finish_reason"], model=model,
                    refusal="".join(refusal) or None)

    message = {"role": "assistant", "content": "".join(content)}
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    # 保留拒绝原因（OpenAI 的 message.refusal 字段）：丢弃它会让客户端
    # 只看到一句空内容 + 未知 finish_reason，无法知道为何被拒。
    if refusal:
        message["refusal"] = "".join(refusal)
    # 回读（issue #8/#11）：上游未给结构化 tool_calls，但正文恰好是网关内部
    # 协议文本的形态（模型照格式复述）——还原为结构化调用，或按截断语义吞掉，
    # 避免客户端把内部文本当正文显示、本轮调用不执行。判据与流式路径共用同一套
    # （recover_leaked_tool_calls 的收尾分支）；客户端没声明工具时整块跳过
    # （无白名单可校验，fail-open 保留文本）。
    if allowed_names and not tool_calls_map and message.get("content"):
        # issue #16-B1（非流式侧）：正文可能是「散文 + 回声块」。先按标记切分，
        # 散文照常保留，只对标记起的那一段做回读/吞掉判定。
        _head16, _block16 = _find_marker_split(message["content"],
                                               allow_prefix=False)
        _echo_src = _block16 or ""
        if _echo_src:
            _rec, _clean = parse_leaked_tool_calls(_echo_src, allowed_names)
            if _rec:
                message["content"] = _head16 + (_clean or "")
                tool_calls_map = {i: c for i, c in enumerate(_rec)}
            elif _leaked_partial_droppable(_echo_src, allowed_names):
                # issue #9：截断的 marker+JSON 回声不还原、也不透传。
                log("dropped truncated leaked tool-call echo (%d chars) - "
                    "issue #9" % len(_echo_src), level="WARN", tag="chat")
                message["content"] = _head16
            elif _tool_echo_droppable(_echo_src, allowed_names):
                # issue #11：工具结果回声块同样不还原、不透传。
                log("dropped leaked tool-result echo (%d chars) - issue #11"
                    % len(_echo_src), level="WARN", tag="chat")
                message["content"] = _head16
    # 二次防御：剔除「无函数名」的空 tool_call，防止客户端死等
    if tool_calls_map:
        tool_calls_map = {k: v for k, v in tool_calls_map.items()
                          if (v.get("function") or {}).get("name")}
    ordered = []
    dropped_trunc = 0
    if tool_calls_map:
        ordered = [tool_calls_map[k] for k in sorted(tool_calls_map.keys())]
        # 截断防御：arguments 可能是半截 JSON（流被截断 / finish=length / 上游
        # 断连）。原样交给客户端 -> 客户端报 "arguments are not valid JSON:
        # Unterminated string" 并卡死会话。残缺调用**丢弃**（而非补成 {} 伪造
        # 合法外观）。判定只看参数能否解析 —— **不依赖 finish_reason 取值**：
        # 连接中断/超时不会产生 finish_reason 帧，只看 length 会全部漏网。
        _before = len(ordered)
        ordered = drop_truncated_tool_calls(
            ordered, custom_names=(holder or {}).get("custom_names"))
        dropped_trunc = _before - len(ordered)
        if dropped_trunc:
            log("dropped %d truncated tool_call(s) on model '%s' "
                "(arguments not valid JSON, stream cut short)"
                % (dropped_trunc, model), level="WARN", tag="chat")
    if ordered:
        message["tool_calls"] = ordered
        if finish in ("stop", None):
            finish = "tool_calls"
    # DSML 兜底（与 /v1/responses 对齐）：客户端声明了工具，模型却把
    # DeepSeek 风格的 `<｜DSML｜calls>` 文本写进 content（Qoder 语境下常见）
    # —— 不转换的话，客户端只看到一段「像调用却无法执行」的纯文本，且该文本
    # 会进入下一轮上下文诱导模型继续模仿。仅在**本轮没有任何结构化
    # tool_calls**、且解析出的 invoke 名全在客户端声明的工具集内时转换。
    _allowed_names = (holder or {}).get("allowed_tool_names") or ()
    if _allowed_names and not message.get("tool_calls") \
            and "DSML" in (message.get("content") or ""):
        _dsml_calls, _dsml_clean = parse_dsml_tool_calls(message["content"])
        if _dsml_calls and all(
                (c.get("name") or "") in _allowed_names for c in _dsml_calls):
            message["tool_calls"] = [
                {"id": c.get("id") or _new_id("call_"), "type": "function",
                 "function": {"name": c.get("name") or "",
                              "arguments": c.get("arguments") or "{}"}}
                for c in _dsml_calls]
            message["content"] = _dsml_clean or None
            finish = "tool_calls"
            log("DSML fallback: %d tool call(s) recovered from content on "
                "model '%s'" % (len(_dsml_calls), model), tag="chat")
    # finish 口径统一：截断优先（有调用被丢弃 -> 本轮不可信，置 length 让客户端
    # 重试/续写，而不是把它当成「模型只调用了这一个工具」或「正常的空回复」）；
    # 其次，没有任何可下发的调用却报 tool_calls -> 降级为 stop，防止客户端
    # 无限挂起等待工具结果（占位被全部过滤掉 / 上游只给了 finish_reason）。
    if dropped_trunc:
        finish = "length"
    elif not message.get("tool_calls") and finish == "tool_calls":
        finish = "stop"
    out = {
        "id": resp_id or "chatcmpl-qoder",
        "object": "chat.completion",
        "created": created or int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
    }
    if usage:
        out["usage"] = usage
    out["elapsed_ms"] = int((time.time() - started) * 1000)
    out["first_chunk_at"] = first_chunk_at
    return out


# ---------------------------------------------------------------------------
# Responses API (/v1/responses) <-> Chat Completions translation
# ---------------------------------------------------------------------------
def local_ip_addresses():
    """Every non-loopback IPv4 address this machine answers on."""
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found and not ip.startswith("127."):
                found.append(ip)
    except Exception:
        pass
    if not found:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))
            found.append(probe.getsockname()[0])
            probe.close()
        except Exception:
            pass
    return found


def _new_id(prefix):
    return prefix + uuid.uuid4().hex


def _flatten_content(content):
    """Flatten Responses-style content into text, or OpenAI vision parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)
    texts, parts = [], []
    for piece in content:
        if isinstance(piece, str):
            texts.append(piece)
            parts.append({"type": "text", "text": piece})
            continue
        if not isinstance(piece, dict):
            continue
        ptype = piece.get("type") or ""
        if ptype in ("input_text", "output_text", "text", "summary_text"):
            t = piece.get("text") or ""
            texts.append(t)
            parts.append({"type": "text", "text": t})
        elif ptype in ("input_image", "image_url", "image") or "image_url" in piece:
            url = piece.get("image_url") or piece.get("url")
            if isinstance(url, dict):
                url = url.get("url")
            if not url and piece.get("data"):
                mime = piece.get("mimeType") or piece.get("mime_type") or "image/png"
                url = "data:%s;base64,%s" % (mime, piece["data"])
            if url:
                parts.append({"type": "image_url", "image_url": {"url": url}})
    if any(p.get("type") == "image_url" for p in parts):
        return parts          # multimodal: keep structured parts
    return "\n".join(t for t in texts if t)


# ---------------------------------------------------------------------------
# Responses API "custom" (freeform) tools
#
# Codex 等客户端把文件编辑工具声明为 custom freeform tool：
#     {"type": "custom", "name": "apply_patch", "format": {...grammar...}}
# 上游 chat 端点没有 custom 概念 -> 出站降级为单 "input" 字符串参数的
# function tool，入站再还原为 custom_tool_call。否则工具被静默忽略。
# ---------------------------------------------------------------------------
CUSTOM_TOOL_HINT = (
    "This is a freeform tool. Put the COMPLETE raw payload into the single "
    "'input' string parameter, verbatim. Do not wrap it in JSON, do not wrap "
    "it in markdown code fences, do not add commentary."
)


def _is_custom_tool(tool):
    return isinstance(tool, dict) and str(tool.get("type") or "").lower() == "custom"


def custom_tool_names(tools):
    """Names of tools declared as freeform/custom in a Responses request."""
    names = set()
    for t in tools or []:
        if _is_custom_tool(t) and t.get("name"):
            names.add(str(t["name"]))
    return names


def _downgrade_custom_tool(tool):
    """Rewrite a Responses custom tool into a Chat function tool."""
    desc = tool.get("description") or ""
    fmt = tool.get("format") or {}
    extra = ""
    if isinstance(fmt, dict) and fmt.get("definition"):
        extra = "\n\nGrammar:\n" + str(fmt["definition"])
    elif isinstance(fmt, dict) and fmt.get("syntax"):
        extra = "\n\nGrammar syntax: %s" % str(fmt["syntax"])
    return {
        "type": "function",
        "name": tool.get("name") or "",
        "description": (desc + "\n\n" + CUSTOM_TOOL_HINT + extra).strip(),
        "parameters": {
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": "Complete raw payload for this tool, verbatim.",
                }
            },
            "required": ["input"],
        },
    }


def _tools_for_chat(tools):
    """Downgrade custom tools; leave everything else untouched."""
    out = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        out.append(_downgrade_custom_tool(t) if _is_custom_tool(t) else t)
    return out


def _unwrap_custom_input(args):
    """Pull the freeform string back out of an {"input": "..."} argument blob."""
    if not isinstance(args, str):
        return json.dumps(args or "", ensure_ascii=False)
    try:
        parsed = json.loads(args)
    except Exception:
        return args
    if isinstance(parsed, dict):
        val = parsed.get("input")
        if isinstance(val, str):
            return val
        if val is not None:
            return json.dumps(val, ensure_ascii=False)
    if isinstance(parsed, str):
        return parsed
    return args


def responses_to_chat(payload):
    """Translate a Responses API request body into a Chat Completions body."""
    messages = []
    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions.strip():
        messages.append({"role": "system", "content": instructions})
    inp = payload.get("input")
    pending_reasoning = ""
    if isinstance(inp, str):
        messages.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if isinstance(item, str):
                messages.append({"role": "user", "content": item})
                continue
            if not isinstance(item, dict):
                continue
            itype = item.get("type")
            if itype in (None, "message"):
                body = _flatten_content(item.get("content"))
                if body:
                    role = item.get("role") or "user"
                    if role == "developer":
                        role = "system"
                    # 与相邻 function_call 的 assistant 文本合并到同一条，
                    # 避免打断 tool 序列
                    if role == "assistant" and messages \
                            and messages[-1].get("role") == "assistant":
                        prev = messages[-1]
                        if prev.get("content"):
                            prev["content"] = str(prev["content"]) + "\n" + str(body)
                        else:
                            prev["content"] = body
                        if pending_reasoning and "reasoning_content" not in prev:
                            prev["reasoning_content"] = pending_reasoning
                            pending_reasoning = ""
                    else:
                        msg_dict = {"role": role, "content": body}
                        if role == "assistant" and pending_reasoning:
                            msg_dict["reasoning_content"] = pending_reasoning
                            pending_reasoning = ""
                        messages.append(msg_dict)
            elif itype == "reasoning":
                r_text = ""
                summ = item.get("summary")
                if isinstance(summ, list):
                    r_text = "\n".join(p.get("text", "") for p in summ
                                       if isinstance(p, dict) and p.get("text"))
                elif isinstance(summ, str):
                    r_text = summ
                if not r_text:
                    cnt = item.get("content")
                    if isinstance(cnt, str):
                        r_text = cnt
                    elif isinstance(cnt, list):
                        r_text = _flatten_content(cnt)
                if r_text:
                    if messages and messages[-1].get("role") == "assistant":
                        messages[-1]["reasoning_content"] = r_text
                    else:
                        pending_reasoning = r_text
            elif itype == "function_call_output":
                raw_out = item.get("output")
                if isinstance(raw_out, list):
                    content = _flatten_content(raw_out)
                elif isinstance(raw_out, dict):
                    if raw_out.get("type") in ("input_image", "image_url", "image") \
                            or "image_url" in raw_out:
                        content = _flatten_content([raw_out])
                    else:
                        content = json.dumps(raw_out, ensure_ascii=False)
                elif isinstance(raw_out, str):
                    content = raw_out
                else:
                    content = str(raw_out)
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or "",
                    "content": content,
                })
            elif itype == "function_call":
                tc_item = {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": item.get("arguments") or "{}",
                    },
                }
                if messages and messages[-1].get("role") == "assistant":
                    prev = messages[-1]
                    if "tool_calls" in prev:
                        prev["tool_calls"].append(tc_item)
                    else:
                        prev["tool_calls"] = [tc_item]
                    if pending_reasoning and "reasoning_content" not in prev:
                        prev["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                else:
                    msg_dict = {"role": "assistant", "content": "",
                                "tool_calls": [tc_item]}
                    if pending_reasoning:
                        msg_dict["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                    messages.append(msg_dict)
            elif itype == "custom_tool_call":
                raw_input = item.get("input")
                if isinstance(raw_input, (dict, list)):
                    raw_input = json.dumps(raw_input, ensure_ascii=False)
                if not isinstance(raw_input, str):
                    raw_input = "" if raw_input is None else str(raw_input)
                tc_item = {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": json.dumps({"input": raw_input},
                                                ensure_ascii=False),
                    },
                }
                if messages and messages[-1].get("role") == "assistant":
                    prev = messages[-1]
                    if "tool_calls" in prev:
                        prev["tool_calls"].append(tc_item)
                    else:
                        prev["tool_calls"] = [tc_item]
                    if pending_reasoning and "reasoning_content" not in prev:
                        prev["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                else:
                    msg_dict = {"role": "assistant", "content": "",
                                "tool_calls": [tc_item]}
                    if pending_reasoning:
                        msg_dict["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                    messages.append(msg_dict)
            elif itype == "custom_tool_call_output":
                raw_out = item.get("output")
                if isinstance(raw_out, list):
                    content = _flatten_content(raw_out)
                elif isinstance(raw_out, dict):
                    content = json.dumps(raw_out, ensure_ascii=False)
                elif isinstance(raw_out, str):
                    content = raw_out
                else:
                    content = str(raw_out)
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or "",
                    "content": content,
                })
            else:
                # 未知 item 不静默丢弃：丢工具调用会让上游记录不一致
                log("responses: WARNING unhandled input item type=%r keys=%s"
                    % (itype, sorted(item.keys())[:8]))
    chat = {"model": payload.get("model"), "messages": messages}
    for key in ("temperature", "top_p", "seed"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    if payload.get("max_output_tokens") is not None:
        chat["max_tokens"] = payload["max_output_tokens"]
    effort = None
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, dict):
        effort = reasoning.get("effort")
    if not effort:
        effort = payload.get("reasoning_effort")
    if effort:
        chat["reasoning_effort"] = effort
    if payload.get("tools"):
        chat["tools"] = _tools_for_chat(payload["tools"])
    if payload.get("tool_choice"):
        chat["tool_choice"] = payload["tool_choice"]
    if payload.get("parallel_tool_calls") is not None:
        chat["parallel_tool_calls"] = payload["parallel_tool_calls"]
    return chat


# Responses 端点的 status / incomplete_details 映射。refusal 归一后为
# content_filter，必须与 length 一样记为 incomplete —— 否则拒绝会以
# 「空的成功响应」呈现（status=completed、output_text 空），客户端无从归类。
_RESP_INCOMPLETE = {"length": "max_output_tokens",
                    "content_filter": "content_filter"}


def _resp_status(finish):
    return "incomplete" if finish in _RESP_INCOMPLETE else "completed"


def _resp_incomplete_detail(finish):
    _r = _RESP_INCOMPLETE.get(finish)
    return {"reason": _r} if _r else None


def _responses_usage(u):
    if not u:
        return None
    det = u.get("completion_tokens_details") or {}
    pdet = u.get("prompt_tokens_details") or {}
    return {
        "input_tokens": u.get("prompt_tokens") or 0,
        "input_tokens_details": {
            "cached_tokens": u.get("prompt_cache_hit_tokens")
            or det.get("cached_tokens") or pdet.get("cached_tokens") or 0,
        },
        "output_tokens": u.get("completion_tokens") or 0,
        "output_tokens_details": {
            "reasoning_tokens": det.get("reasoning_tokens") or 0},
        "total_tokens": u.get("total_tokens") or 0,
    }


def chat_to_response(chat_obj, model, custom_names=None):
    """Fold a Chat Completions object into a Responses API response object.

    custom_names: the set of tool names the client declared as freeform.
    Calls to those tools are re-inflated into custom_tool_call items so
    clients such as Codex recognise them.
    """
    custom_names = custom_names or set()
    choice = (chat_obj.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    text = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    output = []
    if reasoning:
        output.append({
            "id": _new_id("rs_"),
            "type": "reasoning",
            "status": "completed",
            "summary": [{"type": "summary_text", "text": reasoning}],
        })
    _dropped_trunc = False
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        call_id = tc.get("id") or _new_id("call_")
        name = fn.get("name") or ""
        _is_custom = bool(name) and name in custom_names
        # 截断防御（同流式路径）：arguments 是半截 JSON 时整条丢弃 —— 原样发出
        # 会让客户端解析失败（Unterminated string）。丢弃而非补 "{}"：后者会
        # 伪造「合法空参调用」的外观，客户端会真的去执行它。
        #
        # **custom freeform 工具例外**：其载荷本就是自由文本（网关自己的
        # CUSTOM_TOOL_HINT 就要求模型原样放入 input，`_unwrap_custom_input`
        # 对解析失败的串原样返回）—— 裸文本不是截断，不能误杀。
        if not _is_custom and is_truncated_arguments(fn.get("arguments")):
            log("dropped truncated tool_call '%s' on model '%s' "
                "(arguments not valid JSON)" % (name or "?", model),
                level="WARN", tag="responses")
            _dropped_trunc = True
            continue
        if _is_custom:
            output.append({
                "id": _new_id("ctc_"),
                "type": "custom_tool_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "input": _unwrap_custom_input(fn.get("arguments") or ""),
            })
        else:
            output.append({
                "id": _new_id("fc_"),
                "type": "function_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "arguments": fn.get("arguments") or "{}",
            })
    # DeepSeek DSML 工具调用回退
    if not (msg.get("tool_calls")):
        dsml_calls, clean_t = parse_dsml_tool_calls(text)
        if dsml_calls:
            for dc in dsml_calls:
                output.append({
                    "id": _new_id("fc_"),
                    "type": "function_call",
                    "status": "completed",
                    "call_id": dc.get("id") or _new_id("call_"),
                    "name": dc.get("name") or "",
                    "arguments": dc.get("arguments") or "{}",
                })
            text = clean_t
    if text or not output:
        output.append({
            "id": _new_id("msg_"),
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text,
                         "annotations": []}] if text else [],
        })
    finish = normalize_finish_reason(
        choice.get("finish_reason"), model=model,
        refusal=msg.get("refusal")) or "stop"
    # 本轮有调用因截断被丢弃 -> 整轮不可信，置 length 让 status=incomplete。
    # 否则客户端看到的是「成功的空响应」（status=completed、output_text 空），
    # 无从判断该重试 —— 与流式路径的处置对齐。
    if _dropped_trunc:
        finish = "length"
    # 拒绝也是「未完成」：只把 length 记为 incomplete 会让 refusal 以
    # 「空的成功响应」呈现，客户端无从归类 —— 正是要修的症状。
    _refusal_text = msg.get("refusal") or ""
    if _refusal_text:
        # 把拒绝原因放进 message 项，客户端至少能看到「为何被拒」。
        for _o in output:
            if _o.get("type") == "message" and not _o.get("content"):
                _o["content"] = [{"type": "output_text",
                                  "text": _refusal_text,
                                  "annotations": []}]
    obj = {
        "id": _new_id("resp_"),
        "object": "response",
        "created_at": int(time.time()),
        "status": _resp_status(finish),
        "model": model,
        "output": output,
        "output_text": text or _refusal_text,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "metadata": {},
    }
    u = _responses_usage(chat_obj.get("usage"))
    if u:
        obj["usage"] = u
    _detail = _resp_incomplete_detail(finish)
    if _detail:
        obj["incomplete_details"] = _detail
    return obj


def stream_responses_events(inner_lines, model, holder):
    """Yield Responses-API SSE frames translated from chat-completions chunks.

    inner_lines: 已解包的 "data: {chunk}" 行迭代器（iter_inner_sse 输出）。
    """
    resp_id, msg_id, rs_id = _new_id("resp_"), _new_id("msg_"), _new_id("rs_")
    created = int(time.time())
    seq = 0
    text_parts, reason_parts = [], []
    outputs = []
    reason_index = None
    msg_index = None
    finish = "stop"
    usage = None
    tool_calls_map = {}
    text_buffer = ""
    dsml_tool_calls = []
    custom_names = set(holder.get("custom_names") or ())

    def resp_obj(status):
        obj = {
            "id": resp_id,
            "object": "response",
            "created_at": created,
            "status": status,
            "model": model,
            "output": [o for o in outputs if o],
            "output_text": "".join(text_parts),
            "parallel_tool_calls": True,
            "tool_choice": "auto",
            "tools": [],
            "metadata": {},
        }
        u = _responses_usage(usage)
        if u:
            obj["usage"] = u
        return obj

    def ev(etype, payload_obj):
        nonlocal seq
        seq += 1
        data = {"type": etype, "sequence_number": seq}
        data.update(payload_obj)
        body = json.dumps(data, ensure_ascii=False)
        return ("event: " + etype + "\ndata: " + body + "\n\n").encode("utf-8")

    def reason_item(status):
        return {
            "id": rs_id,
            "type": "reasoning",
            "status": status,
            "summary": [{"type": "summary_text", "text": "".join(reason_parts)}],
        }

    def msg_item(status):
        item = {"id": msg_id, "type": "message", "status": status,
                "role": "assistant", "content": []}
        if text_parts:
            item["content"] = [{"type": "output_text",
                                "text": "".join(text_parts),
                                "annotations": []}]
        return item

    yield ev("response.created", {"response": resp_obj("in_progress")})
    yield ev("response.in_progress", {"response": resp_obj("in_progress")})
    for raw in inner_lines:
        data = strip_data_prefix(raw.decode("utf-8", "replace")
                                 if isinstance(raw, bytes) else raw)
        if not data or data == "[DONE]":
            continue
        try:
            chunk = json.loads(data)
        except Exception:
            continue
        if usage is None and chunk.get("usage"):
            usage = chunk["usage"]
            holder["usage"] = usage
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            piece = delta.get("reasoning_content")
            if piece:
                if reason_index is None:
                    reason_index = len(outputs)
                    outputs.append(None)
                    yield ev("response.output_item.added",
                             {"output_index": reason_index,
                              "item": reason_item("in_progress")})
                    yield ev("response.reasoning_summary_part.added", {
                        "item_id": rs_id, "output_index": reason_index,
                        "summary_index": 0,
                        "part": {"type": "summary_text", "text": ""},
                    })
                reason_parts.append(piece)
                yield ev("response.reasoning_summary_text.delta", {
                    "item_id": rs_id, "output_index": reason_index,
                    "summary_index": 0, "delta": piece,
                })
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                fn = tc.get("function") or {}
                fn_name = fn.get("name") or ""
                fn_args = fn.get("arguments") or ""
                call_id = tc.get("id") or ""
                if idx not in tool_calls_map:
                    out_idx = len(outputs)
                    outputs.append(None)
                    c_id = call_id or _new_id("call_")
                    is_custom = bool(fn_name) and fn_name in custom_names
                    entry = {
                        "output_index": out_idx,
                        "id": c_id,
                        "name": fn_name,
                        "arguments": fn_args,
                        "custom": is_custom,
                        "item_id": _new_id("ctc_" if is_custom else "fc_"),
                    }
                    tool_calls_map[idx] = entry
                    item = {"id": entry["item_id"], "status": "in_progress",
                            "call_id": c_id, "name": fn_name}
                    if is_custom:
                        item["type"] = "custom_tool_call"
                        item["input"] = ""
                    else:
                        item["type"] = "function_call"
                        item["arguments"] = ""
                    yield ev("response.output_item.added",
                             {"output_index": out_idx, "item": item})
                else:
                    entry = tool_calls_map[idx]
                    if fn_name and not entry["name"]:
                        entry["name"] = fn_name
                        if fn_name in custom_names:
                            entry["custom"] = True
                    if fn_args:
                        # **不**即时下发 arguments 分片：SSE 写出即不可撤回，而
                        # 是否截断只有收尾才能判定 —— 半截 JSON 一旦进入客户端的
                        # 累积 buffer，客户端收尾时严格解析失败（实测报错
                        # `Unterminated string`）。故此处只累积，收尾判定完整后
                        # 再补发（见下方"已完成的结构化工具调用"段）。
                        entry["arguments"] += fn_args
            piece = delta.get("content")
            if piece:
                if msg_index is None:
                    if reason_index is not None:
                        full_r = "".join(reason_parts)
                        yield ev("response.reasoning_summary_text.done", {
                            "item_id": rs_id, "output_index": reason_index,
                            "summary_index": 0, "text": full_r,
                        })
                        yield ev("response.reasoning_summary_part.done", {
                            "item_id": rs_id, "output_index": reason_index,
                            "summary_index": 0,
                            "part": {"type": "summary_text", "text": full_r},
                        })
                        outputs[reason_index] = reason_item("completed")
                        yield ev("response.output_item.done",
                                 {"output_index": reason_index,
                                  "item": outputs[reason_index]})
                    msg_index = len(outputs)
                    outputs.append(None)
                    yield ev("response.output_item.added", {
                        "output_index": msg_index,
                        "item": {"id": msg_id, "type": "message",
                                 "status": "in_progress", "role": "assistant",
                                 "content": []},
                    })
                    yield ev("response.content_part.added", {
                        "item_id": msg_id, "output_index": msg_index,
                        "content_index": 0,
                        "part": {"type": "output_text", "text": "",
                                 "annotations": []},
                    })
                # DSML 缓冲：不把原始 DSML 标签流给客户端
                text_buffer += piece
                while text_buffer:
                    idx = text_buffer.find("<")
                    if idx == -1:
                        text_parts.append(text_buffer)
                        yield ev("response.output_text.delta", {
                            "item_id": msg_id, "output_index": msg_index,
                            "content_index": 0, "delta": text_buffer,
                        })
                        text_buffer = ""
                        break
                    m = DSML_CALLS_RE.search(text_buffer)
                    if m and m.start() == idx:
                        if idx > 0:
                            lead = text_buffer[:idx]
                            text_parts.append(lead)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": lead,
                            })
                        calls_found, _ = parse_dsml_tool_calls(m.group(0))
                        if calls_found:
                            dsml_tool_calls.extend(calls_found)
                        text_buffer = text_buffer[m.end():]
                        continue
                    cand = text_buffer[idx:idx + 30]
                    is_cand = ("DSML" in cand) or (
                        len(cand) < 10 and not any(c in cand
                                                   for c in (" ", "\t", "\n", ">")))
                    if is_cand:
                        lead = text_buffer[:idx]
                        text_parts.append(lead)
                        yield ev("response.output_text.delta", {
                            "item_id": msg_id, "output_index": msg_index,
                            "content_index": 0, "delta": lead,
                        })
                        text_buffer = text_buffer[idx:]
                        break
                    else:
                        next_lt = text_buffer[idx + 1:].find("<")
                        if next_lt != -1:
                            flush_len = idx + 1 + next_lt
                            lead = text_buffer[:flush_len]
                            text_parts.append(lead)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": lead,
                            })
                            text_buffer = text_buffer[flush_len:]
                        else:
                            text_parts.append(text_buffer)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": text_buffer,
                            })
                            text_buffer = ""
                            break
            if choice.get("finish_reason"):
                finish = normalize_finish_reason(
                    choice["finish_reason"], model=model,
                    refusal=delta.get("refusal"))
    if reason_index is not None and outputs[reason_index] is None:
        full_r = "".join(reason_parts)
        yield ev("response.reasoning_summary_text.done", {
            "item_id": rs_id, "output_index": reason_index,
            "summary_index": 0, "text": full_r,
        })
        yield ev("response.reasoning_summary_part.done", {
            "item_id": rs_id, "output_index": reason_index,
            "summary_index": 0,
            "part": {"type": "summary_text", "text": full_r},
        })
        outputs[reason_index] = reason_item("completed")
        yield ev("response.output_item.done",
                 {"output_index": reason_index, "item": outputs[reason_index]})
    # 1. 已完成的结构化工具调用
    for idx in sorted(tool_calls_map.keys()):
        entry = tool_calls_map[idx]
        # 截断防御（同 chat 路径）：arguments 可能是半截 JSON，原样发出会让
        # 客户端解析失败并卡死会话。判定只看参数能否解析，**不依赖
        # finish_reason 取值**（断连/超时不会产生 finish_reason 帧）。
        #
        # 注意两点（实测客户端行为）：
        #  1. `output_item.added` 在聚合首片时**已经发出**，所以必须补一个 done
        #     维持配对 —— 否则客户端收到 added 却等不到 done。
        #  2. done 的 item **不能带 `arguments: ""`** —— 客户端把空串解析成 `{}`
        #     后会当成合法空参调用去执行（伪造了「成功」外观）。改为不带
        #     arguments 字段，并让整轮以 incomplete 收尾，客户端据此放弃该轮。
        # **custom freeform 工具例外**：其载荷本就是自由文本（网关的
        # CUSTOM_TOOL_HINT 要求模型原样放入 input），裸文本不是截断。
        if not entry.get("custom") and is_truncated_arguments(
                entry.get("arguments")):
            log("dropped truncated tool_call on model '%s' "
                "(arguments not valid JSON, stream cut short)"
                % model, level="WARN", tag="responses")
            # custom_tool_call 在 OpenAI 规范里**没有 status 字段**（只有
            # function_call 有）。仅 function_call 带 status（审查 S2）。
            _tr_item = {
                "id": entry["item_id"],
                "type": ("custom_tool_call" if entry.get("custom")
                         else "function_call"),
                "call_id": entry["id"],
                "name": entry["name"],
            }
            if not entry.get("custom"):
                _tr_item["status"] = "incomplete"
            outputs[entry["output_index"]] = _tr_item
            yield ev("response.output_item.done",
                     {"output_index": entry["output_index"],
                      "item": _tr_item})
            # 整轮标记为未完成：截断意味着这一轮不可信，客户端应重试而非
            # 执行残缺/空参调用。
            finish = "length"
            continue
        if entry.get("custom"):
            # 分片改为收尾补发（见聚合段的说明）：此处一次性下发完整 input。
            if entry["arguments"]:
                yield ev("response.custom_tool_call_input.delta", {
                    "output_index": entry["output_index"],
                    "item_id": entry["item_id"],
                    "call_id": entry["id"],
                    "delta": entry["arguments"],
                })
            yield ev("response.custom_tool_call_input.done", {
                "output_index": entry["output_index"],
                "item_id": entry["item_id"],
                "call_id": entry["id"],
                "input": _unwrap_custom_input(entry["arguments"]),
            })
            fc_item = {
                "id": entry["item_id"],
                "type": "custom_tool_call",
                "status": "completed",
                "call_id": entry["id"],
                "name": entry["name"],
                "input": _unwrap_custom_input(entry["arguments"]),
            }
        else:
            # 同上：分片在收尾一次性补发，绝不把半截 arguments 提前写出去。
            if entry["arguments"]:
                yield ev("response.function_call_arguments.delta", {
                    "output_index": entry["output_index"],
                    "call_id": entry["id"],
                    "delta": entry["arguments"],
                })
            yield ev("response.function_call_arguments.done", {
                "output_index": entry["output_index"],
                "call_id": entry["id"],
                "arguments": entry["arguments"],
            })
            fc_item = {
                "id": entry["item_id"],
                "type": "function_call",
                "status": "completed",
                "call_id": entry["id"],
                "name": entry["name"],
                "arguments": entry["arguments"],
            }
        outputs[entry["output_index"]] = fc_item
        yield ev("response.output_item.done",
                 {"output_index": entry["output_index"], "item": fc_item})
    # 冲刷剩余缓冲文本
    if text_buffer:
        calls_rem, clean_rem = parse_dsml_tool_calls(text_buffer)
        if calls_rem:
            dsml_tool_calls.extend(calls_rem)
        if clean_rem:
            text_parts.append(clean_rem)
            if msg_index is not None:
                yield ev("response.output_text.delta", {
                    "item_id": msg_id, "output_index": msg_index,
                    "content_index": 0, "delta": clean_rem,
                })
        text_buffer = ""
    # 2. DSML 回退：无结构化工具调用时用解析出的 DSML 调用
    full_text = "".join(text_parts)
    dsml_calls = dsml_tool_calls
    if not dsml_calls:
        extra_calls, clean_text = parse_dsml_tool_calls(full_text)
        if extra_calls:
            dsml_calls = extra_calls
            full_text = clean_text
    if dsml_calls and not tool_calls_map:
        for dc in dsml_calls:
            out_idx = len(outputs)
            fc_item = {
                "id": _new_id("fc_"),
                "type": "function_call",
                "status": "completed",
                "call_id": dc.get("id") or _new_id("call_"),
                "name": dc.get("name") or "",
                "arguments": dc.get("arguments") or "{}",
            }
            outputs.append(fc_item)
            yield ev("response.output_item.added", {
                "output_index": out_idx,
                "item": dict(fc_item, status="in_progress", arguments=""),
            })
            yield ev("response.function_call_arguments.delta", {
                "output_index": out_idx,
                "call_id": fc_item["call_id"],
                "delta": fc_item["arguments"],
            })
            yield ev("response.function_call_arguments.done", {
                "output_index": out_idx,
                "call_id": fc_item["call_id"],
                "arguments": fc_item["arguments"],
            })
            yield ev("response.output_item.done",
                     {"output_index": out_idx, "item": fc_item})
    # 3. 有文本或没有任何输出项时，补 message 项
    has_other_items = any(o for o in outputs if o)
    if msg_index is not None or full_text or not has_other_items:
        if msg_index is None:
            msg_index = len(outputs)
            outputs.append(None)
            yield ev("response.output_item.added", {
                "output_index": msg_index,
                "item": {"id": msg_id, "type": "message",
                         "status": "in_progress", "role": "assistant",
                         "content": []},
            })
            yield ev("response.content_part.added", {
                "item_id": msg_id, "output_index": msg_index,
                "content_index": 0,
                "part": {"type": "output_text", "text": "",
                         "annotations": []},
            })
        yield ev("response.output_text.done", {
            "item_id": msg_id, "output_index": msg_index,
            "content_index": 0, "text": full_text,
        })
        yield ev("response.content_part.done", {
            "item_id": msg_id, "output_index": msg_index,
            "content_index": 0,
            "part": {"type": "output_text", "text": full_text,
                     "annotations": []},
        })
        outputs[msg_index] = msg_item("completed")
        yield ev("response.output_item.done",
                 {"output_index": msg_index, "item": outputs[msg_index]})
    # 同非流式：refusal(content_filter) 也是 incomplete，否则客户端看到
    # 空的成功响应而无法归类。
    status = _resp_status(finish)
    final = resp_obj(status)
    _detail = _resp_incomplete_detail(finish)
    if _detail:
        final["incomplete_details"] = _detail
    yield ev("response.completed", {"response": final})


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Which configured API key the caller used, set by _key_ok(). Its bound
    # realm decides the upstream exit for this request alone.
    key_entry = None

    def handle(self):
        try:
            super(Handler, self).handle()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    def finish(self):
        try:
            super(Handler, self).finish()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    server_version = "qd-proxy/" + VERSION

    def log_message(self, fmt, *args):
        # 静默看板高频轮询的正常 200 GET，异常状态与业务操作照常记录。
        try:
            req_path = (getattr(self, "path", None)
                        or (args[0] if args else "")).split("?")[0]
            if req_path == "/favicon.ico":
                return           # 浏览器自动请求的 404 不刷屏
            status_code = int(args[1]) if len(args) > 1 \
                and str(args[1]).isdigit() else 200
            if status_code < 400 and getattr(self, "command", "GET") == "GET":
                quiet_prefixes = (
                    "/logs", "/usage", "/accounts", "/scheduler",
                    "/health", "/panel/status", "/realm",
                )
                if any(req_path == p or req_path.startswith(p + "/")
                       for p in quiet_prefixes):
                    return
        except Exception:
            pass
        log(fmt % args)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message, err_type="server_error", retry_after=None):
        """错误响应。所有"不可用"类响应都应带 Retry-After。

        经验②：零成本失败 = 无限重试率。必须把"什么时候再来"告诉客户端，
        否则客户端会以亚秒级频率重打，把偶发限流放大成持续滥用。
        """
        if retry_after is None and code in (429, 503):
            retry_after = _clamp_retry_after(retry_after or 5)
        body = json.dumps({"error": {"message": message, "type": err_type,
                                     "code": code,
                                     "retry_after": retry_after}}
                          if retry_after else
                          {"error": {"message": message, "type": err_type,
                                     "code": code}},
                          ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _rate_limited(self, exc):
        """429 with Retry-After, so clients back off instead of hammering."""
        wait = max(1, int(getattr(exc, "wait", 60) or 60))
        body = json.dumps({
            "error": {
                "message": ("upstream rate limit reached for this model; "
                            "retry in %ds" % wait)
                + ((" - " + exc.detail[:200]) if getattr(exc, "detail", "") else ""),
                "type": "rate_limit_error",
                "code": 429,
                "retry_after": wait,
            }
        }, ensure_ascii=False).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(wait))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _download(self, filename, obj):
        """Send a JSON document as a browser download.

        Content-Disposition is quoted because the filename is generated from
        user-controlled parts (the realm filter) and could otherwise break the
        header or allow a response-splitting attempt.
        """
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        safe = re.sub(r'[^A-Za-z0-9._-]', "_", str(filename))[:120] \
            or "export.json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % safe)
        self.send_header("Cache-Control", "no-store")
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _supplied_key(self):
        """The key the caller presented, from the header or the ?key= query."""
        supplied = (self.headers.get("Authorization") or "").removeprefix(
            "Bearer ").strip()
        if supplied:
            return supplied
        # 浏览器顶层导航无法设置头，所以 ?key= 也接受（看板跨设备打开用）。
        try:
            query = parse_qs(urlparse(self.path).query)
            return (query.get("key") or [""])[0].strip()
        except Exception:
            return ""

    def _key_ok(self):
        """True when the request carries a right key (or no key is needed)."""
        # 面板会话同时解锁管理 API，浏览器无需在 localStorage 存 API key。
        if self._panel_ok():
            return True
        self.key_entry = identify_key(self._supplied_key())
        if self.key_entry:
            return True
        if not auth_required():
            return True
        return False

    def _key_realm(self):
        """Realm bound to the key this request used, or "" when unbound."""
        return (self.key_entry or {}).get("realm") or ""

    def _cross_realm_error(self, model, realm):
        """解释模型/出口错配，替代上游晦涩的 403。"""
        if not realm or not model:
            return ""
        owner = exclusive_realm(model)
        if not owner or owner == realm:
            return ""
        name = (self.key_entry or {}).get("name") or "当前 Key"
        served = "国内版" if owner == "cn" else "国际版"
        used = "国内版" if realm == "cn" else "国际版"
        return ("模型 %s 只在%s提供，但「%s」绑定的是%s出口。"
                "请改用对应出口的 Key，或把该 Key 的出口改为「跟随面板切换」。"
                % (model, served, name, used))

    def _request_realm(self, explicit=None):
        """Pick the upstream exit for this request.

        Priority: an explicit ?realm= argument, then the realm bound to the
        API key, then the X-Realm header / ?realm= query, and finally the
        global switch. Returning None lets open_upstream() fall back to
        model-based detection.
        """
        if explicit:
            return explicit
        bound = self._key_realm()
        if bound:
            return bound
        header = self.headers.get("X-Realm")
        if header:
            return header
        try:
            return parse_qs(urlparse(self.path).query).get("realm", [None])[0]
        except Exception:
            return None

    def _authorized(self):
        if self._key_ok():
            return True
        self._error(401, "invalid api key", "invalid_request_error")
        return False

    # ---- web panel access ----
    def _panel_token(self):
        """Session token from the X-Panel-Token header.

        Deliberately header-only: a token in the query string leaks through
        browser history, the Referer header and any reverse-proxy access log.
        """
        return (self.headers.get("X-Panel-Token") or "").strip()

    def _panel_ok(self):
        return PANEL.valid(self._panel_token())

    @staticmethod
    def _is_panel_route(path):
        """Management endpoints shown in the web panel.

        Model listings stay reachable with the API key alone so that plain
        OpenAI clients can keep discovering models.
        """
        if path.startswith("/accounts"):
            return True
        if path.startswith("/usage") or path.startswith("/v1/usage"):
            return True
        if path.startswith("/tasks") or path.startswith("/scheduler"):
            return True
        if path.startswith("/settings"):
            return True
        if path.startswith("/logs"):
            return True
        return False

    def do_OPTIONS(self):
        self.send_response(204)
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if self._is_panel_route(path) and not self._panel_ok():
            return self._error(401, "panel password required",
                               "invalid_request_error")
        if path in ("/", "/dashboard", "/ui"):
            return self._dashboard()
        if path == "/panel/status":
            # 不带 token 也要回答：看板需要先知道是否显示登录页。
            info = {
                "panel_password_required": True,
                "panel_password_is_default":
                    qoder_settings.panel_password_is_default(ACCOUNTS_DIR),
                "authenticated": self._panel_ok(),
            }
            info["api_key_set"] = bool(API_KEY)
            return self._json(200, info)
        if path == "/health":
            rep = current_account()
            info = {
                "ok": True,
                "service": "qoder-proxy",
                "version": VERSION,
                "realm": CURRENT_REALM,
                "accounts": len(POOL.accounts) if POOL else 0,
                "accounts_ready": POOL.count_ready() if POOL else 0,
                "api_key_required": bool(API_KEY),
                # 出口模式：让运维一眼看到当前是直连还是代理（M3）。
                # 默认直连且忽略进程级 *_PROXY，升级后若原依赖 HTTP_PROXY
                # 访问国际区，这里会立刻暴露，而不是靠连接超时排查。
                "egress": qoder_accounts.egress_summary(),
                # TLS 指纹：stdlib-openssl = 未伪装（默认，零依赖）
                "tls": qoder_accounts.tls_summary(),
            }
            if self._key_ok():
                info.update({
                    "uid": rep.uid if rep else None,
                    "domain": rep.domain if rep else None,
                    "issuer": "qoder" if rep else None,
                    "credential_file": os.path.basename(rep.path)
                    if rep and rep.path else None,
                    "expires_at": rep.expires_at if rep else None,
                })
            return self._json(200, info)
        if path == "/realm":
            return self._json(200, {"current": CURRENT_REALM,
                                    "options": ["intl", "cn"]})
        if path in ("/v1/models", "/models"):
            if not self._authorized():
                return
            req_realm = self._request_realm() or CURRENT_REALM
            try:
                entries = fetch_models(realm=req_realm)
            except Exception as exc:
                return self._error(502, str(exc))
            data = [model_entry(mid, meta) for mid, meta in entries]
            return self._json(200, {"object": "list", "data": data,
                                    "realm": req_realm or CURRENT_REALM})
        if path in ("/usage", "/v1/usage"):
            if not self._authorized():
                return
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            return self._json(200, usage_snapshot(realm=req_realm))
        if path == "/usage/credits":
            if not self._authorized():
                return
            # 按自然日统计（每日定点采样）。`days` 控制回看天数；
            # `hours` 保留为兼容旧调用，内部折算成天数。
            try:
                days = int((query.get("days") or ["14"])[0])
            except (TypeError, ValueError):
                days = 14
            if not (query.get("days")) and query.get("hours"):
                try:
                    days = max(1, int(int((query.get("hours") or ["24"])[0]) / 24))
                except (TypeError, ValueError):
                    pass
            realm = (query.get("realm") or [None])[0] or None
            return self._json(200, credits_daily(days=days, realm=realm))
        if path == "/usage/recent":
            if not self._authorized():
                return
            try:
                limit = max(1, min(1000, int((query.get("limit") or ["100"])[0])))
            except ValueError:
                limit = 100
            try:
                page = max(1, int((query.get("page") or ["1"])[0]))
            except ValueError:
                page = 1
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            return self._json(200, recent_usage(limit, realm=req_realm, page=page))
        if path == "/accounts/credits":
            if not self._authorized():
                return
            for a in (POOL.accounts if POOL else []):
                a.fetch_credits()
            record_credits_snapshot(reason="panel_refresh")
            return self._json(200, {"accounts": account_views()})
        if path == "/accounts":
            if not self._authorized():
                return
            return self._json(200, {
                "accounts": account_views(realm=query.get("realm", [None])[0]
                                          or CURRENT_REALM),
                "storage": ACCOUNTS_DIR,
                "usable": POOL.count_ready() if POOL else 0,
            })
        if path == "/accounts/export":
            if not self._authorized():
                return
            realm = (query.get("realm") or [None])[0] or None
            if realm not in ("intl", "cn"):
                realm = None
            include_secrets = (query.get("secrets") or ["1"])[0] \
                not in ("0", "false", "no")
            uids = []
            for raw in query.get("uid") or []:
                uids.extend(part.strip() for part in str(raw).split(",")
                            if part.strip())
            if uids:
                known = {a.uid for a in (POOL.accounts if POOL else [])}
                missing = [u for u in uids if u not in known]
                if missing:
                    return self._error(404, "no such account: %s"
                                       % ", ".join(missing[:5]),
                                       "invalid_request_error")
            doc = qoder_accounts.build_export_document(
                POOL.accounts if POOL else [],
                realm=realm, include_secrets=include_secrets,
                uids=uids or None)
            if (query.get("download") or ["0"])[0] in ("1", "true", "yes"):
                stamp = time.strftime("%Y%m%d-%H%M%S")
                if len(uids) == 1:
                    label = uids[0][:8]
                else:
                    label = realm + "-" if realm else ""
                name = "qoder-accounts-%s%s.json" % (label, stamp)
                return self._download(name, doc)
            return self._json(200, doc)
        if path == "/accounts/login/poll":
            if not self._authorized():
                return
            state = (query.get("state") or [""])[0]
            return self._json(200, POOL.poll_login(state))
        if path == "/usage/analytics":
            if not self._authorized():
                return
            return self._json(200, compute_usage_analytics())
        if path == "/usage/by-account":
            if not self._authorized():
                return
            return self._json(200, {"accounts": usage_by_account()})
        if path == "/usage/perf":
            if not self._authorized():
                return
            try:
                sample = max(10, min(20000,
                                     int((query.get("sample") or ["5000"])[0])))
            except ValueError:
                sample = 5000
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            return self._json(200, perf_stats(sample, realm=req_realm))
        if path == "/tasks":
            if not self._authorized():
                return
            import qoder_tasks
            uid = (query.get("uid") or [None])[0]
            view = qoder_tasks.fetch_tasks_view(POOL, uid=uid)
            if view.get("msg") and not view.get("tasks"):
                return self._json(200, view)
            return self._json(200, view)
        if path == "/scheduler":
            if not self._authorized():
                return
            return self._json(200, SCHEDULER.status() if SCHEDULER
                              else {"enabled": False, "msg": "未运行"})
        if path == "/settings":
            if not self._authorized():
                return
            return self._json(200, runtime_settings_view())
        if path == "/logs":
            if not self._authorized():
                return
            try:
                limit = int(query.get("limit", ["200"])[0])
            except (ValueError, TypeError):
                limit = 200
            level = query.get("level", [""])[0]
            tag = query.get("tag", [""])[0]
            search = query.get("search", [""])[0]
            req = query.get("req", [""])[0]
            try:
                since_id = int(query.get("since_id", ["0"])[0])
            except (ValueError, TypeError):
                since_id = 0
            return self._json(200, get_logs(limit=limit, level=level, tag=tag,
                                            search=search, since_id=since_id,
                                            req=req))
        if path == "/logs/export":
            if not self._authorized():
                return
            log_data = get_logs(limit=5000)
            lines = ["[%s] [%s] [%s] %s" % (item["ts"], item["level"],
                                             item["tag"], item["msg"])
                     for item in log_data["logs"]]
            text_content = "\n".join(lines).encode("utf-8")
            filename = "qd-proxy-%s.log" % time.strftime("%Y%m%d-%H%M%S")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % filename)
            self.send_header("Content-Length", str(len(text_content)))
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(text_content)
            return
        if path == "/settings/reveal":
            # 看板只画掩码 Key，复制明文需要显式请求；必须面板会话。
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            wanted = (query.get("id") or [""])[0]
            for entry in configured_keys():
                if entry.get("id") == wanted:
                    return self._json(200, {"id": wanted,
                                            "key": entry.get("key") or ""})
            return self._error(404, "no such key", "invalid_request_error")
        return self._error(404, "not found", "invalid_request_error")

    def _dashboard(self):
        try:
            with open(DASHBOARD_HTML, "rb") as fh:
                body = fh.read()
        except Exception as exc:
            return self._error(500, "dashboard.html unavailable: %s" % exc)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_payload(self, max_bytes=MAX_PAYLOAD_BYTES, allow_list=False):
        """Parse the request body into a dict (or a list when allow_list)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length > max_bytes:
            raise BodyTooLarge(length)
        if length < 0:
            raise BadJSON()
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw or "{}")
        except Exception:
            raise BadJSON()
        if isinstance(data, dict):
            return data
        if allow_list and isinstance(data, list):
            return data
        return {}

    def _payload_or_error(self, allow_list=False):
        """Read the body, replying with the right error and returning None."""
        try:
            return self._read_payload(allow_list=allow_list)
        except BodyTooLarge as exc:
            self._error(413, "payload too large (%d bytes > %d limit)"
                        % (exc.length, MAX_PAYLOAD_BYTES),
                        "invalid_request_error")
            return None
        except BadJSON:
            self._error(400, "invalid JSON body", "invalid_request_error")
            return None

    def _handle_settings_save(self):
        """Persist panel-managed settings from the web settings tab."""
        payload = self._payload_or_error()
        if payload is None:
            return
        reply = {}
        if "api_keys" in payload:
            raw = payload.get("api_keys")
            if not isinstance(raw, list):
                return self._error(400, "api_keys must be a list",
                                   "invalid_request_error")
            # 面板只画掩码 Key：空值表示“保留原值”，不是“清空”。
            existing = {entry.get("id"): entry for entry in configured_keys()}
            cleaned = []
            for index, item in enumerate(raw):
                if not isinstance(item, dict):
                    return self._error(400, "each api key must be an object",
                                       "invalid_request_error")
                entry_id = str(item.get("id") or "").strip()
                value = str(item.get("key") or "").strip()
                if not value and entry_id and entry_id in existing:
                    value = existing[entry_id].get("key") or ""
                if not entry_id:
                    entry_id = "k%d" % index
                if value and len(value) < 4:
                    return self._error(400,
                                       "api key must be at least 4 characters",
                                       "invalid_request_error")
                if not value:
                    return self._error(400,
                                       "a key entry is empty - fill it in or "
                                       "remove the row",
                                       "invalid_request_error")
                realm = str(item.get("realm") or "").strip().lower()
                if realm not in ("", "intl", "cn"):
                    return self._error(400, "realm must be intl, cn or empty",
                                       "invalid_request_error")
                created_at = item.get("created_at") \
                    or (existing.get(entry_id, {}).get("created_at")
                        if entry_id in existing else None) \
                    or time.strftime("%Y/%m/%d %H:%M")
                cleaned.append({
                    "id": entry_id,
                    "name": str(item.get("name") or "").strip(),
                    "key": value,
                    "realm": realm,
                    "enabled": item.get("enabled", True) is not False,
                    "created_at": created_at,
                })
            qoder_settings.set_api_keys(ACCOUNTS_DIR, cleaned)
            reply["api_keys_saved"] = len(cleaned)
        if "auth_disabled" in payload:
            qoder_settings.set_auth_disabled(ACCOUNTS_DIR,
                                             payload.get("auth_disabled"))
            reply["auth_disabled"] = bool(payload.get("auth_disabled"))
        new_key = payload.get("api_key")
        if new_key is not None:
            new_key = str(new_key).strip()
            if new_key and len(new_key) < 4:
                return self._error(400, "api key must be at least 4 characters",
                                   "invalid_request_error")
            global API_KEY, API_KEY_FILE_SET
            qoder_settings.set_api_key(ACCOUNTS_DIR, new_key)
            API_KEY = new_key
            API_KEY_FILE_SET = True
            reply["api_key_set"] = bool(new_key)
        if payload.get("restart_scheduler"):
            if SCHEDULER:
                SCHEDULER.stop()
                SCHEDULER.start()
            reply["scheduler"] = "restarted"
        reply.update(runtime_settings_view())
        return self._json(200, reply)

    def _handle_panel(self, path):
        """Panel login, logout and the settings screen (password)."""
        payload = self._payload_or_error()
        if payload is None:
            return
        if path == "/panel/login":
            client_ip = self.client_address[0] \
                if hasattr(self, "client_address") and self.client_address \
                else "127.0.0.1"
            now = time.time()
            with _login_lock:
                _prune_login_attempts(now)
                attempts = [t for t in _login_attempts.get(client_ip, [])
                            if now - t < 60]
                _login_attempts[client_ip] = attempts
                if len(attempts) >= 5:
                    wait_sec = int(60 - (now - attempts[0]))
                    return self._error(429,
                                       "too many login attempts, please wait %ds"
                                       % max(1, wait_sec),
                                       "rate_limit_error",
                                       retry_after=_clamp_retry_after(wait_sec))
            password = str(payload.get("password") or "")
            if not qoder_settings.verify_panel_password(ACCOUNTS_DIR, password):
                with _login_lock:
                    _login_attempts.setdefault(client_ip, []).append(now)
                time.sleep(0.5)   # 撞库缓解
                return self._error(401, "invalid panel password",
                                   "invalid_request_error")
            with _login_lock:
                _login_attempts.pop(client_ip, None)
            token = PANEL.create()
            return self._json(200, {
                "ok": True,
                "token": token,
                "using_default_password":
                    qoder_settings.panel_password_is_default(ACCOUNTS_DIR),
            })
        if path == "/panel/logout":
            PANEL.revoke(self._panel_token())
            return self._json(200, {"ok": True})
        # 之后所有路由都要面板会话
        if not self._panel_ok():
            return self._error(401, "panel password required",
                               "invalid_request_error")
        if path == "/panel/password":
            current = str(payload.get("current") or "")
            new = str(payload.get("new") or "")
            if not qoder_settings.verify_panel_password(ACCOUNTS_DIR, current):
                return self._error(401, "current password is wrong",
                                   "invalid_request_error")
            if len(new) < 4:
                return self._error(400, "new password must be at least 4 characters",
                                   "invalid_request_error")
            qoder_settings.set_panel_password(ACCOUNTS_DIR, new)
            if new != qoder_settings.DEFAULT_PANEL_PASSWORD:
                # 换密码使其它浏览器会话全部失效
                PANEL.revoke_all()
            token = PANEL.create()
            return self._json(200, {"ok": True, "token": token})
        return self._error(404, "not found", "invalid_request_error")

    def _handle_accounts(self, path, payload):
        """Account-management endpoints (dashboard uses these)."""
        if POOL is None:
            return self._error(503, "account pool unavailable")
        if path == "/accounts/import" and isinstance(payload, list):
            payload = {"data": payload}
        if not isinstance(payload, dict):
            return self._error(400, "expected a JSON object",
                               "invalid_request_error")
        if path in ("/accounts/credits", "/accounts/credits/fetch"):
            uid = payload.get("uid")
            realm = payload.get("realm")
            if uid:
                targets = [POOL.get(uid)]
            elif realm and realm != "all":
                targets = [a for a in POOL.accounts if a.realm == realm]
            else:
                targets = list(POOL.accounts)
            results = []
            for account in targets:
                if account is None:
                    continue
                res = account.fetch_credits()
                account.fetch_plan()
                results.append({"uid": account.uid, "ok": res.get("ok", False),
                                "credits": account.credits,
                                "plan": account.plan,
                                "error": res.get("error", "")})
            # 刷新即落一条快照：这是「某时段消耗」差值的数据源。
            record_credits_snapshot(reason="panel_refresh")
            return self._json(200, {"results": results,
                                    "accounts": account_views()})
        if path == "/tasks/run":
            import qoder_tasks
            if not POOL:
                return self._json(200, {"ok": False, "msg": "账号池不可用"})
            uid = payload.get("uid")
            if uid and uid != "all":
                target = POOL.get(uid)
                if not target:
                    return self._json(200, {"ok": False,
                                            "msg": "未找到指定的账号"})
                targets = [target]
            else:
                targets = [a for a in POOL.accounts
                           if a.enabled
                           and get_realm_config(a.realm)["has_checkin"]]
            if not targets:
                return self._json(200, {"ok": False, "msg": "未找到可签到的账号（签到仅国内版开放）"})
            res = qoder_tasks.run_batch_checkin(targets, gap=1.0)
            return self._json(200, {
                "ok": res["ok"],
                "credit_added": res["credit_added"],
                "logs": res["logs"],
                "accounts_count": res["accounts_count"],
            })
        if path == "/tasks/travel":
            # 看板福利按钮的对应动作：批量领取 Pro 福利包（官方仅国内版 sash 活动）
            import qoder_tasks
            if not POOL:
                return self._json(200, {"ok": False, "msg": "账号池不可用"})
            uid = payload.get("uid")
            if uid and uid != "all":
                target = POOL.get(uid)
                if not target:
                    return self._json(200, {"ok": False,
                                            "msg": "未找到指定的账号"})
                targets = [target]
            else:
                targets = [a for a in POOL.accounts
                           if a.enabled
                           and get_realm_config(a.realm)["has_checkin"]]
            if not targets:
                return self._json(200, {"ok": False, "msg": "未找到可领取的账号（活动仅国内版开放）"})
            res = qoder_tasks.run_batch_pro_claim(targets)
            return self._json(200, {
                "ok": True,
                "results": res["results"],
                "msg": res["msg"],
                "logs": res["logs"],
                "accounts_count": res["accounts_count"],
            })
        if path == "/scheduler/trigger":
            if SCHEDULER:
                return self._json(200, SCHEDULER.trigger_now())
            return self._json(200, {"ok": False, "msg": "调度器未初始化"})
        if path == "/scheduler/toggle":
            if SCHEDULER:
                SCHEDULER.enabled = not SCHEDULER.enabled
                SCHEDULER.log("用户切换调度器状态为: %s"
                              % ("启用" if SCHEDULER.enabled else "暂停"))
                return self._json(200, SCHEDULER.status())
            return self._json(200, {"ok": False, "msg": "调度器未初始化"})
        if path == "/logs/clear":
            clear_logs()
            return self._json(200, {"ok": True})
        if path == "/realm":
            new_realm = payload.get("realm")
            if new_realm in ("intl", "cn"):
                save_persisted_realm(new_realm)
            return self._json(200, {"ok": True, "current": CURRENT_REALM,
                                    "persisted": True})
        if path == "/accounts/checkin":
            uid = payload.get("uid")
            targets = [POOL.get(uid)] if uid else list(POOL.accounts)
            results = []
            for account in targets:
                if account is None:
                    continue
                if not get_realm_config(account.realm)["has_checkin"]:
                    continue      # 官方：仅国内版有签到
                res = account.checkin()
                results.append({"uid": account.uid,
                                "nickname": account.nickname, **res})
            return self._json(200, {"results": results,
                                    "accounts": account_views()})
        if path == "/accounts/login/start":
            platform = payload.get("platform") or "CLI"
            target_realm = payload.get("realm") or CURRENT_REALM
            if target_realm not in ("intl", "cn"):
                target_realm = "cn"
            try:
                started = POOL.start_login(realm=target_realm,
                                           platform=platform)
            except Exception as exc:
                return self._error(502, "could not start login: %s" % exc)
            log("oauth device login started (realm=%s, state=%s)"
                % (target_realm, started["state"][:8]))
            return self._json(200, started)
        if path == "/accounts/login/cancel":
            state = payload.get("state") or ""
            return self._json(200, {"cancelled": POOL.cancel_login(state)})
        if path == "/accounts/import/pat":
            pat = payload.get("pat") or ""
            realm = payload.get("realm") or CURRENT_REALM
            if realm not in ("intl", "cn"):
                realm = "cn"
            try:
                account = POOL.import_pat(pat, realm=realm)
            except Exception as exc:
                return self._error(400, "PAT import failed: %s" % exc)
            log("imported PAT account %s (realm=%s)"
                % (account.uid[:8], realm))
            return self._json(200, {"imported": [account.public()],
                                    "accounts": account_views()})
        if path == "/accounts/import/desktop":
            # 两步确认：{} 只读扫描（双区：桌面 App auth.v1.dat + CLI user）；
            # {"path":...} 按确认导入该凭证；{"all":true} 导入全部有效项。
            target_path = payload.get("path")
            if target_path:
                realm = payload.get("realm")
                try:
                    account = qoder_accounts.import_desktop_credential(
                        path=target_path, realm=realm)
                except Exception as exc:
                    return self._error(400, "import failed: %s" % exc)
                log("imported %s (%s) from local client credential"
                    % (account.uid[:8], account.realm), tag="accounts")
                return self._json(200, {
                    "imported": [account.public()],
                    "accounts": account_views(),
                    "pool_uids": [a.uid for a in POOL.accounts],
                })
            if payload.get("all"):
                try:
                    imported = qoder_accounts.import_desktop_credential()
                except Exception as exc:
                    return self._error(400, "import failed: %s" % exc)
                for account in imported:
                    log("imported %s (%s) from local client credential"
                        % (account.uid[:8], account.realm), tag="accounts")
                return self._json(200, {
                    "imported": [a.public() for a in imported],
                    "accounts": account_views(),
                    "pool_uids": [a.uid for a in POOL.accounts],
                })
            try:
                detected = qoder_accounts.scan_desktop_credentials()
            except Exception as exc:
                detected = []
                log("desktop credential scan failed: %s" % exc)
            return self._json(200, {
                "detected": detected,
                "accounts": account_views(),
                "pool_uids": [a.uid for a in POOL.accounts],
            })
        if path == "/accounts/refresh":
            uid = payload.get("uid")
            targets = [POOL.get(uid)] if uid else list(POOL.accounts)
            results = []
            for account in targets:
                if account is None:
                    continue
                ok = account.refresh()
                account.save(ACCOUNTS_DIR)
                results.append({"uid": account.uid, "ok": ok,
                                "error": account.last_error})
            return self._json(200, {"results": results})
        if path == "/accounts/test":
            uid = payload.get("uid")
            if not uid:
                return self._error(400, "uid required")
            account = POOL.get(uid)
            if not account:
                return self._error(404, "no such account")
            test_model = payload.get("model") or "auto"
            test_payload = {
                "model": test_model,
                "messages": [{"role": "user", "content": "hi"}],
                "stream": False,
            }
            t0 = time.time()
            # 诊断必须复用生产链路**且锁定目标账号**（经验⑦）。否则流量走池子
            # 正常选号，可能由健康账号代答，却把结果记在请求的 uid 上——双向假
            # 证据：给死号报 ok、给好号记冷却。这里临时把池收敛为单账号。
            _orig_pool = POOL
            _test_pool = None
            try:
                try:
                    if POOL is not None:
                        import qoder_accounts as _qa
                        _test_pool = _qa.AccountPool(POOL.dir)
                        _test_pool.accounts = [account]
                        globals()["POOL"] = _test_pool
                    # 诊断是**交互式**的（面板点一下就等）：不要把推理链路的
                    # 长排队预算带进来，否则上游排队时面板会挂满 5 分钟。
                    resp, acc, _ = open_upstream(
                        test_payload, target_realm=acc_realm(account),
                        queue_deadline=time.time() + 30)
                    with resp:
                        chat_obj = aggregate_stream(resp, test_model, None)
                finally:
                    if _test_pool is not None:
                        globals()["POOL"] = _orig_pool
                wall_ms = int((time.time() - t0) * 1000)
                choices = chat_obj.get("choices") or []
                msg = (choices[0].get("message") or {}) if choices else {}
                reply_text = (msg.get("content") or msg.get("reasoning_content")
                              or "OK").strip()
                if len(reply_text) > 80:
                    reply_text = reply_text[:77] + "..."
                # 记账记在实际承担流量的账号上（正常即 account 本身）
                (acc or account).clear_error()
                log("account test: uid=%s model=%s wall=%dms ok=True"
                    % (account.uid[:8], test_model, wall_ms), tag="accounts")
                return self._json(200, {"ok": True, "uid": account.uid,
                                        "model": test_model,
                                        "elapsed_ms": wall_ms,
                                        "reply": reply_text})
            except RateLimited as exc:
                wall_ms = int((time.time() - t0) * 1000)
                return self._json(200, {"ok": False, "uid": account.uid,
                                        "status": 429,
                                        "error": "rate limited: %s" % exc.detail[:150],
                                        "elapsed_ms": wall_ms})
            except urllib.error.HTTPError as exc:
                wall_ms = int((time.time() - t0) * 1000)
                try:
                    detail = exc.read(400).decode("utf-8", "replace")
                except Exception:
                    detail = ""
                account.note_error("HTTP %d: %s" % (exc.code, detail[:80]),
                                   cooldown=60)
                log("account test: uid=%s model=%s wall=%dms error=%d"
                    % (account.uid[:8], test_model, wall_ms, exc.code),
                    level="WARN", tag="accounts")
                return self._json(200, {"ok": False, "uid": account.uid,
                                        "status": exc.code,
                                        "error": "HTTP %d: %s"
                                        % (exc.code, detail[:150]),
                                        "elapsed_ms": wall_ms})
            except Exception as exc:
                wall_ms = int((time.time() - t0) * 1000)
                account.note_error(str(exc)[:80], cooldown=60)
                log("account test: uid=%s model=%s wall=%dms exc=%s"
                    % (account.uid[:8], test_model, wall_ms, exc),
                    level="WARN", tag="accounts")
                return self._json(200, {"ok": False, "uid": account.uid,
                                        "status": 500, "error": str(exc),
                                        "elapsed_ms": wall_ms})
        if path == "/accounts/set":
            uid = payload.get("uid")
            if not uid:
                return self._error(400, "uid required")
            updated = POOL.set_enabled(uid, bool(payload.get("enabled")))
            if updated is None:
                return self._error(404, "no such account")
            log("account %s %s" % (uid[:8],
                                   "enabled" if payload.get("enabled")
                                   else "disabled"))
            return self._json(200, {"account": updated})
        if path == "/accounts/set-all":
            POOL.set_all_enabled(bool(payload.get("enabled")))
            return self._json(200, {"accounts": account_views()})
        if path == "/accounts/delete":
            uid = payload.get("uid")
            if not uid:
                return self._error(400, "uid required")
            removed = POOL.remove(uid)
            log("account %s deleted" % uid[:8])
            return self._json(200, {"deleted": removed,
                                    "accounts": account_views()})
        if path == "/accounts/import":
            # 支持的文档形态见 qoder_accounts._coerce_account_rows。
            # 选项：dryRun / overwrite / realm ("intl"|"cn")
            blob = payload.get("data") if "data" in payload else payload
            if not isinstance(blob, (dict, list)):
                return self._error(400, "the document must be a JSON object "
                                   "or array", "invalid_request_error")
            rows, problem = qoder_accounts._coerce_account_rows(blob)
            if problem:
                return self._error(400, "cannot read the document: %s" % problem,
                                   "invalid_request_error")
            dry_run = bool(payload.get("dryRun"))
            overwrite = bool(payload.get("overwrite"))
            forced_realm = (payload.get("realm") or "").strip().lower() or None
            if forced_realm and forced_realm not in ("intl", "cn"):
                return self._error(400, "realm must be intl or cn",
                                   "invalid_request_error")
            if dry_run:
                return self._json(200, {
                    "dryRun": True,
                    "count": len(rows),
                    "result": POOL.preview_import_rows(rows, realm=forced_realm,
                                                       overwrite=overwrite),
                    "accounts": account_views(),
                })
            report = POOL.import_rows(rows, realm=forced_realm,
                                      overwrite=overwrite)
            log("account import: %d added, %d updated, %d skipped, %d invalid"
                % (len(report["added"]), len(report["updated"]),
                   len(report["skipped"]), len(report["invalid"])))
            return self._json(200, {
                "count": len(rows),
                "result": report,
                "accounts": account_views(),
            })
        return self._error(404, "unknown account endpoint",
                           "invalid_request_error")

    def _handle_responses(self, payload):
        """Serve /v1/responses by translating to chat completions upstream."""
        session_key = extract_session_key(self.headers, payload)
        custom_names = custom_tool_names(payload.get("tools"))
        chat_req = responses_to_chat(payload)
        model = payload.get("model") or "auto"
        want_stream = bool(payload.get("stream"))
        t_start = time.time()
        fp = prompt_fingerprint(chat_req.get("messages"))
        log("responses: model=%s stream=%s msgs=%d effort=%r custom_tools=%s"
            % (model, want_stream, len(chat_req.get("messages") or []),
               chat_req.get("reasoning_effort"),
               sorted(custom_names) or "-"))
        holder = {"usage": None, "custom_names": custom_names,
                  "model": model,
                  # 客户端声明的工具名（转换后的 chat 形态）：泄漏回读/DSML
                  # 兜底的白名单 —— 名字不在名单内的文本一律不转换（fail-open）。
                  "allowed_tool_names": declared_tool_names(
                      chat_req.get("tools"))}
        # 本次请求的排队等待总预算：**初开与流内信封重开共用同一个截止时间**。
        req_queue_deadline = time.time() + _QUEUE_RETRY_BUDGET
        try:
            req_realm = self._request_realm() or CURRENT_REALM
            blocked = self._cross_realm_error(chat_req.get("model"), req_realm)
            if blocked:
                return self._error(400, blocked, "invalid_request_error")
            upstream, account, _ = open_upstream(
                chat_req, session_key=session_key, target_realm=req_realm,
                queue_deadline=req_queue_deadline, abort_conn=self.connection)
        except RateLimited as exc:
            t = time.time() - t_start
            record_error(model, 429, exc.detail[:200],
                         elapsed_ms=int(t * 1000))
            return self._rate_limited(exc)
        except urllib.error.HTTPError as exc:
            # 错误体在 open_upstream 中已读过（挂在 qoder_detail），二次 read
            # 会拿到残缺内容——优先取挂载值。
            detail = getattr(exc, "qoder_detail", "")
            if not detail:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
            record_error(model, exc.code, detail,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            msg, etype = friendly_upstream_error(exc.code, detail)
            return self._error(exc.code, msg, etype)
        except Exception as exc:
            message = str(exc)
            record_error(model, 502, message,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            if message.startswith("no usable account"):
                # 走到这里说明抛的是 RuntimeError("no usable account")，
                # 而熔断打开时抛的是 RateLimited（走 _rate_limited）——所以此处
                # failgate 按构造必然未开，直接给一个固定退避即可。
                return self._error(
                    503, message
                    + " - add or enable one at the dashboard (/)",
                    retry_after=5)
            return self._error(502, "upstream unreachable: %s" % exc)
        with upstream:
            if want_stream:
                self.send_response(200)
                self.send_header("Content-Type",
                                 "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                if cors_origin_allowed(self.path):
                    self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                first_ms = None
                # 流内信封重试：上游可能 HTTP200 建流后在信封里投 418
                # （access log 记 200 + 业务错 418 即此形态）。只要还没向
                # 客户端写出任何上游字节，就重开上游再试。
                attempts = 0
                queue_rot = 0
                quota_rot = 0
                pump_quota = None      # 额度耗尽的终态（429 语义）
                queue_deadline = req_queue_deadline
                cur = upstream
                pump_exc = None
                try:
                    while True:
                        try:
                            # 统计已消费的上游数据行：错误信封本身不产出
                            # 行，故 n==0 表示还没消费到任何上游数据 → 可重开
                            consumed = {"n": 0}

                            def _count_src(src, _c=consumed):
                                for item in src:
                                    _c["n"] += 1
                                    yield item

                            # 泄漏回读接在信封解包与事件翻译之间：还原出的调用
                            # 走与结构化 tool_calls 完全相同的 added/delta/done
                            # 事件，被吞掉的回声文本不会进 output_text。
                            inner = _count_src(recover_leaked_tool_calls(
                                iter_inner_sse(cur, holder=holder),
                                allowed_names=holder.get("allowed_tool_names")))
                            for frame in stream_responses_events(inner, model, holder):
                                if first_ms is None:
                                    first_ms = int((time.time() - t_start) * 1000)
                                self.wfile.write(clean_responses_frame(frame))
                                self.wfile.flush()
                            break
                        except (BrokenPipeError, ConnectionResetError,
                                ConnectionAbortedError):
                            wall = int((time.time() - t_start) * 1000)
                            record_usage(model, holder.get("usage"), stream=True,
                                         elapsed_ms=wall, ttft_ms=first_ms,
                                         gen_ms=(wall - first_ms)
                                         if first_ms is not None else None,
                                         fp=fp, account=account.uid,
                                         finish=holder.get("finish_reason"),
                                         finish_raw=holder.get("finish_reason_raw"),
                                         refusal=holder.get("refusal"))
                            return
                        except UpstreamStatus as exc:
                            # 控制帧（response.created 等）先于数据，不能算
                            # “已输出”；以上游数据行计数判断能否重开。
                            _q, _qw = parse_queue_hint(exc.detail or "")
                            if _q and consumed.get("n", 0) == 0 and \
                                    queue_rot < _QUEUE_WAIT_MAX and \
                                    time.time() < queue_deadline:
                                queue_rot += 1
                                nap = queue_backoff_seconds(exc)
                                nap = max(1, min(nap,
                                                 int(queue_deadline - time.time())))
                                # 同上：排队是模型级容量门控，等待而非换号，
                                # 否则一个请求就会把整池标记成不可用。
                                log("responses in-stream queue (10605) on "
                                    "model '%s' (wait %d/%d), waiting %ds"
                                    % (model, queue_rot, _QUEUE_WAIT_MAX,
                                       nap), level="WARN", tag="chat")
                                # 同上：等待前先关流，别抱着并发额度睡 30s。
                                try:
                                    cur.close()
                                except Exception:
                                    pass
                                if client_disconnected(self.connection):
                                    log("client gone while queued on '%s' - "
                                        "abandoning wait" % model,
                                        level="WARN", tag="chat")
                                    pump_exc = exc
                                    break
                                time.sleep(nap)
                                note_queue_wait(nap, hint=_qw)
                                # 必须用翻译后的 chat_req：payload 是 Responses
                                # 格式（input/instructions，无 messages），用它
                                # 重建会发出**空会话**请求 —— 客户端会收到 200
                                # 但内容是错的（静默错数据，比 429 更糟）。
                                try:
                                    cur2, account, _ = open_upstream(
                                        chat_req, session_key=session_key,
                                        target_realm=req_realm,
                                        queue_deadline=queue_deadline,
                                        abort_conn=self.connection)
                                except Exception as rex:
                                    log("responses reopen after queue "
                                        "failed: %s" % str(rex)[:160],
                                        level="WARN")
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            if qoder_accounts.quota_exhausted(exc.detail or "") \
                                    and consumed.get("n", 0) == 0:
                                # 账号额度耗尽（110/112）：换号重开（同上）。
                                log("responses in-stream account quota "
                                    "exhausted (status %s) on '%s' - "
                                    "rotating: %s"
                                    % (exc.status, account.uid[:8],
                                       str(exc.detail)[:120]),
                                    level="WARN", tag="chat")
                                note_retry("quota_exhausted",
                                           account=account.uid[:8])
                                account.note_quota_exhausted(
                                    "HTTP %s %s" % (exc.status,
                                                    str(exc.detail)[:80]))
                                if session_key and POOL:
                                    POOL.affinity.unbind(session_key)
                                if quota_rot >= _QUOTA_ROTATE_MAX:
                                    pump_quota = (exc, account)
                                    pump_exc = exc
                                    break
                                quota_rot += 1
                                try:
                                    cur2, account, _ = open_upstream(
                                        chat_req, session_key=session_key,
                                        target_realm=req_realm,
                                        queue_deadline=queue_deadline,
                                        abort_conn=self.connection)
                                except Exception as rex:
                                    log("responses reopen after quota "
                                        "exhausted failed: %s"
                                        % str(rex)[:160], level="WARN")
                                    pump_quota = ((rex, account)
                                                  if isinstance(rex, RateLimited)
                                                  else (exc, account))
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            if should_retry_envelope(exc, False, attempts) \
                                    and consumed.get("n", 0) == 0:
                                attempts += 1
                                log("responses in-stream envelope status %s "
                                    "(try %d/%d), reopening upstream"
                                    % (exc.status, attempts + 1,
                                       TRANSIENT_MAX_RETRIES + 1),
                                    level="WARN", tag="chat")
                                time.sleep(attempts)
                                try:
                                    cur2, account, _ = open_upstream(
                                        chat_req, session_key=session_key,
                                        target_realm=req_realm,
                                        queue_deadline=queue_deadline,
                                        abort_conn=self.connection)
                                except Exception as rex:
                                    log("responses reopen failed: %s"
                                        % str(rex)[:160], level="WARN")
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            pump_exc = exc
                            break
                finally:
                    if cur is not upstream:
                        try:
                            cur.close()
                        except Exception:
                            pass
                if pump_exc is not None:
                    record_error(model, pump_exc.status, pump_exc.detail,
                                 elapsed_ms=int((time.time() - t_start) * 1000))
                    msg, _ = friendly_upstream_error(
                        _to_int_status(pump_exc.status), pump_exc.detail)
                    _q, _qw = parse_queue_hint(pump_exc.detail or "")
                    if pump_quota is not None:
                        _q_exc, _q_acct = pump_quota
                        _rq = (int(_q_exc.wait) if isinstance(_q_exc, RateLimited)
                               else int(max(60, (_q_acct.quota_until - time.time())
                                            if _q_acct is not None else 60)))
                        msg = ("all accounts quota exhausted for model '%s'; "
                               "retry in %ds" % (model, min(3600, _rq)))
                    elif _q:
                        msg = ("upstream queue busy for model '%s'; retry in %ds"
                               % (model, int(queue_backoff_seconds(pump_exc))))
                    log("responses upstream status %s: %s"
                        % (pump_exc.status, msg[:200]), level="ERROR",
                        tag="chat")
                    # **不能静默结束**：客户端只看到空流会立刻重试（零成本失败
                    # = 重试放大器）。按 Responses 规范投一帧 response.failed，
                    # 把上游状态与重试提示明确交给客户端。
                    _fail = {
                        "type": "response.failed",
                        "sequence_number": 1,
                        "response": {
                            "id": _new_id("resp_"),
                            "object": "response",
                            "created_at": int(time.time()),
                            "status": "failed",
                            "model": model,
                            "output": [],
                            "error": {"code": str(
                                (429 if parse_queue_hint(
                                    getattr(pump_exc, "detail", "") or "")[0]
                                 else pump_exc.status)),
                                      "message": msg[:400]},
                        },
                    }
                    try:
                        self.wfile.write(
                            ("event: response.failed\ndata: "
                             + json.dumps(_fail, ensure_ascii=False)
                             + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                    except Exception:
                        pass
                    return
                wall = int((time.time() - t_start) * 1000)
                record_usage(model, holder.get("usage"), stream=True,
                             elapsed_ms=wall, ttft_ms=first_ms,
                             gen_ms=(wall - first_ms)
                             if first_ms is not None else None,
                             fp=fp, account=account.uid,
                             finish=holder.get("finish_reason"),
                             finish_raw=holder.get("finish_reason_raw"),
                             refusal=holder.get("refusal"))
                return
            try:
                # 同上：必须是 chat_req，否则重开会发出空会话请求。
                chat_obj, account = aggregate_with_envelope_retry(
                    upstream, chat_req, session_key, req_realm, model,
                    holder, account, queue_deadline=req_queue_deadline, abort_conn=self.connection)
            except RateLimited as exc:
                record_error(model, 429, exc.detail[:200],
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._rate_limited(exc)
            except UpstreamStatus as exc:
                record_error(model, exc.status, exc.detail,
                             elapsed_ms=int((time.time() - t_start) * 1000))
                msg, etype = friendly_upstream_error(_to_int_status(exc.status),
                                                     exc.detail)
                return self._error(exc.status if str(exc.status).isdigit() else 502,
                                   msg, etype)
            except Exception as exc:
                record_error(model, 502, str(exc),
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._error(502, "upstream stream error: %s" % exc)
            wall = int((time.time() - t_start) * 1000)
            result = chat_to_response(chat_obj, model, custom_names)
            _r0 = (chat_obj.get("choices") or [{}])[0]
            record_usage(model, chat_obj.get("usage"), stream=False,
                         elapsed_ms=wall, fp=fp, account=account.uid,
                         finish=_r0.get("finish_reason"),
                         finish_raw=holder.get("finish_reason_raw"),
                         refusal=((_r0.get("message") or {}).get("refusal")))
            return self._json(200, result)

    def do_POST(self):
        # 包装：保证**每个** request.start 都有配对的 request.end。
        # 早退路径（如 cross-realm 400）不经 record_error/record_usage，
        # 此前会留下永不闭合的 start（实测 events.jsonl 积压多个）。
        # end_request 自带幂等（ctx.finished），正常路径不会重复写。
        try:
            return self._do_POST_impl()
        finally:
            end_request()

    def _do_POST_impl(self):
        path = self.path.split("?")[0]
        if path == "/settings/save":
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            return self._handle_settings_save()
        if path in ("/panel/login", "/panel/logout", "/panel/password"):
            return self._handle_panel(path)
        if self._is_panel_route(path) and not self._panel_ok():
            return self._error(401, "panel password required",
                               "invalid_request_error")
        is_account_route = (
            path.startswith("/accounts/")
            or path == "/realm"
            or path.startswith("/tasks")
            or path.startswith("/scheduler")
            or path.startswith("/logs")
        )
        if not is_account_route and path not in (
                "/v1/chat/completions", "/chat/completions",
                "/v1/completions", "/completions",
                "/v1/responses", "/responses"):
            return self._error(404, "not found", "invalid_request_error")
        if not self._authorized():
            return
        payload = self._payload_or_error(allow_list=(path == "/accounts/import"))
        if payload is None:
            return
        if is_account_route:
            return self._handle_accounts(path, payload)
        # ---- 推理请求：开启可溯源的请求上下文（req_id + 遥测累计）----
        begin_request(tag="chat", path=path,
                      model=str((payload or {}).get("model") or ""))
        if path in ("/v1/responses", "/responses"):
            return self._handle_responses(payload)

        # ---- Chat Completions 主链路 ----
        normalize_tool_choice(payload)
        normalize_tools(payload)
        translate_max_completion_tokens(payload)
        model = payload.get("model") or "auto"
        payload.setdefault("stream", False)
        # custom freeform 工具名：流式截断防护需要据此跳过 JSON 判定 ——
        # 这类工具的载荷本就是自由文本，按「能否解析 JSON」判会误杀。
        _chat_custom = custom_tool_names(payload.get("tools"))
        # 客户端声明的工具名（DSML 兜底白名单）：模型若把调用写成 DSML 文本，
        # 只有 invoke 名全在该集合内才敢转成结构化 tool_calls。
        _chat_tools = declared_tool_names(payload.get("tools"))
        # 保持原始终端 stream 意图
        want_stream = bool(payload.get("stream"))
        # 转换统一在 build_qoder_body 内做（压平/清洗/工具）
        session_key = extract_session_key(self.headers, payload)
        fp = prompt_fingerprint(payload.get("messages"))
        t_start = time.time()
        effort = payload.get("reasoning_effort") or \
            (payload.get("reasoning") or {}).get("effort") \
            if isinstance(payload.get("reasoning"), dict) \
            else payload.get("reasoning_effort")
        log("chat: model=%s client_effort=%r stream=%s msgs=%d"
            % (model, effort, want_stream,
               len(payload.get("messages") or [])))
        # 同上：初开与流内信封重开共用同一个排队截止时间。
        req_queue_deadline = time.time() + _QUEUE_RETRY_BUDGET
        try:
            req_realm = self._request_realm() or CURRENT_REALM
            blocked = self._cross_realm_error(model, req_realm)
            if blocked:
                return self._error(400, blocked, "invalid_request_error")
            upstream, account, _ = open_upstream(
                payload, session_key=session_key, target_realm=req_realm,
                queue_deadline=req_queue_deadline, abort_conn=self.connection)
        except RateLimited as exc:
            record_error(model, 429, exc.detail[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000))
            return self._rate_limited(exc)
        except urllib.error.HTTPError as exc:
            # 错误体在 open_upstream 中已读过（挂在 qoder_detail），二次 read
            # 会拿到残缺内容——优先取挂载值。
            detail = getattr(exc, "qoder_detail", "")
            if not detail:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
            record_error(model, exc.code, detail,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            msg, etype = friendly_upstream_error(exc.code, detail)
            return self._error(exc.code, msg, etype)
        except Exception as exc:
            message = str(exc)
            record_error(model, 502, message,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            if message.startswith("no usable account"):
                # 走到这里说明抛的是 RuntimeError("no usable account")，
                # 而熔断打开时抛的是 RateLimited（走 _rate_limited）——所以此处
                # failgate 按构造必然未开，直接给一个固定退避即可。
                return self._error(
                    503, message
                    + " - add or enable one at the dashboard (/)",
                    retry_after=5)
            return self._error(502, "upstream unreachable: %s" % exc)

        with upstream:
            holder = {"usage": None, "model": model,
                      # custom freeform 工具名：截断防护据此跳过 JSON 判定，
                      # 避免把自由文本载荷误杀（非流式聚合路径）。
                      "custom_names": _chat_custom,
                      # 客户端声明的工具名：非流式聚合据此做 DSML 兜底白名单
                      # 校验（与流式的 allowed_tool_names 同一份名单）。
                      "allowed_tool_names": _chat_tools}
            if want_stream:
                self.send_response(200)
                self.send_header("Content-Type",
                                 "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                if cors_origin_allowed(self.path):
                    self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                emitted = False
                first_ms = None
                # 流内信封重试（同上：200 建流后信封投 418 的形态），仅在
                # 尚未向客户端写出任何上游字节时重开。
                attempts = 0
                queue_rot = 0
                quota_rot = 0
                pump_quota = None      # 额度耗尽的终态（429 语义）
                queue_deadline = req_queue_deadline
                cur = upstream
                pump_exc = None
                try:
                    while True:
                        try:
                            # 守卫链（顺序与参数都不能改）：
                            #   iter_client_sse(recover_leaked_tool_calls(
                            #       iter_inner_sse(cur)))
                            # 1) 截断防护层：tool_calls 分片缓冲后按完整性补发，
                            #    残缺参数不下发（否则客户端解析失败卡死会话）；
                            # 2) 泄漏回读：模型把内部协议文本（marker + JSON）
                            #    复述成正文时还原为结构化 tool_calls / 按截断
                            #    语义吞掉；必须在截断层**之前**，还原出的调用
                            #    才能过同一套截断校验与白名单；
                            # 3) DSML 文本兜底（白名单=客户端声明的工具名）。
                            for line in iter_client_sse(
                                    cur, holder=holder,
                                    custom_names=_chat_custom,
                                    allowed_tool_names=_chat_tools,
                                    inner_lines=recover_leaked_tool_calls(
                                        iter_inner_sse(cur, holder=holder),
                                        allowed_names=_chat_tools)):
                                if first_ms is None:
                                    first_ms = int((time.time() - t_start) * 1000)
                                emitted = True
                                self.wfile.write(line)
                                self.wfile.flush()
                            break
                        except (BrokenPipeError, ConnectionResetError,
                                ConnectionAbortedError):
                            # 客户端断开；上游已产出的部分照常记账。
                            wall = int((time.time() - t_start) * 1000)
                            record_usage(model, holder.get("usage"), stream=True,
                                         elapsed_ms=wall, ttft_ms=first_ms,
                                         gen_ms=(wall - first_ms)
                                         if first_ms is not None else None,
                                         fp=fp, account=account.uid,
                                         finish=holder.get("finish_reason"),
                                         finish_raw=holder.get("finish_reason_raw"),
                                         refusal=holder.get("refusal"))
                            return
                        except UpstreamStatus as exc:
                            _q, _qw = parse_queue_hint(exc.detail or "")
                            if _q and not emitted and \
                                    queue_rot < _QUEUE_WAIT_MAX and \
                                    time.time() < queue_deadline:
                                queue_rot += 1
                                nap = queue_backoff_seconds(exc)
                                nap = max(1, min(nap,
                                                 int(queue_deadline - time.time())))
                                # 排队（10605）是**模型级容量门控**：实测同池
                                # 所有账号此刻一起排队（queueCount 常为 0 而
                                # serviceAvailable=false）。换号既拿不到服务，
                                # 又会在**一个请求内**把整池账号全标记成不可用
                                # ——后续请求随即全部 429。故与非流式一致：
                                # 等上游放行后原样重开，不换号、不标记。
                                log("chat in-stream queue (10605) on model "
                                    "'%s' (wait %d/%d), waiting %ds"
                                    % (model, queue_rot, _QUEUE_WAIT_MAX,
                                       nap), level="WARN", tag="chat")
                                # 等待前先关掉当前流：排队可长达 30s，抱着在途
                                # 名额睡觉会把本号并发额度占满（close 幂等，外层
                                # with 再关一次也安全）。
                                try:
                                    cur.close()
                                except Exception:
                                    pass
                                if client_disconnected(self.connection):
                                    log("client gone while queued on '%s' - "
                                        "abandoning wait" % model,
                                        level="WARN", tag="chat")
                                    pump_exc = exc
                                    break
                                time.sleep(nap)
                                note_queue_wait(nap, hint=_qw)
                                try:
                                    cur2, account, _ = open_upstream(
                                        payload, session_key=session_key,
                                        target_realm=req_realm,
                                        queue_deadline=queue_deadline,
                                        abort_conn=self.connection)
                                except Exception as rex:
                                    log("chat reopen after queue failed: %s"
                                        % str(rex)[:160], level="WARN")
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            if qoder_accounts.quota_exhausted(exc.detail or ""):
                                # 账号额度耗尽（110/112）：换号重开。必须在
                                # should_retry_envelope 之前处理——后者对 403 只
                                # 看瞬时性，会把它当不可重试而直接失败。
                                log("chat in-stream account quota exhausted "
                                    "(status %s) on '%s' - rotating: %s"
                                    % (exc.status, account.uid[:8],
                                       str(exc.detail)[:120]),
                                    level="WARN", tag="chat")
                                note_retry("quota_exhausted",
                                           account=account.uid[:8])
                                account.note_quota_exhausted(
                                    "HTTP %s %s" % (exc.status,
                                                    str(exc.detail)[:80]))
                                if session_key and POOL:
                                    POOL.affinity.unbind(session_key)
                                if quota_rot >= _QUOTA_ROTATE_MAX:
                                    pump_quota = (exc, account)
                                    pump_exc = exc
                                    break
                                quota_rot += 1
                                try:
                                    cur2, account, _ = open_upstream(
                                        payload, session_key=session_key,
                                        target_realm=req_realm,
                                        queue_deadline=queue_deadline,
                                        abort_conn=self.connection)
                                except Exception as rex:
                                    log("chat reopen after quota exhausted "
                                        "failed: %s" % str(rex)[:160],
                                        level="WARN", tag="chat")
                                    pump_quota = ((rex, account)
                                                  if isinstance(rex, RateLimited)
                                                  else (exc, account))
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            if should_retry_envelope(exc, emitted, attempts):
                                attempts += 1
                                log("chat in-stream envelope status %s on "
                                    "model '%s' (try %d/%d), reopening upstream"
                                    % (exc.status, model, attempts + 1,
                                       TRANSIENT_MAX_RETRIES + 1),
                                    level="WARN", tag="chat")
                                time.sleep(attempts)
                                try:
                                    cur2, account, _ = open_upstream(
                                        payload, session_key=session_key,
                                        target_realm=req_realm,
                                        queue_deadline=queue_deadline,
                                        abort_conn=self.connection)
                                except Exception as rex:
                                    log("chat reopen failed: %s"
                                        % str(rex)[:160], level="WARN")
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            pump_exc = exc
                            break
                        except Exception as _uexc:
                            # 上游断连类异常（IncompleteRead / TimeoutError 等）不属于上面任何一类。
                            # **必须放在 except 链最后** —— 否则会先捕获 UpstreamStatus，把排队/
                            # 额度换号逻辑全部吞掉。此处记一条错误帧收尾：HTTP 200 头已发出，若不
                            # 兜底，客户端只能看到连接被掐断（既无错误帧也无 [DONE]），无从判断重试。
                            log("upstream stream broke on model '%s': %s"
                                % (model, type(_uexc).__name__),
                                level="WARN", tag="chat")
                            wall = int((time.time() - t_start) * 1000)
                            record_error(model, 502,
                                         "upstream stream broke: %s"
                                         % type(_uexc).__name__,
                                         elapsed_ms=wall)
                            try:
                                _err_body = json.dumps({"error": {
                                    "message": "upstream stream broke (%s)"
                                               % type(_uexc).__name__,
                                    "type": "upstream_error",
                                    "code": 502}}, ensure_ascii=False)
                                self.wfile.write(("data: " + _err_body
                                                  + "\n\n").encode("utf-8"))
                                self.wfile.write(b"data: [DONE]\n\n")
                                self.wfile.flush()
                            except Exception:
                                pass
                            return
                finally:
                    if cur is not upstream:
                        try:
                            cur.close()
                        except Exception:
                            pass
                if pump_exc is not None:
                    exc = pump_exc
                    wall = int((time.time() - t_start) * 1000)
                    record_error(model, exc.status, exc.detail, elapsed_ms=wall)
                    msg, etype = friendly_upstream_error(
                        _to_int_status(exc.status), exc.detail)
                    # 排队耗尽的终态：SSE 头已发出（HTTP 200），无法再改
                    # 状态码，只能把明确的退避提示放进错误帧。
                    # **code 必须与 type 一致**：排队语义是「稍后重试」= 429。
                    # 曾直接抄上游的 403，客户端当「权限/拒绝」处理，走自己的
                    # 重试逻辑而非按 Retry-After 退避（实测 Reconnecting 1/5）。
                    _ecode = exc.status
                    _retry_s = None
                    if pump_quota is not None:
                        # 池内额度集体用尽：429 + Retry-After（额度按日重置）。
                        _q_exc, _q_acct = pump_quota
                        if isinstance(_q_exc, RateLimited):
                            _retry_s = int(_q_exc.wait)
                        else:
                            _retry_s = int(max(60, (
                                _q_acct.quota_until - time.time())
                                if _q_acct is not None else 60))
                        _retry_s = min(3600, _retry_s)
                        msg = ("all accounts quota exhausted for model '%s'; "
                               "retry in %ds" % (model, _retry_s))
                        etype = "rate_limit_error"
                        _ecode = 429
                    elif parse_queue_hint(getattr(exc, "detail", "") or "")[0]:
                        _retry_s = int(queue_backoff_seconds(exc))
                        msg = ("upstream queue busy for model '%s'; retry in %ds"
                               % (model, _retry_s))
                        etype = "rate_limit_error"
                        _ecode = 429
                    err = json.dumps({"error": {
                        "message": msg, "type": etype,
                        "code": _ecode,
                        "retry_after": _retry_s if _ecode == 429 else None}},
                        ensure_ascii=False)
                    try:
                        self.wfile.write(("data: %s\n\n" % err).encode("utf-8"))
                        self.wfile.write(b"data: [DONE]\n\n")
                        self.wfile.flush()
                    except Exception:
                        pass
                    return
                if not emitted:
                    err = json.dumps({"error": {
                        "message": "empty upstream stream",
                        "type": "server_error"}})
                    self.wfile.write(("data: %s\n\n" % err).encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
                wall = int((time.time() - t_start) * 1000)
                record_usage(model, holder.get("usage"), stream=True,
                             elapsed_ms=wall, ttft_ms=first_ms,
                             gen_ms=(wall - first_ms)
                             if first_ms is not None else None,
                             fp=fp, account=account.uid,
                             finish=holder.get("finish_reason"),
                             finish_raw=holder.get("finish_reason_raw"),
                             refusal=holder.get("refusal"))
                return
            try:
                result, account = aggregate_with_envelope_retry(
                    upstream, payload, session_key, req_realm, model,
                    holder, account, queue_deadline=req_queue_deadline, abort_conn=self.connection)
            except RateLimited as exc:
                record_error(model, 429, exc.detail[:200],
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._rate_limited(exc)
            except UpstreamStatus as exc:
                record_error(model, exc.status, exc.detail,
                             elapsed_ms=int((time.time() - t_start) * 1000))
                code = exc.status if str(exc.status).isdigit() else 502
                try:
                    code = int(code)
                except Exception:
                    code = 502
                if code < 400 or code > 599:
                    code = 502
                msg, etype = friendly_upstream_error(
                    _to_int_status(exc.status), exc.detail)
                return self._error(code, msg, etype)
            except Exception as exc:
                record_error(model, 502, str(exc),
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._error(502, "upstream stream error: %s" % exc)
            wall = int((time.time() - t_start) * 1000)
            first_at = result.get("first_chunk_at")
            first_ms = int((first_at - t_start) * 1000) if first_at else None
            _r0 = (result.get("choices") or [{}])[0]
            record_usage(model, result.get("usage"), stream=False,
                         elapsed_ms=wall, ttft_ms=first_ms,
                         gen_ms=(wall - first_ms) if first_ms is not None else None,
                         fp=fp, account=account.uid,
                         finish=_r0.get("finish_reason"),
                         finish_raw=holder.get("finish_reason_raw"),
                         refusal=((_r0.get("message") or {}).get("refusal")))
            return self._json(200, result)


def acc_realm(account):
    return account.realm if account else CURRENT_REALM


def main():
    global POOL, ACCOUNTS_DIR, API_KEY, SYSTEM_PROMPT, USAGE_DIR, USAGE_LOG, \
        USAGE_SUMMARY, SCHEDULER
    API_KEY_GENERATED = False
    ap = argparse.ArgumentParser(
        description="Qoder (qoder.com.cn / qoder.com) -> OpenAI-compatible proxy")
    ap.add_argument("--host", default=os.environ.get("HOST") or "127.0.0.1")
    # 8788 被 mimo-api-proxy.mjs 占用，8789 是 wb-proxy 默认端口；
    # Qoder 网关默认 8790。Docker 显式传 --port 8790。
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("PORT") or "8790"))
    ap.add_argument("--lan", action="store_true",
                    help="listen on every interface so other devices on the "
                         "LAN can reach it (implies --host 0.0.0.0 and forces "
                         "an api key)")
    ap.add_argument("--api-key",
                    default=os.environ.get("API_KEY")
                    or os.environ.get("QD_PROXY_KEY") or None,
                    help="require this bearer token on /v1/* (optional)")
    ap.add_argument("--system-prompt", default=DEFAULT_SYSTEM_PROMPT,
                    help="system message used when the request has none "
                         "(default: keep the official Qoder template prompt)")
    ap.add_argument("--usage-dir", default=None,
                    help="where to store usage.jsonl / usage-summary.json "
                         "(default: ./usage)")
    ap.add_argument("--accounts-dir",
                    default=os.environ.get("ACCOUNTS_DIR") or None,
                    help="where the per-account credential files live "
                         "(default: ./accounts)")
    ap.add_argument("--panel-password", default=None,
                    help="set the web panel password on startup (default: "
                         "admin)")
    args = ap.parse_args()

    if args.lan and args.host == "127.0.0.1":
        args.host = "0.0.0.0"
    if args.usage_dir:
        USAGE_DIR = os.path.abspath(args.usage_dir)
        USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
        USAGE_SUMMARY = os.path.join(USAGE_DIR, "usage-summary.json")

    # 拒绝启动第二份：Windows 上 SO_REUSEADDR 会让两个 socket 绑同一端口，
    # 连接被静默分流，极难诊断。
    try:
        probe = qoder_accounts.open_url(
            "http://%s:%d/health"
            % ("127.0.0.1" if args.host == "0.0.0.0" else args.host, args.port),
            timeout=2)
        existing = json.loads(probe.read().decode("utf-8"))
    except Exception:
        existing = None   # 没人应答 /health —— 让下面的 bind 决定
    if isinstance(existing, dict):
        # 只有我们的 /health 带账号池字段（"accounts"）。其它服务可能占用
        # 同端口也应答 /health JSON（例如 wb-proxy / mimo-api-proxy）。
        foreign = existing.get("service") not in (None, "qoder-proxy") \
            or "accounts" not in existing
        if foreign:
            who = existing.get("service") or "an unknown HTTP service"
            print()
            print("  [ERROR] port %d is already taken by another program: %s"
                  % (args.port, who))
            print("          qd-proxy itself is NOT running - nothing was "
                  "started.")
            print()
            print("  Fix: start qoder-proxy on a different port, e.g.")
            print("          start-qoder-proxy.bat %d" % (args.port + 1))
            print("          python qoder_proxy.py --port %d" % (args.port + 1))
            print()
            print("  Check who owns the port:  netstat -ano | findstr :%d"
                  % args.port)
            print()
            raise SystemExit(1)
        print()
        print("  [已有一个反代在 %d 端口运行，无需重复启动]" % args.port)
        print("  账号: %s @ %s" % (existing.get("uid", "?"),
                                   existing.get("domain", "?")))
        print("  看板: http://127.0.0.1:%d/" % args.port)
        print()
        print("  如果要重启: 先把原来那个窗口关掉（或结束 python 进程），"
              "再运行本程序。")
        print()
        return

    API_KEY = args.api_key
    SYSTEM_PROMPT = args.system_prompt
    if args.accounts_dir:
        ACCOUNTS_DIR = os.path.abspath(args.accounts_dir)
    # LAN 模式绝不能带默认密钥：网关花的是账号自己的上游额度，
    # 可猜的默认值等于让全网段的人白嫖。首次生成一次并持久化。
    if args.lan and not API_KEY:
        API_KEY, API_KEY_GENERATED = qoder_settings.ensure_launcher_key(
            ACCOUNTS_DIR)
    # 面板保存的 Key 优先于自动生成的 LAN Key（.bat 重启后浏览器改动仍生效）；
    # 命令行 --api-key 依然最高优先级。
    global API_KEY_FILE_SET
    saved_key, key_from_panel = qoder_settings.api_key_override(ACCOUNTS_DIR)
    if key_from_panel and not args.api_key:
        API_KEY = saved_key
        API_KEY_FILE_SET = True
    if args.panel_password:
        qoder_settings.set_panel_password(ACCOUNTS_DIR, args.panel_password)
        log("panel      : password set from --panel-password")
    elif qoder_settings.panel_password_is_default(ACCOUNTS_DIR):
        log("panel      : password is still the default 'admin' - change it "
            "in the panel")

    POOL = qoder_accounts.AccountPool(ACCOUNTS_DIR, log=log)
    POOL.load()
    load_persisted_realm()
    from qoder_scheduler import Scheduler
    SCHEDULER = Scheduler(POOL)
    SCHEDULER.start()
    # 积分采样：启动补采一次（当日尚无快照时），此后每天定点（默认 08:00）
    # 采一条。按自然日统计消耗 = 当日首末快照的 used 差值。
    threading.Thread(target=_startup_credit_snapshot, daemon=True).start()
    threading.Thread(target=_credits_daily_loop, daemon=True).start()
    # 余额守护：活跃账号按 next-probe 时间探测（正常 600s，低余额 45s），
    # 配合 record_usage 的内存扣减让两次探测之间余额近似实时。
    threading.Thread(target=_credit_guard_loop, daemon=True).start()

    if not POOL.accounts:
        # 永不静默采用本机客户端登录：先报告扫描结果，由用户在看板确认导入。
        try:
            detected = qoder_accounts.scan_desktop_credentials()
        except Exception:
            detected = []
        usable = [d for d in detected if d.get("valid")]
        if usable:
            log("no accounts yet - detected %d local credential(s), NOT importing"
                % len(usable))
            for d in usable:
                log("  available: %s  %s  %s" % (
                    (d.get("uid") or "?")[:8], d.get("nickname") or "(no name)",
                    d.get("realmName") or d.get("realm")))
            log("open the dashboard and click [Scan local credentials] to import")
        else:
            log("no accounts yet - no local Qoder credentials found on this machine")
        # 不在这里退出：看板必须可达，才能通过浏览器完成登录。
    rep = current_account()
    log("accounts   : %d total, %d usable"
        % (len(POOL.accounts), POOL.count_ready()))
    for account in POOL.accounts:
        log("  - %s  %s  %s  %s" % (
            account.uid[:8], account.nickname or "(no name)",
            account.realm, account.domain))
    log("store      : %s" % ACCOUNTS_DIR)
    log("credential : %s" % (rep.path if rep else "-"))
    log("account    : %s @ %s" % (rep.uid if rep else "-",
                                  rep.domain if rep else "-"))
    log("realm      : %s (%s)" % (
        CURRENT_REALM,
        "qoder.com" if CURRENT_REALM == "intl" else "qoder.com.cn"))
    log("catalog    : %s" % (BASEPROMPT_PATH if BASEPROMPT
                             else "baseprompt.json MISSING"))

    if args.host == "0.0.0.0":
        ips = local_ip_addresses() or ["<this-pc-ip>"]
        print()
        print("  " + "=" * 62)
        print("  LAN MODE - reachable from other devices")
        print()
        for ip in ips:
            print("    API       : http://%s:%s/v1" % (ip, args.port))
            print("    Dashboard : http://%s:%s/" % (ip, args.port))
        print()
        print("    API Key   : %s" % API_KEY)
        if API_KEY_GENERATED:
            print("                (newly generated & saved to "
                  "accounts/settings.json)")
        else:
            print("                (reused from accounts/settings.json)")
        print()
        print("    Open the dashboard (key already included):")
        print("      http://%s:%s/?key=%s" % (ips[0], args.port, API_KEY))
        print()
        print("    Clients: Base URL = the API address above, then paste "
              "the key.")
        print()
        print("    If nothing can connect, allow python through the")
        print("    firewall: run allow-firewall.bat once as administrator.")
        print("  " + "=" * 62)
        print()
        sys.stdout.flush()

    if not POOL.accounts:
        print()
        print("  " + "=" * 62)
        print("  NO ACCOUNTS YET")
        print()
        print("  Open the dashboard and click [+ 添加账号 (OAuth)]:")
        print("      http://127.0.0.1:%d/" % args.port)
        print()
        print("  The browser flow adds the account automatically.")
        print("  This window must stay open.")
        print("  " + "=" * 62)
        print()
        sys.stdout.flush()

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        # bind 前探测与 bind 之间端口被抢，或被不答 /health 的程序占着
        print()
        print("  [ERROR] failed to listen on %s:%d - %s"
              % (args.host, args.port, exc))
        print("          the port is reserved or held by another program;")
        print("          qd-proxy did NOT start.")
        print()
        print("  Fix: stop the program holding the port, or pick another "
              "port:")
        print("          netstat -ano | findstr :%d" % args.port)
        print("          start-qoder-proxy.bat %d" % (args.port + 1))
        print()
        raise SystemExit(1)
    log("listening  : http://%s:%d/v1  (api key: %s)"
        % (args.host, args.port, "on" if API_KEY else "off"))
    log("dashboard  : http://%s:%d/" % (args.host, args.port))
    # 进程生命周期内保持 handler 引用：SetConsoleCtrlHandler 存的是裸指针，
    # 回调被 GC 会在关窗时崩溃。
    _ctrl_handler = install_console_close_handler()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("bye")
    finally:
        try:
            server.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
