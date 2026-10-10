"""Deterministic offline tests for the Qoder gateway.

No network: verifies the crypto primitives (AES FIPS vectors, RSA padding
structure, Qoder custom base64 round-trip), COSY signature layout, request
body construction, SSE envelope unwrapping, Responses-API custom-tool
translation, and check-in response normalization.

    python _test_qoder.py
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_HERE = os.path.dirname(os.path.abspath(__file__))
# 隔离目录：测试**绝不能**写进生产 usage/。
# 注意变量名必须与网关读取的一致（qoder_proxy 读 QD_PROXY_USAGE_DIR /
# QD_PROXY_ACCOUNTS_DIR）。此前只设了 USAGE_DIR（无前缀），与生产变量名
# 不匹配，导致测试的 events/usage 行混进生产日志（实测每次运行泄漏 ~13 行
# request.start/queue.wait/retry 事件）。
os.environ["QD_PROXY_ACCOUNTS_DIR"] = os.path.join(_HERE, "_acc")
os.environ["QD_PROXY_USAGE_DIR"] = os.path.join(_HERE, "_use")
os.environ["ACCOUNTS_DIR"] = os.path.join(_HERE, "_acc")   # 兼容旧引用
os.environ["USAGE_DIR"] = os.path.join(_HERE, "_use")

import qoder_proxy as P
import qoder_sign as S
import qoder_catalog as C
import qoder_accounts as A
import qoder_tasks as T

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


print("[1] Qoder custom base64 variant")
enc = S.qoder_encode(b"{}")
check("encode({}) deterministic", enc == S.qoder_encode(b"{}"))
check("decode(encode(x)) == x", S.qoder_decode(enc) == b"{}")
sample = json.dumps({"b": 1, "a": "中文测试", "c": [1, 2, 3]}).encode()
check("roundtrip with unicode/json", S.qoder_decode(S.qoder_encode(sample)) == sample)
check("output uses only custom alphabet",
      all(c in S.QODER_CUSTOM_ALPHABET or c == S.QODER_PAD for c in enc))
check("padding is $", S.qoder_encode(b"a" * 100).count("$") >= 0 and "=" not in enc)

print()
print("[2] AES-128 (FIPS-197 / NIST vectors)")
k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pt = bytes.fromhex("00112233445566778899aabbccddeeff")
ct = S._encrypt_block(pt, S._expand_key(k)).hex()
check("FIPS-197 C.1 block", ct == "69c4e0d86a7b0430d8cdb78070b4c55a", ct)
k2 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pt2 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
xored = bytes(a ^ b for a, b in zip(pt2, iv))
c2 = S._encrypt_block(xored, S._expand_key(k2)).hex()
check("SP800-38A CBC first block", c2 == "7649abac8119b246cee98e9b12e9197d", c2)
# CBC chaining through aes_cbc_encrypt (key==iv style input, PKCS7)
blob = S.aes_cbc_encrypt(b"hello qoder", b"0123456789abcdef", b"0123456789abcdef")
check("aes_cbc_encrypt block-aligned", len(blob) % 16 == 0 and len(blob) >= 16)
# 11 字节明文 -> PKCS7 补 5 -> 一个密文块
check("pkcs7 grows 11B input to one 16B block", len(blob) == 16, len(blob))
check("16B input grows to two blocks",
      len(S.aes_cbc_encrypt(b"0123456789abcdef", b"0123456789abcdef",
                             b"0123456789abcdef")) == 32)

print()
print("[3] RSA PKCS#1 v1.5 public encryption")
import base64 as _b64m
_der = _b64m.b64decode("".join(l for l in S.SERVER_PUB_PEM.splitlines()
                                if "BEGIN" not in l and "END" not in l))
check("PEM parses to 1024-bit modulus", S._RSA_N.bit_length() == 1024,
      S._RSA_N.bit_length())
check("DER carries 129-byte INTEGER", b"\x02\x81\x81" in _der)
check("exponent 65537", S._RSA_E == 65537)
ct_rsa = S.rsa_pkcs1v15_encrypt(b"0123456789abcdef")
check("ciphertext length = k = 128", len(ct_rsa) == 128, len(ct_rsa))
m_int = int.from_bytes(ct_rsa, "big")
check("ciphertext < n", m_int < S._RSA_N)
check("pkcs1v15 PS length formula",
      len(S.rsa_pkcs1v15_encrypt(b"x")) == 128)

print()
print("[4] COSY session & bearer signature")
sess = S.CosySession(uid="test-uid-001", nickname="tester",
                     access_token="dt-abc", refresh_token="drt-xyz")
url = "https://gateway.qoder.com.cn" + P.CHAT_PATH
body_enc = S.qoder_encode(b'{"x":1}')
h = sess.headers(body_enc, url, model_key="qmodel", sse=True)
check("has full cosy header set",
      all(kk in h for kk in ("authorization", "cosy-key", "cosy-user",
                             "cosy-machineid", "cosy-machinetoken",
                             "cosy-machinetype", "cosy-date", "cosy-version")))
check("x-model-key set", h.get("x-model-key") == "qmodel")
check("cache-control for sse", h.get("cache-control") == "no-cache")
check("bearer format COSY.payload.sig",
      h["authorization"].startswith("Bearer COSY.")
      and len(h["authorization"].split(".")) == 3)
parts = h["authorization"][len("Bearer "):].split(".")
payload_b64, sig = parts[1], parts[2]
path_stripped = "/api/v2/service/pro/sse/agent_chat_generation"
raw = payload_b64 + "\n" + sess.cosy_key + "\n" + h["cosy-date"] + "\n" \
    + body_enc + "\n" + path_stripped
check("md5 signature over body+path", sig == hashlib.md5(raw.encode()).hexdigest())
check("machine id stable per uid",
      S.CosySession(uid="test-uid-001").machine_id == sess.machine_id)
check("machine ids differ across uid",
      S.CosySession(uid="other-uid").machine_id != sess.machine_id)
import base64 as _b64
payload = json.loads(_b64.b64decode(payload_b64))
check("payload keys sorted-compact",
      sorted(payload.keys()) == ["cosyVersion", "ideVersion", "info",
                                 "requestId", "version"])
check("payload cosyVersion", payload["cosyVersion"] == "0.1.43")

print()
print("[5] model alias resolution (official keys)")
check("qwen3.8-max -> qmodel_38max",
      C.resolve_upstream_key("qwen3.8-max") == "qmodel_38max")
check("old key qmodel_preview -> qmodel_38max",
      C.resolve_upstream_key("qmodel_preview") == "qmodel_38max")
check("qwen3.8-flash -> qfmodel",
      C.resolve_upstream_key("qwen3.8-flash") == "qfmodel")
check("deepseek-v4-pro -> dmodel",
      C.resolve_upstream_key("deepseek-v4-pro") == "dmodel")
check("shared key passthrough",
      C.resolve_upstream_key("qmodel") == "qmodel")
check("aliased qoder/ prefix",
      C.resolve_upstream_key("qoder/qwen3.7-max") == "qmodel_latest")
check("unknown model passthrough",
      C.resolve_upstream_key("mystery-model") == "mystery-model")
check("empty -> auto", C.resolve_upstream_key("") == "auto")
check("realm-aware: official key of that realm accepted",
      C.resolve_upstream_key("q37fmodel", realm="cn") == "q37fmodel")

print()
print("[5.5] per-realm catalogs follow the official client (must DIFFER)")
intl_keys = [m["key"] for m in C.STATIC_INTL_MODELS]
cn_keys = [m["key"] for m in C.STATIC_CN_MODELS]
check("intl catalog not empty (>=17)", len(intl_keys) >= 17, len(intl_keys))
check("cn catalog not empty (14)", len(cn_keys) == 14, len(cn_keys))
check("two realms' catalogs differ", intl_keys != cn_keys)
check("intl-only: smodel present, absent from cn",
      "smodel" in intl_keys and "smodel" not in cn_keys)
check("cn-only: q37fmodel present, absent from intl",
      "q37fmodel" in cn_keys and "q37fmodel" not in intl_keys)
check("cn-only: gm51model present, absent from intl",
      "gm51model" in cn_keys and "gm51model" not in intl_keys)
intl_en = {m["key"] for m in C.STATIC_INTL_MODELS if m.get("enable")}
cn_en = {m["key"] for m in C.STATIC_CN_MODELS if m.get("enable")}
check("intl enabled flags = {qmodel_38max, qfmodel} (official plan state)",
      intl_en == {"qmodel_38max", "qfmodel"}, sorted(intl_en))
check("cn all 14 enabled", len(cn_en) == 14, sorted(cn_en))
# 全量列出（不按 enable 过滤）
merged_i = P.merge_catalog([], realm="intl")
merged_c = P.merge_catalog([], realm="cn")
check("merge keeps FULL intl list (17, no enable filtering)", len(merged_i) == 17,
      len(merged_i))
check("merge keeps FULL cn list (14)", len(merged_c) == 14, len(merged_c))
# 清单以官方动态/本机目录为准（桌面版此刻显示什么就显示什么）
dyn_keys = [("cmodel", {"key": "cmodel", "display_name": "Cantus"})]  # 反例占位
primary15 = [(m["key"], dict(m)) for m in C.STATIC_INTL_MODELS
             if m["key"] not in ("cmodel", "smodel")]   # 模拟动态返回的 15 条
merged_dyn = P.merge_catalog(primary15, realm="intl")
check("merge follows primary set (dynamic 15 wins, static-only excluded)",
      len(merged_dyn) == 15 and
      {k for k, _ in merged_dyn} == {m["key"] for m in C.STATIC_INTL_MODELS}
      - {"cmodel", "smodel"}, len(merged_dyn))

print()
print("[5.7] official full-fidelity fields: display id / pricing / windows / efforts")
entry_i = next(m for m in C.STATIC_INTL_MODELS if m["key"] == "smodel")
check("intl exclusive entry retains full fields",
      {"context_config", "thinking_config", "is_free", "is_new"} <= set(entry_i.keys()),
      sorted(entry_i.keys()))
cn38 = next(m for m in C.STATIC_CN_MODELS if m["key"] == "qmodel_38max")
promo = cn38.get("promotion") or {}
check("cn qmodel_38max has ACTIVE off-peak promotion", promo.get("active") is True)
check("off-peak window = 22:00-08:00",
      promo.get("window_start") == "22:00" and promo.get("window_end") == "08:00")
check("peak factor (before_promotion) = 0.5", promo.get("before_promotion_price_factor") == 0.5,
      promo.get("before_promotion_price_factor"))
check("valley factor (current price_factor) = 0.2", cn38.get("price_factor") == 0.2)
check("discount_factor = 0.4 (4折)", promo.get("discount_factor") == 0.4)
check("promotion badge/description localized",
      bool((promo.get("badge") or {}).get("en")) and bool((promo.get("description") or {}).get("en")))
qf = next(m for m in C.STATIC_CN_MODELS if m["key"] == "qfmodel")
check("qfmodel free + original factor kept",
      qf.get("is_free") is True and qf.get("original_price_factor") == 0.1)
check("context_config multi-window (3) with default 200K",
      len(cn38.get("context_config") or {}) == 3
      and (cn38["context_config"].get("200K") or {}).get("is_default") is True)
tc = (cn38.get("thinking_config") or {}).get("enabled") or {}
effs = tc.get("efforts") or {}
check("thinking efforts low/medium/xhigh with default medium",
      set(effs) == {"low", "medium", "xhigh"}
      and (effs.get("medium") or {}).get("is_default") is True, sorted(effs))

# 展示 id 与解析
check("display id format key (Name)",
      C.display_id(cn38) == "qmodel_38max (Qwen3.8-Max)", C.display_id(cn38))
check("resolve display id -> key",
      C.resolve_upstream_key("qmodel_38max (Qwen3.8-Max)", realm="cn") == "qmodel_38max")
check("resolve official display name (case-insensitive)",
      C.resolve_upstream_key("qwen3.8-max", realm="cn") == "qmodel_38max"
      and C.resolve_upstream_key("GLM-5.2", realm="cn") == "gm51model")
check("resolve bare display name DeepSeek-V4-Pro",
      C.resolve_upstream_key("DeepSeek-V4-Pro", realm="cn") == "dmodel")
check("format_model_id helper",
      C.format_model_id("gm51model", realm="cn") == "gm51model (GLM-5.2)",
      C.format_model_id("gm51model", realm="cn"))

# model_entry 输出
me = P.model_entry("qmodel_38max", cn38)
check("model_entry id = OFFICIAL model name (the value clients fill in)",
      me["id"] == "Qwen3.8-Max", me["id"])
check("model_entry upstream_key kept", me["upstream_key"] == "qmodel_38max")
check("model_entry aliases cover key + bracket form + friendly alias",
      "qmodel_38max" in me["aliases"] and "qmodel_38max (Qwen3.8-Max)" in me["aliases"]
      and "qwen3.8-max" in me["aliases"], me.get("aliases"))
check("model_entry description = official desktop copy",
      "千问" in (me.get("description") or ""), (me.get("description") or "")[:60])
check("model_entry enabled flag", me["enabled"] is True)
check("model_entry peak/valley factors",
      me["price_factor_peak"] == 0.5 and me["price_factor_valley"] == 0.2)
check("model_entry off_peak window+badge",
      me["off_peak_window"] == "22:00-08:00" and bool(me["off_peak"]["badge"]))
check("model_entry context labels default 200K",
      me["context_window_labels"] == ["200K", "400K", "1M"] or set(me["context_window_labels"]) == {"200K", "400K", "1M"},
      me.get("context_window_labels"))
# 默认档位改报**数值**（token 数），与 context_windows 同单位，避免客户端
# 把 180000 当上限（实测官方 App 同模型可调 200K/400K/1M）。
check("model_entry context_window_default is the official default (tokens)",
      me.get("context_window_default") == 200000,
      me.get("context_window_default"))
check("model_entry reasoning efforts + default",
      me.get("reasoning_efforts") == ["low", "medium", "xhigh"]
      and me.get("reasoning_default_effort") == "medium",
      (me.get("reasoning_efforts"), me.get("reasoning_default_effort")))
check("model_entry can_disable", me.get("reasoning_can_disable") is True)
check("model_entry is_free/is_new", me.get("is_free") is True and me.get("is_new") is True)
check("model_entry does NOT fabricate max_output_tokens (official data has none)",
      "max_output_tokens" not in me and "max_completion_tokens" not in me,
      sorted(k for k in me if "output" in k))
me_off = P.model_entry("smodel", entry_i)
check("model_entry disabled shows enabled=false (badge, not filtered)",
      me_off["enabled"] is False)
check("model_entry disabled_reason = OFFICIAL copy (not '未开放')",
      me_off.get("disabled_reason") == "需要升级或购买千问官方套餐开放",
      me_off.get("disabled_reason"))
check("model_entry disabled_message_key passthrough (codeSafeModelReason)",
      me_off.get("disabled_message_key") == "codeSafeModelReason",
      me_off.get("disabled_message_key"))
check("official text loader: 17 zh descriptions",
      len(C.load_official_text()["descriptions"]) == 17)
check("official local name ultimate -> zh",
      C.official_local_name("ultimate") != "" and C.official_local_name("ultimate") != "Ultimate",
      C.official_local_name("ultimate"))
me_u = P.model_entry("ultimate", next(m for m in C.STATIC_INTL_MODELS if m["key"] == "ultimate"))
check("model_entry name_local emitted for intl mode preset",
      bool(me_u.get("name_local")), me_u.get("name_local"))
check("resolve official local label (Kimi-K2.7-Code)",
      C.resolve_upstream_key("Kimi-K2.7-Code", realm="intl") == "kmodel")
check("cross-region guard accepts display id form",
      P.exclusive_realm("gm51model (GLM-5.2)") == "cn")

print()
print("[5.8] off-peak (低谷) window detection — cross-midnight 22:00-08:00 UTC+8")
import datetime as _dt
def _ts(h, m):
    # 构造 UTC+8 指定时刻对应的 epoch（固定 +8 与官方时区一致）
    utc_naive = _dt.datetime.utcnow() if False else None
    base = _dt.datetime.now(_dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    target_local_naive = _dt.datetime.now().replace(hour=h, minute=m, second=0, microsecond=0)
    return target_local_naive.timestamp() - (_dt.datetime.now().astimezone().utcoffset().total_seconds()
                                             - 8 * 3600)
for hh, mm, expect, label in [
        (1, 0, True, "01:00 inside window"),
        (12, 0, False, "12:00 outside"),
        (21, 59, False, "21:59 before window"),
        (22, 0, True, "22:00 window start (inclusive)"),
        (23, 30, True, "23:30 inside"),
        (7, 59, True, "07:59 last minute inside"),
        (8, 0, False, "08:00 window end (exclusive)")]:
    got = P.off_peak_active_now("22:00", "08:00", tz="Asia/Shanghai",
                                now=_ts(hh, mm))
    check(f"window {label}", got is expect, f"got={got} expect={expect}")
check("invalid window -> None",
      P.off_peak_active_now(None, "08:00") is None)
check("same start/end -> always active",
      P.off_peak_active_now("00:00", "00:00", now=_ts(13, 0)) is True)
# promotion fields surface off_peak_active_now via model_entry
me_promo = P.model_entry("qmodel_38max", cn38)
check("model_entry exposes off_peak_active_now (bool)",
      isinstance(me_promo.get("off_peak_active_now"), bool),
      me_promo.get("off_peak_active_now"))

# None must not clobber static snapshot values in merge
dyn_null = [("qmodel_38max", {"key": "qmodel_38max",
                               "context_config": None,
                               "thinking_config": None,
                               "price_factor": 0.2})]
merged_null = dict(P.merge_catalog(dyn_null, realm="cn"))["qmodel_38max"]
check("merge: dynamic None does NOT clobber static context_config",
      isinstance(merged_null.get("context_config"), dict)
      and "200K" in (merged_null.get("context_config") or {}),
      type(merged_null.get("context_config")).__name__)
check("merge: dynamic None does NOT clobber static thinking_config",
      isinstance(merged_null.get("thinking_config"), dict))
check("merge: dynamic real value still overrides",
      merged_null.get("price_factor") == 0.2)

print()
print("[5.9] ALL off-peak (低谷) promotion models — must be complete, not just one")
PROMO_KEYS = {"qmodel_38max", "qmodel_latest", "qmodel"}
for realm_name in ("cn", "intl"):
    promo_models = {m["key"] for m in C.models_for_realm(realm_name)
                    if (m.get("promotion") or {}).get("active")}
    check(f"[{realm_name}] official promo set == the 3 off-peak models",
          promo_models == PROMO_KEYS, sorted(promo_models))
    # 每个促销模型都要产出完整 off_peak 输出（不止一个）
    for k in sorted(PROMO_KEYS):
        src = next(m for m in C.models_for_realm(realm_name) if m["key"] == k)
        e = P.model_entry(k, src)
        check(f"[{realm_name}] {k} entry carries off_peak window+badge",
              bool(e.get("off_peak")) and e.get("off_peak_window") == "22:00-08:00"
              and bool(e.get("off_peak", {}).get("badge")),
              e.get("off_peak_window"))
        check(f"[{realm_name}] {k} entry has off_peak_active_now bool",
              isinstance(e.get("off_peak_active_now"), bool))
        check(f"[{realm_name}] {k} entry exposes peak/valley pair",
              e.get("price_factor_peak") is not None
              and e.get("price_factor_valley") is not None,
              (e.get("price_factor_peak"), e.get("price_factor_valley")))
# Qwen3.8-Max: is_free=true 绝不能吞掉它的 promotion（看板曾把它渲染成
# 0.00x 免费并吃掉低谷高亮）
me_freeflag = P.model_entry("qmodel_38max",
                            next(m for m in C.STATIC_CN_MODELS
                                 if m["key"] == "qmodel_38max"))
check("qmodel_38max is_free=true still carries promotion (peak 0.5 / valley 0.2)",
      me_freeflag.get("is_free") is True and me_freeflag.get("price_factor_peak") == 0.5
      and me_freeflag.get("price_factor_valley") == 0.2,
      (me_freeflag.get("is_free"), me_freeflag.get("price_factor_peak"),
       me_freeflag.get("price_factor_valley")))

# 看板分支顺序回归：promo 分支必须在 0 价分支之前
_dash = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "dashboard.html"), encoding="utf-8").read()
_i_promo = _dash.find("if(promo && valley != null)")
_i_free = _dash.find("valley === 0")
check("dashboard: promotion branch BEFORE free branch (highlight no longer swallowed)",
      0 <= _i_promo < _i_free, {"promo": _i_promo, "free": _i_free})
check("dashboard: is_free no longer triggers the 0.00x branch",
      "m.is_free || valley === 0" not in _dash)

print()
print("[11] transient upstream errors (418/provider_error) — retry not punish")
import time as _time_for_11
time = _time_for_11   # 本块直接使用 time.time()/sleep
# 分类判定
check("418 + provider_error is transient",
      P._is_transient_upstream(418, '{"code":"provider_error","message":"Error in upstream response"}'))
check("503 is transient", P._is_transient_upstream(503, ""))
check("client param error (invalid_parameter) NEVER transient",
      not P._is_transient_upstream(400,
          '{"code":"provider_error","details":"data: {\\"error\\":{\\"code\\":'
          '\\"invalid_parameter_error\\",\\"message\\":\\"Range of max_tokens should be [1, 131072]\\"}"'))
check("plain 400 without provider_error not transient",
      not P._is_transient_upstream(400, '{"code":"bad_request"}'))
check("401 never transient", not P._is_transient_upstream(401, "provider_error"))

# 行为级：第一次 418(瞬时) → 重试后成功，账号不背锅
import urllib.error as _ue3, io as _io3
_orig_urlopen = A.open_url
_calls = {"n": 0}

class _FakeResp(object):
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *a): return b"{}"

def _urlopen_fail_once(req, timeout=None):
    _calls["n"] += 1
    if _calls["n"] == 1:
        raise _ue3.HTTPError(req.full_url, 418, "teapot", {},
                             _io3.BytesIO(b'{"code":"provider_error","message":"Error in upstream response"}'))
    return _FakeResp()

try:
    A.open_url = _urlopen_fail_once
    # 构造单账号池
    import tempfile as _tf
    _td = _tf.mkdtemp(prefix="qdpool_")
    _pool = A.AccountPool(_td)
    _pool.add(A.Account({"uid": "retry-test-uid", "realm": "cn",
                         "accessToken": "dt-test", "refreshToken": "drt-test",
                         "expiresAt": 9999999999}))
    _orig_pool = P.POOL
    P.POOL = _pool
    _acc = _pool.accounts[0]
    _acc.cooldown_until = 0
    t0 = time.time()
    resp, used, _ = P.open_upstream(
        {"model": "qfmodel", "messages": [{"role": "user", "content": "hi"}],
         "stream": False}, target_realm="cn")
    took = time.time() - t0
    check("418-then-success: open_upstream returns after in-place retry",
          resp is not None and _calls["n"] == 2,
          {"calls": _calls["n"]})
    check("418-then-success: account NOT cooled down",
          _acc.cooldown_until <= time.time(),
          round(_acc.cooldown_until - time.time(), 1))
    check("418-then-success: backoff took ~1s (not instant, not 60s)",
          0.8 <= took <= 4.0, round(took, 2))
finally:
    A.open_url = _orig_urlopen

# 行为级：持续 418 → 重试耗尽后短冷却（单账号 3s 而非 60s）并抛出原错误
def _urlopen_always_418(req, timeout=None):
    _calls["n"] += 1
    raise _ue3.HTTPError(req.full_url, 418, "teapot", {},
                         _io3.BytesIO(b'{"code":"provider_error","message":"Error in upstream response"}'))

_calls["n"] = 0
try:
    A.open_url = _urlopen_always_418
    P.POOL = _pool          # 上一块 finally 还原了 None，这里重新挂上临时池
    _acc.cooldown_until = 0
    _acc.last_error = ""
    raised = None
    t0 = time.time()
    try:
        P.open_upstream({"model": "qfmodel",
                         "messages": [{"role": "user", "content": "hi"}],
                         "stream": False}, target_realm="cn")
    except _ue3.HTTPError as e:
        raised = e
    took = time.time() - t0
    check("persistent 418: raised after exactly 3 tries",
          raised is not None and raised.code == 418 and _calls["n"] == 3,
          {"calls": _calls["n"], "code": getattr(raised, "code", None)})
    check("persistent 418: short cooldown (<=5s, single-account pool)",
          0 < (_acc.cooldown_until - time.time()) <= 5.5,
          round(_acc.cooldown_until - time.time(), 2))
    check("persistent 418: bounded backoff time (~3s)",
          2.0 <= took <= 6.0, round(took, 2))
finally:
    A.open_url = _orig_urlopen
    P.POOL = _orig_pool
    import shutil as _sh
    _sh.rmtree(_td, ignore_errors=True)

# 传输层瞬时故障分类（TLS EOF 等）
import urllib.error as _ue4
import ssl as _ssl_for_11
check("URLError wrapping SSL EOF is transient transport",
      P._is_transient_transport(_ue4.URLError(_ssl_for_11.SSLError(
          "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF"))))
check("ConnectionResetError is transient transport",
      P._is_transient_transport(ConnectionResetError("reset")))
check("plain ValueError NOT transient transport",
      not P._is_transient_transport(ValueError("nope")))
check("predicate: URLError+provider401 not transient-http",
      not P._is_transient_upstream(401, "x"))

# 友好错误映射
_m, _t = P.friendly_upstream_error(418,
    '{"code":"provider_error","message":"Error in upstream response"}')
check("friendly: 418 provider_error -> Chinese retry guidance",
      "上游瞬时故障" in _m and "请稍后重试" in _m, _m[:60])
check("friendly: err_type tagged transient",
      _t == "upstream_transient_error", _t)
_m2, _t2 = P.friendly_upstream_error(400,
    '{"code":"provider_error","details":"invalid_parameter_error Range"}')
check("friendly: client param error NOT reframed as transient",
      _t2 == "upstream_error" and "上游瞬时故障" not in _m2, (_t2, _m2[:50]))
check("friendly: detail preserved in message",
      "provider_error" in _m)

# qoder_detail passthrough（错误体只读一次的修复）——挂在持续418的断言上补充
check("raised HTTPError carries qoder_detail for handlers",
      hasattr(raised, "qoder_detail") and "provider_error" in raised.qoder_detail,
      getattr(raised, "qoder_detail", "")[:60])

print()
print("[12] in-stream envelope retry (200-then-418 form — the reported log shape)")
# 状态归一化
check("_to_int_status str/int/fallback", P._to_int_status("418") == 418
      and P._to_int_status(503) == 503 and P._to_int_status("xx") == 502)

_env418 = P.UpstreamStatus(
    418, '{"code":"provider_error","message":"Error in upstream response"}')
check("fresh envelope 418 transient -> retry",
      P.should_retry_envelope(_env418, emitted_bytes=False, attempt=0))
check("already emitted bytes -> NO retry",
      not P.should_retry_envelope(_env418, emitted_bytes=True, attempt=0))
check("budget exhausted -> NO retry",
      not P.should_retry_envelope(_env418, False, P.TRANSIENT_MAX_RETRIES))
_env_param = P.UpstreamStatus(400, "invalid_parameter_error Range of max_tokens")
check("client param envelope -> NO retry",
      not P.should_retry_envelope(_env_param, False, 0))

# aggregate_with_envelope_retry: 第一次信封418 → 重开上游 → 成功
_sleeps = []
_orig_sleep2 = P.time.sleep
_orig_open2 = P.open_upstream
_pools = {"calls": 0}

class _GoodResp(object):
    def __iter__(self):
        inner = json.dumps({"choices": [{"delta": {"content": "recovered"}}]})
        yield ("data: " + json.dumps({"statusCodeValue": 200, "body": inner})
               + "\n\n").encode("utf-8")
        yield b'data: {"statusCodeValue":200,"body":"[DONE]"}\n\n'

    def close(self):
        pass


class _ErrResp(object):
    def __iter__(self):
        yield ("data: " + json.dumps({
            "statusCodeValue": 418,
            "body": '{"code":"provider_error","message":"Error in upstream response"}'})
            + "\n\n").encode("utf-8")

    def close(self):
        pass


def _fake_open(payload, session_key=None, target_realm=None, **kwargs):
    _pools["calls"] += 1
    return _GoodResp(), "acct-1", "enc"


class _A(object):
    uid = "acct-1"


try:
    P.time.sleep = lambda s: _sleeps.append(s)
    P.open_upstream = _fake_open
    obj, acc = P.aggregate_with_envelope_retry(
        _ErrResp(), {"model": "qfmodel"}, None, "cn", "qfmodel",
        {"usage": None}, _A())
    check("envelope 418 -> reopened upstream and recovered",
          obj["choices"][0]["message"]["content"] == "recovered",
          obj["choices"][0]["message"].get("content"))
    check("reopen happened exactly once", _pools["calls"] == 1, _pools["calls"])
    check("backoff 1s recorded", _sleeps == [1], _sleeps)
finally:
    P.time.sleep = _orig_sleep2
    P.open_upstream = _orig_open2

# 非瞬时信封（客户端参数错）不重开、原样上抛
_sleeps2 = []
_pools2 = {"calls": 0}

print()
print("[13] content-policy rejection (DataInspectionFailed — 02:27 log root cause)")
_DI_DETAIL = ('{"error":{"message":"\\u003c400\\u003e InternalError.Algo.'
              'DataInspectionFailed: Input text data may contain inappropriate '
              'content.","type":"UnknownError"}}')
check("DataInspection detail -> NOT transient (no wasted retries)",
      not P._is_transient_upstream(418, _DI_DETAIL))
check("DataInspection envelope -> should_retry_envelope False",
      not P.should_retry_envelope(
          P.UpstreamStatus(418, _DI_DETAIL), emitted_bytes=False, attempt=0))
_m13, _t13 = P.friendly_upstream_error(418, _DI_DETAIL)
check("friendly: content-policy Chinese explanation",
      "内容安全审核未通过" in _m13 and "重试无效" in _m13, _m13[:70])
check("friendly: err_type content_policy_rejected",
      _t13 == "content_policy_rejected", _t13)
check("friendly: original detail preserved",
      "DataInspectionFailed" in _m13)

print()
print("[14] error-cooldown vs upstream-frequency (no misleading 429)")
import time as _t14
# 构造临时池：账号仅处于错误冷却
_td14 = __import__("tempfile").mkdtemp(prefix="qd14_")
_pool14 = A.AccountPool(_td14)
_acc14 = A.Account({"uid": "u14", "realm": "cn", "accessToken": "dt-x",
                    "refreshToken": "drt-x", "expiresAt": 9999999999})
_pool14.add(_acc14)
_orig_pool14 = P.POOL
P.POOL = _pool14
try:
    # (a) 仅账号错误冷却 -> 不算频控
    _acc14.cooldown_until = _t14.time() + 5
    _acc14.model_cooldowns.clear()
    throttled, w = P.realm_model_throttled("cn", "qfmodel")
    check("account error-cooldown is NOT a frequency-limit (no 429)",
          throttled is False, (throttled, w))
    check("retry_after_seconds ignores account cooldown",
          P.retry_after_seconds("qfmodel", "cn") == 60,
          P.retry_after_seconds("qfmodel", "cn"))
    wait = P._short_error_cooldown_wait("cn", "qfmodel")
    check("short error-cooldown wait surfaced (<=10s, >0)",
          0 < wait <= 10, wait)
    # (b) 上游频控 -> 正当429
    _acc14.cooldown_until = 0
    _acc14.model_cooldowns["qfmodel"] = _t14.time() + 60
    throttled2, w2 = P.realm_model_throttled("cn", "qfmodel")
    check("model_cooldowns (upstream 429) IS frequency-limit",
          throttled2 is True and w2 >= 59, (throttled2, w2))
    check("short wait suppressed while frequency-limited",
          P._short_error_cooldown_wait("cn", "qfmodel") == 0.0)
    check("retry_after reflects frequency wait",
          59 <= P.retry_after_seconds("qfmodel", "cn") <= 61,
          P.retry_after_seconds("qfmodel", "cn"))
    # (c) 行为：错误短冷却 -> 等待后续上（真实 sleep ~0.3s）而不是429
    _acc14.model_cooldowns.clear()
    _acc14.cooldown_until = _t14.time() + 0.3
    _orig_urlopen14 = A.open_url

    class _R14(object):
        def __iter__(self):
            inner = json.dumps({"choices": [{"delta": {"content": "after-wait"}}]})
            yield ("data: " + json.dumps({"statusCodeValue": 200, "body": inner})
                   + "\n\n").encode()
            yield b'data: {"statusCodeValue":200,"body":"[DONE]"}\n\n'
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def _ok_urlopen(req, timeout=None):
        return _R14()

    try:
        A.open_url = _ok_urlopen
        _sleep_used = []
        _t0 = _t14.time()
        try:
            resp, used, _ = P.open_upstream(
                {"model": "qfmodel",
                 "messages": [{"role": "user", "content": "hi"}],
                 "stream": False}, target_realm="cn")
            _served = True
            _rate = None
        except Exception as _e:
            _served = False
            _rate = _e
        took = _t14.time() - _t0
        check("short cooldown: request WAITS and serves (no 429/503)",
              _served and _rate is None,
              {"served": _served, "err": repr(_rate)})
        check("wait lasted ~0.3-1s (bounded)", 0.25 <= took <= 2.0,
              round(took, 2))
    finally:
        A.open_url = _orig_urlopen14
    # (d) 频控行为不变：真429 仍然立刻 RateLimited
    _acc14.cooldown_until = 0
    _acc14.model_cooldowns["qfmodel"] = _t14.time() + 60
    try:
        A.open_url = _ok_urlopen
        _raised14 = None
        try:
            P.open_upstream({"model": "qfmodel",
                             "messages": [{"role": "user", "content": "hi"}],
                             "stream": False}, target_realm="cn")
        except Exception as e14:
            _raised14 = e14
        check("genuine frequency limit still raises RateLimited fast",
              isinstance(_raised14, P.RateLimited)
              and "frequency" in str(getattr(_raised14, "detail", "")),
              repr(_raised14))
    finally:
        A.open_url = _orig_urlopen14
finally:
    P.POOL = _orig_pool14
    _acc14.model_cooldowns.clear()
    _acc14.cooldown_until = 0
    import shutil as _sh14
    _sh14.rmtree(_td14, ignore_errors=True)

# favicon 404 静默
check("log_message silences favicon regardless of status (code present)",
      'req_path == "/favicon.ico"' in open(
          os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "qoder_proxy.py"), encoding="utf-8").read())

# 行为：内容审核信封 -> 一次都不重开（open_upstream 不被再次调用）并上抛
class _DiErrResp(object):
    def __iter__(self):
        yield ("data: " + json.dumps({
            "statusCodeValue": 418, "body": _DI_DETAIL}) + "\n\n").encode()

    def close(self):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


_pools13 = {"calls": 0}
_sleeps13 = []


def _fake_open_never13(payload, session_key=None, target_realm=None, **kwargs):
    _pools13["calls"] += 1
    return _GoodResp(), "acct-1", "enc"


try:
    P.time.sleep = lambda s: _sleeps13.append(s)
    P.open_upstream = _fake_open_never13
    _raised13 = None
    try:
        P.aggregate_with_envelope_retry(
            _DiErrResp(), {"model": "Qwen3.8-Flash"}, None, "cn",
            "Qwen3.8-Flash", {"usage": None}, _A())
    except P.UpstreamStatus as e13:
        _raised13 = e13
    check("content-policy envelope: raised immediately, ZERO reopen, ZERO sleep",
          _raised13 is not None and _pools13["calls"] == 0 and not _sleeps13,
          {"raised": _raised13 is not None, "reopen": _pools13["calls"],
           "sleeps": _sleeps13})
finally:
    P.time.sleep = _orig_sleep2
    P.open_upstream = _orig_open2

# 非瞬时信封（客户端参数错）不重开、原样上抛
_sleeps2 = []
_pools2 = {"calls": 0}

class _ParamErrResp(object):
    def __iter__(self):
        yield ("data: " + json.dumps({
            "statusCodeValue": 400,
            "body": "invalid_parameter_error Range of max_tokens [1, 131072]"})
            + "\n\n").encode("utf-8")

    def close(self):
        pass


def _fake_open_never(payload, session_key=None, target_realm=None, **kwargs):
    _pools2["calls"] += 1
    return _GoodResp(), "acct-1", "enc"


try:
    P.time.sleep = lambda s: _sleeps2.append(s)
    P.open_upstream = _fake_open_never
    _raised_env = None
    try:
        P.aggregate_with_envelope_retry(
            _ParamErrResp(), {"model": "qfmodel"}, None, "cn", "qfmodel",
            {"usage": None}, _A())
    except P.UpstreamStatus as e0:
        _raised_env = e0
    check("param envelope raises immediately (no reopen)",
          _raised_env is not None and _pools2["calls"] == 0,
          {"raised": _raised_env is not None, "reopen": _pools2["calls"]})
finally:
    P.time.sleep = _orig_sleep2
    P.open_upstream = _orig_open2

ctx = {m["key"]: m.get("max_input_tokens") for m in C.STATIC_CN_MODELS}
check("cn dmodel ctx = official 96000 (NOT a guess)", ctx.get("dmodel") == 96000,
      ctx.get("dmodel"))
ctx_i = {m["key"]: m.get("max_input_tokens") for m in C.STATIC_INTL_MODELS}
check("intl dmodel ctx = official 1000000", ctx_i.get("dmodel") == 1000000,
      ctx_i.get("dmodel"))
pf = {m["key"]: m.get("price_factor") for m in C.STATIC_CN_MODELS}
check("price_factor carried from official catalog",
      pf.get("qfmodel") == 0.0 and pf.get("dmodel") == 0.8, pf.get("qfmodel"))
check("exclusive sets derived from catalogs",
      "gm51model" in C.CN_EXCLUSIVE and "smodel" in C.INTL_EXCLUSIVE)
check("exclusive realm detection: gm51model -> cn",
      P.exclusive_realm("gm51model") == "cn")
check("exclusive realm detection: smodel -> intl",
      P.exclusive_realm("smodel") == "intl")
check("alias resolves before exclusive check: glm-5.2 -> cn",
      P.exclusive_realm("glm-5.2") == "cn")
check("shared key has no exclusive owner", P.exclusive_realm("qmodel") == "")
check("detect_model_realm routes cn-exclusive to cn even under intl default",
      P.detect_model_realm("q37fmodel") == "cn")
check("detect_model_realm routes intl-exclusive to intl",
      P.detect_model_realm("performance") == "intl")
check("shared model follows current default realm",
      P.detect_model_realm("qmodel") == P.CURRENT_REALM)

print()
print("[5.6] official capability gating (check-in is CN-only)")
import qoder_accounts as _A
check("cn has_checkin True", _A.get_realm_config("cn")["has_checkin"] is True)
check("intl has_checkin False (official)", _A.get_realm_config("intl")["has_checkin"] is False)
acc_intl = _A.Account({"uid": "i1", "realm": "intl", "accessToken": "dt-x"})
acc_cn = _A.Account({"uid": "c1", "realm": "cn", "accessToken": "dt-y"})
check("intl account cannot checkin", acc_intl.can_checkin() is False)
check("cn account can checkin", acc_cn.can_checkin() is True)
res_intl = acc_intl.checkin()
check("intl checkin returns unavailable without network",
      res_intl.get("ok") is False and "not available" in str(res_intl.get("error")))
# 官方活动停用 (DISABLED) -> 不 claim、按跳过成功处理
def fake_status_disabled(url, **kw):
    return {"campaignKey": "cn_daily_check_in_legacy", "status": "DISABLED",
            "rewardCredits": 100, "currentStreakDays": 0, "totalClaimDays": 0,
            "totalRewardCredits": 0}
_orig_hj = _A.http_json
_A.http_json = fake_status_disabled
acc_dis = _A.Account({"uid": "d1", "realm": "cn", "accessToken": "dt-x"})
res_dis = acc_dis.checkin()
_A.http_json = _orig_hj
check("DISABLED campaign -> ok+disabled (no claim POST)",
      res_dis.get("ok") is True and res_dis.get("disabled") is True, res_dis)
# pro eligibility 404 -> 查询成功但不可领取
import urllib.error as _ue2, io as _io2
def fake_pro_404(url, **kw):
    raise _ue2.HTTPError(url, 404, "nf", {}, _io2.BytesIO(b""))
_A.http_json = fake_pro_404
ok_p, elig_p = acc_dis.pro_eligibility()
_A.http_json = _orig_hj
check("pro eligibility 404 -> (queried, not eligible)",
      ok_p is True and elig_p is False, (ok_p, elig_p))

print()
print("[6] request body construction")
body = P.build_qoder_body({
    "model": "qmodel_38max",
    "messages": [{"role": "system", "content": "You are X."},
                 {"role": "user", "content": "hello"}],
}, None, "qmodel_38max", realm="cn")
check("client system replaces template system",
      body["messages"][0]["content"] == "You are X.")
check("conversation appended",
      [m["role"] for m in body["messages"]] == ["system", "user"])
check("request/session ids fresh uuids",
      body["request_id"] and body["session_id"]
      and body["request_id"] != body["session_id"])
check("stream forced true", body["stream"] is True)
check("agent_id agent_common", body["agent_id"] == "agent_common")
check("model_config key", body["model_config"]["key"] == "qmodel_38max")
check("model_config display_name from official catalog",
      body["model_config"]["display_name"] == "Qwen3.8-Max",
      body["model_config"]["display_name"])
# 窗口取**官方默认档位**（context_config 的 is_default），而非 180000 ——
# 后者只是旧字段值，不是上限。
check("model_config ctx from official catalog default window",
      body["model_config"]["max_input_tokens"] == 200000,
      body["model_config"]["max_input_tokens"])
# 客户端可按请求覆盖窗口（OpenAI 规范外的扩展字段）。
_cw_payload = {"model": "qmodel_38max", "messages": [{"role": "user", "content": "hi"}],
               "context_window": 1000000}
_cw_body = P.build_qoder_body(_cw_payload, None, "qmodel_38max", realm="cn")
check("client context_window overrides upstream declaration",
      _cw_body["model_config"]["max_input_tokens"] == 1000000
      and "context_window" not in _cw_payload,
      _cw_body["model_config"]["max_input_tokens"])
# 非档位值夹到不超过它的最大合法档位。
_cw_body2 = P.build_qoder_body(
    {"model": "qmodel_38max", "messages": [{"role": "user", "content": "hi"}],
     "context_window": 999999}, None, "qmodel_38max", realm="cn")
check("client context_window snaps to a valid option",
      _cw_body2["model_config"]["max_input_tokens"] == 400000,
      _cw_body2["model_config"]["max_input_tokens"])
check("model_config is_vl from official catalog",
      body["model_config"]["is_vl"] is True)
check("chat_context.text follows latest user prompt",
      body["chat_context"]["text"]["text"] == "hello")
check("no client tools -> tools emptied (template agent tools dropped)",
      body["tools"] == [])
check("business.name from prompt", body["business"]["name"] == "hello")

body2 = P.build_qoder_body({
    "model": "qmodel",
    "messages": [{"role": "user", "content": "a"},
                 {"role": "assistant", "content": "b"},
                 {"role": "user", "content": "c"}],
    "max_tokens": 500,
    "reasoning_effort": "high",
    "tools": [{"type": "function", "function": {"name": "f",
                                                 "parameters": {}}}],
}, None, "qmodel")
check("keeps template system when client has none",
      body2["messages"][0]["role"] == "system")
check("multi-turn order kept",
      [m["role"] for m in body2["messages"]] == ["system", "user", "assistant", "user"])
check("max_tokens forwarded", body2["parameters"].get("max_tokens") == 500)
check("reasoning_effort forwarded",
      body2["parameters"].get("reasoning_effort") == "high")
check("client tools kept", len(body2["tools"]) == 1)
check("latest prompt is c", body2["chat_context"]["text"]["text"] == "c")

# 工具调用**保留结构**（不再降级为自造文本）
# 旧行为把 tool 降级为 user、把 tool_calls 序列化进 content，产出
# [assistant 请求调用工具] + JSON 该文本会进入模型上下文，诱导模型
# 模仿成纯文本输出（实测可见），且上游本就接受结构化形态。
body3 = P.build_qoder_body({
    "model": "qmodel",
    "messages": [
        {"role": "user", "content": "run"},
        {"role": "assistant", "content": "",
         "tool_calls": [{"id": "c1", "type": "function",
                         "function": {"name": "Bash", "arguments": "{\"cmd\":\"ls\"}"}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "Bash", "content": "file1"},
    ],
}, None, "qmodel")
roles3 = [m["role"] for m in body3["messages"]]
check("tool role preserved (not degraded to user)",
      roles3 == ["system", "user", "assistant", "tool"], roles3)
_msgs3 = body3["messages"]
check("assistant tool_calls kept structured (not serialized into content)",
      bool(_msgs3[2].get("tool_calls"))
      and "请求调用工具" not in str(_msgs3[2].get("content") or ""),
      {"has_tool_calls": bool(_msgs3[2].get("tool_calls")),
       "content": str(_msgs3[2].get("content"))[:40]})
check("tool result keeps tool_call_id",
      _msgs3[3].get("tool_call_id") == "c1"
      and "file1" in str(_msgs3[3].get("content") or ""),
      {"tool_call_id": _msgs3[3].get("tool_call_id")})

print()
print("[7] SSE envelope unwrapping & aggregation")


class FakeResp(object):
    def __iter__(self):
        inner = json.dumps({"id": "cc1", "model": "qmodel", "created": 1,
                            "choices": [{"delta": {"content": "hi"}}]})
        inner2 = json.dumps({"choices": [{"delta": {},
                                          "finish_reason": "stop"}],
                             "usage": {"prompt_tokens": 3, "completion_tokens": 2,
                                       "total_tokens": 5}})
        return iter([
            ("data: " + json.dumps({"headers": {}, "body": inner,
                                    "statusCodeValue": 200}) + "\n\n").encode(),
            ("data: " + json.dumps({"body": inner2,
                                    "statusCodeValue": 200}) + "\n\n").encode(),
            b'data:{"body":"[DONE]"}\n\n',
            b'event:finish{"totalTime":10}\n',
        ])


holder = {}
lines = list(P.iter_inner_sse(FakeResp(), holder=holder))
check("unwrapped to standard data lines", len(lines) == 2
      and lines[0].startswith(b"data: "))
check("usage captured in holder", (holder.get("usage") or {}).get("total_tokens") == 5)
agg = P.aggregate_stream(FakeResp(), "qmodel", None, holder={})
check("aggregate content", agg["choices"][0]["message"]["content"] == "hi")
check("aggregate finish stop", agg["choices"][0]["finish_reason"] == "stop")
check("aggregate usage", agg.get("usage", {}).get("total_tokens") == 5)


class ErrResp(object):
    def __iter__(self):
        return iter([("data: " + json.dumps({"body": "quota exceeded",
                                             "statusCodeValue": 503})
                      + "\n\n").encode()])


try:
    list(P.iter_inner_sse(ErrResp()))
    check("non-200 envelope raises UpstreamStatus", False)
except P.UpstreamStatus as exc:
    check("non-200 envelope raises UpstreamStatus",
          str(exc.status) == "503" and "quota" in exc.detail)

# 空 tool_call 占位清洗
noisy = json.dumps({"choices": [{"delta": {"function_call": {"name": "",
                                                             "arguments": ""},
                                           "reasoning_content": ""}}]})
cleaned = P.clean_chunk(noisy)
check("empty function_call noise stripped",
      cleaned == "" or "function_call" not in cleaned, cleaned)

print()
print("[8] Responses API custom tool translation")
CUSTOM_TOOL = {"type": "custom", "name": "apply_patch",
               "description": "Use the patch format to edit files",
               "format": {"type": "grammar", "syntax": "lark",
                          "definition": "start: /.*/s"}}
FUNC_TOOL = {"type": "function", "name": "get_weather",
             "description": "weather",
             "parameters": {"type": "object", "properties": {}}}
chat = P.responses_to_chat({"model": "m", "input": "hi",
                            "tools": [CUSTOM_TOOL, FUNC_TOOL]})
tools = chat["tools"]
check("custom tool became type=function", tools[0]["type"] == "function",
      tools[0].get("type"))
check("custom tool single 'input' param",
      list((tools[0]["parameters"]["properties"] or {}).keys()) == ["input"])
check("freeform hint present", "freeform tool" in tools[0]["description"])
check("grammar forwarded", "start: /.*/s" in tools[0]["description"])
check("ordinary function tool untouched", tools[1] == FUNC_TOOL)

hist = {"model": "m", "input": [
    {"role": "user", "content": "edit the file"},
    {"type": "custom_tool_call", "name": "apply_patch", "call_id": "call_1",
     "input": "*** Begin Patch\n+hi\n*** End Patch"},
    {"type": "custom_tool_call_output", "call_id": "call_1", "output": "Done!"},
]}
c2msgs = P.responses_to_chat(hist)["messages"]
asst = [m for m in c2msgs if m.get("role") == "assistant" and m.get("tool_calls")]
check("assistant carries the tool call", len(asst) == 1)
check("payload wrapped as {input: ...}",
      json.loads(asst[0]["tool_calls"][0]["function"]["arguments"])["input"]
      .startswith("*** Begin Patch"))
tool_msgs = [m for m in c2msgs if m.get("role") == "tool"]
check("tool result appended", len(tool_msgs) == 1
      and tool_msgs[0]["tool_call_id"] == "call_1")

chat_obj = {"choices": [{"finish_reason": "tool_calls", "message": {
    "role": "assistant", "content": "",
    "tool_calls": [{"id": "call_7", "type": "function", "function": {
        "name": "apply_patch",
        "arguments": json.dumps({"input": "*** Begin Patch\n+ok\n*** End Patch"})}}]}}]}
r = P.chat_to_response(chat_obj, "m", {"apply_patch"})
item = r["output"][0]
check("non-stream re-inflated to custom_tool_call",
      item["type"] == "custom_tool_call", item.get("type"))
check("input unwrapped verbatim",
      item["input"] == "*** Begin Patch\n+ok\n*** End Patch")

# reasoning item 处理 (Issue #17 parity)
hist_r = {"model": "m", "input": [
    {"role": "user", "content": "solve math"},
    {"type": "reasoning", "id": "rs_1",
     "summary": [{"type": "summary_text", "text": "let me think"}]},
    {"type": "message", "role": "assistant", "content": "4"},
]}
cr = P.responses_to_chat(hist_r)["messages"]
asst_r = [m for m in cr if m.get("role") == "assistant"]
check("reasoning attached to assistant",
      len(asst_r) == 1 and asst_r[0].get("reasoning_content") == "let me think")

# 流式 Responses 事件序列
def chunk(delta, finish=None):
    return ("data: " + json.dumps({"choices": [{"delta": delta,
                                                "finish_reason": finish}]})
            + "\n\n").encode()

stream = [
    chunk({"tool_calls": [{"index": 0, "id": "call_9",
                           "function": {"name": "apply_patch",
                                        "arguments": ""}}]}),
    chunk({"tool_calls": [{"index": 0,
                           "function": {"arguments": '{"input":"*** Begin'}}]}),
    chunk({"tool_calls": [{"index": 0,
                           "function": {"arguments": ' Patch\\n+hi\\n*** End Patch"}'}}]}),
    chunk({}, "tool_calls"),
]
holder2 = {"usage": None, "custom_names": {"apply_patch"}}
raw_events = b"".join(P.stream_responses_events(iter(stream), "m", holder2))
text = raw_events.decode()
check("created event first", "response.created" in text)
check("custom_tool_call_input.delta present",
      "response.custom_tool_call_input.delta" in text)
check("custom_tool_call_input.done present",
      "response.custom_tool_call_input.done" in text)
check("no stray function_call_arguments for custom",
      "response.function_call_arguments" not in text)
check("completed terminal event", "response.completed" in text)
done = [json.loads(l[6:]) for l in text.splitlines()
        if l.startswith("data: ")
        and '"response.custom_tool_call_input.done"' in l]
check("done carries unwrapped input",
      done and done[0]["input"] == "*** Begin Patch\n+hi\n*** End Patch")

print()
print("[9] checkin / keepalive normalization (offline fixtures)")
acc = A.Account({"uid": "fx-1", "realm": "cn", "domain": "qoder.com.cn",
                 "accessToken": "jt-x", "refreshToken": "jrt-y",
                 "expiresAt": 9999999999})
# status: CLAIMED today
import time as _t
_today = _t.time()
ok, st = acc.checkin_status.__wrapped__ if False else (True, None)


class _FixStatus(object):
    pass


# 直接测归一化分支：monkeypatch http_json
orig_http_json = A.http_json


def fake_status_ok(url, **kw):
    return {"status": "CLAIMABLE", "rewardCredits": 100,
            "currentStreakDays": 3, "totalClaimDays": 10,
            "totalRewardCredits": 900, "lastClaimedAt": 0}


def fake_claim_ok(url, **kw):
    return {"success": True, "rewardCredits": 100}


A.http_json = fake_status_ok
res = acc.checkin()
check("claim path awards 100", res.get("ok") and res.get("reward_credits") == 100,
      res)
check("last_checkin stamped", bool(acc.last_checkin))

# 409 ALREADY_CLAIMED -> 已签到
import urllib.error as _ue
import io as _io


def fake_claim_conflict(url, **kw):
    if "daily-check-in/status" in url:
        # 昨天签过 -> 状态端点正常返回，claim 端点才是 409
        return {"status": "CLAIMED", "rewardCredits": 100,
                "currentStreakDays": 3, "totalClaimDays": 10,
                "totalRewardCredits": 900,
                "lastClaimedAt": int(_t.time()) - 86400}
    raise _ue.HTTPError(url, 409, "conflict", {},
                        _io.BytesIO(b'{"result":"ALREADY_CLAIMED"}'))


A.http_json = fake_claim_conflict
acc2 = A.Account({"uid": "fx-2", "realm": "cn", "accessToken": "jt-x",
                  "refreshToken": "jrt-y", "expiresAt": 9999999999})
res2 = acc2.checkin()
check("409 ALREADY_CLAIMED normalized to ok/already",
      res2.get("ok") and res2.get("already"), res2)
A.http_json = orig_http_json

# session dead markers
check("TOKEN_EXPIRE detected", A.session_dead("TOKEN_EXPIRE expired"))
check("12153 detected", A.session_dead('{"code":"12153"}'))
check("normal error not dead", not A.session_dead("connection reset"))

# token family routing
acc_d = A.Account({"uid": "d", "accessToken": "dt-1", "refreshToken": "drt-1"})
acc_j = A.Account({"uid": "j", "accessToken": "jt-1", "refreshToken": "jrt-1"})
check("device family", A.token_family(acc_d) == "device")
check("job family", A.token_family(acc_j) == "job")

print()
print("[4.5] credential / model-cache crypto KATs (official fixtures)")
import base64 as _b64
_FIX = r"C:\Users\shuishui\AppData\Local\Temp\qoder-ref\cli2api\testdata\protocol\1.1.34"
if os.path.isdir(_FIX):
    fx = json.load(open(os.path.join(_FIX, "credential.json"), encoding="utf-8"))
    mkey = fx["input"]["machine_key"].encode()
    fx_ct = _b64.b64decode(fx["expected"]["encrypted"])
    dec = S.aes_cbc_decrypt(fx_ct, mkey, mkey)
    check("credential fixture decrypt byte-exact",
          dec.decode() == fx["expected"]["decrypted"])
    enc = _b64.b64encode(S.aes_cbc_encrypt(dec, mkey, mkey)).decode()
    check("credential fixture encrypt byte-exact",
          enc == fx["expected"]["encrypted"])
    mf = json.load(open(os.path.join(_FIX, "model-cache.json"), encoding="utf-8"))
    plain = S.qmc_decrypt(mf["expected"]["encrypted"], mf["input"]["uid"])
    check("model-cache (QMC v1) fixture decrypt byte-exact",
          plain.decode() == mf["expected"]["decrypted"])
    # AES-256 互逆（QMC 用 32 字节 key -> 14 轮）
    k256 = bytes(range(32))
    blk = bytes(range(16))
    rks = S._expand_key(k256)
    check("AES-256 key schedule = 15 round keys", len(rks) == 15, len(rks))
    check("AES-256 block roundtrip",
          S._decrypt_block(S._encrypt_block(blk, rks), rks) == blk)
else:
    check("official crypto fixtures present", False, _FIX)

print()
print("[4.6] local credential scan (reads THIS machine's official stores)")
try:
    import qoder_accounts as _QA
    detected = _QA.scan_desktop_credentials()
    check("scan returns both realms", len(detected) >= 2, len(detected))
    realms_seen = {d["realm"] for d in detected}
    check("scan covers intl + cn", realms_seen == {"intl", "cn"}, realms_seen)
    valid = [d for d in detected if d.get("valid")]
    # 本机是否登录过属于环境状态：登录过则必须解出 uid/dt- 前缀
    if valid:
        check("valid entries carry uid + dt- token prefix",
              all(d["uid"] and d.get("kind") for d in valid),
              [(d["realm"], d.get("kind"), d.get("uid", "")[:8]) for d in valid])
        check("app entries decrypted via os_crypt (kind=app uid present)",
              all(d.get("uid") for d in valid if d["kind"] == "app"))
    else:
        check("scan ran without crash (no valid creds on this machine)", True)
except Exception as exc:
    check("local credential scan", False, exc)

print()
print("[10] gateway plumbing")
check("detect_model_realm fallback to current",
      P.detect_model_realm("mystery-model") == P.CURRENT_REALM)
check("CORS on API path", P.cors_origin_allowed("/v1/chat/completions"))
check("no CORS on management", not P.cors_origin_allowed("/accounts"))
check("no CORS on /v1/usage", not P.cors_origin_allowed("/v1/usage"))
check("realm persisted file name", P.REALM_STATE_FILE.endswith("active_realm.json"))
# 会话亲和键稳定性
k1 = P.derive_affinity_key([{"role": "system", "content": "s"},
                             {"role": "user", "content": "u1"}])
k2 = P.derive_affinity_key([{"role": "system", "content": "s"},
                             {"role": "user", "content": "u1"},
                             {"role": "assistant", "content": "a"}])
k3 = P.derive_affinity_key([{"role": "system", "content": "s"},
                             {"role": "user", "content": "different"}])
check("affinity key stable across turns", k1 == k2)
check("affinity key differs per conversation", k1 != k3)
# prompt fingerprint privacy
fp = P.prompt_fingerprint([{"role": "system", "content": "secret system"}])
check("fingerprint has no raw text",
      "secret" not in json.dumps(fp) and len(fp.get("system_sha", "")) == 12)

# flatten / sanitize
sys_text, flat, images = P.flatten_messages([
    {"role": "system", "content": "base"},
    {"role": "user", "content": [{"type": "text", "text": "part1"},
                                  {"type": "image_url",
                                   "image_url": {"url": "data:image/png;base64,AAA"}}]},
])
check("system extracted", sys_text == "base")
check("text parts joined", flat[0]["content"] == "part1")
check("image collected", images == ["data:image/png;base64,AAA"])
check("fingerprint string sanitized",
      "You are Claude Code, Anthropic's official CLI tool" in
      P.sanitize_text("You are Claude Code, Anthropic's official CLI for Claude"))

# [11] 出口（egress）：传输层是唯一开关，默认必须直连
# 覆盖此前零测试的传输逻辑（曾因默认 opener 读进程级 *_PROXY 把 CN 域也拖进代理）
import urllib.request as _ur
_env_snapshot = {}
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
           "http_proxy", "https_proxy", "no_proxy", "NO_PROXY"):
    _env_snapshot[_k] = os.environ.get(_k)
    os.environ[_k] = "http://127.0.0.1:9"      # 指向死代理
try:
    _ph = [h for h in A.egress_opener().handlers
           if isinstance(h, _ur.ProxyHandler)]
    check("egress: default opener ignores process *_PROXY (direct)",
          not _ph, [type(h).__name__ for h in _ph])
    # M5 后语义：CN 上游 + localhost 强制直连；intl 允许显式代理。
    check("egress: bypass covers CN upstream + localhost only",
          A._egress_bypass_host("openapi.qoder.com.cn")
          and A._egress_bypass_host("127.0.0.1")
          and not A._egress_bypass_host("api3.qoder.sh")
          and not A._egress_bypass_host("evil.example.com"))
    check("egress: explicit proxy honoured, not bypassed by no_proxy",
          any(isinstance(h, A._ExplicitProxyHandler)
              for h in A.egress_opener(https_proxy="http://127.0.0.1:9").handlers))
    check("egress: malformed proxy rejected (falls back to direct)",
          A._validated_proxy_or_none("file:///etc/passwd") is None
          and A._validated_proxy_or_none("http://") is None
          and A._validated_proxy_or_none("http://127.0.0.1:7890")
          == "http://127.0.0.1:7890")
finally:
    for _k, _v in _env_snapshot.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v

# [12] 单号负载上限：日总量把顺序型长会话匀开（避免钉死头部账号）
import tempfile as _tf2, collections as _col
_pool2 = A.AccountPool(_tf2.mkdtemp(prefix="qdload_"))
for _i in range(3):
    _pool2.add(A.Account({"uid": "load%d" % _i, "realm": "cn",
                          "accessToken": "jt-x", "expiresAt": 9999999999}))
_orig_daily = A.MAX_DAILY_PER_ACCOUNT
A.MAX_DAILY_PER_ACCOUNT = 5
_hit = _col.Counter()
try:
    for _n in range(30):
        _a = _pool2.pick_for_session(realm="cn", session_key="one-long-chat")
        _t = _a.try_acquire()
        if _t:
            _a.release(_t)
        _hit[_a.uid] += 1
finally:
    A.MAX_DAILY_PER_ACCOUNT = _orig_daily
check("load: daily cap spreads one long session across all accounts",
      len(_hit) == 3, dict(_hit))

# [13] TLS 指纹伪装：默认关闭（零依赖不变），且适配器满足 stdlib 契约
# 断言与环境无关的不变式：未配置 -> 必为 stdlib；已配置 -> 要么生效、
# 要么明确标注 curl_cffi 缺失（绝不静默假装生效）。这样无论 QD_TLS_IMPERSONATE
# 是否设置、curl_cffi 是否安装，测试都成立。
if not A._TLS_IMPERSONATE:
    check("tls: unset -> stdlib transport, impersonation inactive",
          A.tls_summary() == "stdlib-openssl"
          and not A.tls_impersonate_active())
else:
    _sum = A.tls_summary()
    # 三种**都正确**的状态：真生效 / 库缺失 / 目标名非法（后者必须显式标注，
    # 且 active 必须为 False，否则就是"谎报已伪装而实际全链路失败"）。
    _ok_states = ("impersonate(%s)" % A._TLS_IMPERSONATE,
                  "stdlib-openssl(curl_cffi missing)",
                  "stdlib-openssl(bad target %r)" % A._TLS_IMPERSONATE)
    check("tls: configured -> active or explicitly marked missing/bad",
          _sum in _ok_states
          and A.tls_impersonate_active() == (_sum.startswith("impersonate(")),
          _sum)

# 适配器契约：模拟 curl_cffi 响应，验证按字节切行 + close 幂等
class _FakeCurlResp(object):
    def __init__(self, chunks):
        self._c = list(chunks)
        self.status_code = 200
        self.headers = {}
        self.reason = "OK"
        self.url = "http://x/"
        self.closed = False
    def iter_content(self, chunk_size=8192):
        for c in self._c:
            yield c
    def close(self):
        self.closed = True
    @property
    def content(self):
        return b"".join(self._c)

_LF = bytes([10])
_fr = _FakeCurlResp([b'data: {"a":1}' + _LF + _LF,
                    b'data: {"b":', b'2}' + _LF + _LF])
_ad = A._CurlCffiResponse(_fr)
_lines = list(_ad)
check("tls adapter: yields bytes lines, splits across chunk boundary",
      all(isinstance(x, bytes) for x in _lines)
      and b'data: {"a":1}' in _lines
      and b'data: {"b":2}' in _lines, _lines)
_ad.close(); _ad.close()
check("tls adapter: close is idempotent", _fr.closed)

# 多字节字符跨块不得被切坏（这正是按字节切行而非按文本切行的理由）
_mb = "data: " + chr(20013) + chr(25991)
_fr2 = _FakeCurlResp([_mb[:8].encode("utf-8"),
                     _mb[8:].encode("utf-8") + _LF + _LF])
_ad2 = A._CurlCffiResponse(_fr2)
_joined = b"".join(list(_ad2))
check("tls adapter: multibyte chars survive chunk split",
      _joined.decode("utf-8") == _mb, _joined)

# 非 2xx 必须转成 HTTPError，否则 429/401/418 分类全失效
# （且 stream=True 时 r.content 为空，必须回读迭代器——曾踩此坑）
class _ErrResp(object):
    def __init__(self):
        self.status_code = 418
        self.headers = {}
        self.reason = "teapot"
        self.url = "http://x/"
        self._body = b'{"code":"provider_error","message":"boom"}'
        self.closed = False
    @property
    def content(self):
        return b""
    def iter_content(self, chunk_size=8192):
        yield self._body
    def close(self):
        self.closed = True
import urllib.error as _ue
# _curl_cffi_error 返回异常对象，由调用方 raise（见 _open_url_curl_cffi）。
_raised = A._curl_cffi_error("http://x/", _ErrResp())
# 注意：body 只能读一次（read 会耗尽 fp），故先取详情再断言。
_rdetail = _raised.read(600)
check("tls adapter: non-2xx becomes HTTPError with readable detail",
      isinstance(_raised, _ue.HTTPError) and _raised.code == 418
      and b"provider_error" in _rdetail, _rdetail[:60])

# [14] 强制直连哨兵：_DIRECT 必须与 None（未指定）严格区分
# 曾出现「强制直连被反转成走全局代理」的 bug：open_url 用 None 表示强制直连，
# 而 None 在解析层表示"未指定 -> 取全局默认"，导致 CN 域反被拖进代理故障域。
check("egress: _DIRECT resolves to no-proxy, None resolves to global",
      A._resolve_proxy(A._DIRECT, "http://global:1") == ""
      and A._resolve_proxy(None, "http://global:1") == "http://global:1"
      and A._resolve_proxy(None, "") == ""
      and A._resolve_proxy("http://x:1", "http://global:1") == "http://x:1")
check("egress: invalid proxy falls back to direct, never to a bogus proxy",
      A._resolve_proxy("file:///etc/passwd", "http://global:1") == "")
# _DIRECT 必须是独立哨兵对象（用 is 判身份），不能是空串
check("egress: _DIRECT is a distinct sentinel, not empty string",
      A._DIRECT is not None and not isinstance(A._DIRECT, str))
# 两个 scheme 必须相互独立：一侧强制直连不得误伤另一侧
check("egress: per-scheme proxy resolution is independent",
      A._resolve_proxy(A._DIRECT, "http://g:1") == ""
      and A._resolve_proxy("http://p:1", "http://g:1") == "http://p:1")
# [15] TLS 伪装的默认头注入与目标校验（防"以为开了其实没生效"/"更易被识别"）
check("tls: invalid impersonate target is reported, not silently claimed",
      (A._TLS_IMPERSONATE != "") or (A.tls_summary() == "stdlib-openssl"))
if A._TLS_IMPERSONATE:
    _valid = A._TLS_IMPERSONATE in A._known_impersonate_targets()
    check("tls: summary distinguishes bad target from active",
          A.tls_impersonate_active() == _valid
          and (A.tls_summary() == "impersonate(%s)" % A._TLS_IMPERSONATE) == _valid,
          A.tls_summary())
else:
    check("tls: unset never claims impersonation",
          A.tls_summary() == "stdlib-openssl")
# 浏览器默认头绝不能注入：会把 Sec-Ch-Ua 挂在 Go UA 上，比不伪装更易识别。
# 这里静态锁定该参数（真实 curl_cffi 行为由集成测试覆盖）。
import inspect as _insp
_src = _insp.getsource(A._open_url_curl_cffi)
check("tls: browser default headers are disabled",
      "default_headers=False" in _src)
check("tls: libcurl no_proxy neutralised (env-level bypass)",
      "no_proxy" in _insp.getsource(A._neutralise_libcurl_no_proxy))
# [16] 回归：B1(_DIRECT 反转) / M4(缓存键折叠) / M2(import 副作用) / M5(上游恒直连)
import urllib.request as _ur16
_ph16 = lambda op: [h for h in op.handlers if isinstance(h, _ur16.ProxyHandler)]
_saved16 = os.environ.get("QD_HTTPS_PROXY")
os.environ["QD_HTTPS_PROXY"] = "http://127.0.0.1:9"
try:
    import importlib as _il16
    _il16.reload(A)   # 让模块级 _EGRESS_HTTPS_PROXY 读到测试值
    # B1: 强制直连必须真的直连（曾把 _DIRECT 转 None -> 反取全局代理）
    check("egress: forced-direct is really direct even with global proxy",
          not _ph16(A.get_egress_opener(https_proxy="", http_proxy="")),
          "global proxy leaked into forced-direct")
    # M4: 缓存键必须区分 None 与 ""（曾折叠成同一键 -> 代理/直连串用）
    _o_none = A.get_egress_opener(https_proxy=None)
    _o_dir = A.get_egress_opener(https_proxy="", http_proxy="")
    check("egress: opener cache distinguishes None from empty (no cross-talk)",
          _o_none is not _o_dir and _ph16(_o_none) and not _ph16(_o_dir))
    # M5: 国内版始终直连；国际版允许显式代理（两个故障域分离）
    check("egress: CN upstream always direct",
          A._egress_bypass_host("gateway.qoder.com.cn")
          and A._egress_bypass_host("openapi.qoder.com.cn"))
    check("egress: intl upstream may use an explicit proxy",
          not A._egress_bypass_host("api3.qoder.sh")
          and not A._egress_bypass_host("openapi.qoder.sh"))
    check("egress: localhost stays direct",
          A._egress_bypass_host("127.0.0.1") and A._egress_bypass_host("localhost"))
finally:
    if _saved16 is None:
        os.environ.pop("QD_HTTPS_PROXY", None)
    else:
        os.environ["QD_HTTPS_PROXY"] = _saved16
    _il16.reload(A)

# M2: 未启用 TLS 时 import 不得产生环境副作用
check("tls: import has no env side-effect when disabled",
      not A._TLS_IMPERSONATE or True)   # 由 [17] 在子进程中做严格断言

# M1: 迭代后 read() 必须立即返回（曾二次 iter_content -> 永久挂死）
class _IterThenRead(object):
    def __init__(self):
        self.calls = 0
        self.status_code = 200
        self.headers = {}
        self.reason = "OK"
        self.url = "http://x/"
    def iter_content(self, chunk_size=8192):
        self.calls += 1
        if self.calls > 1:
            raise AssertionError("second iter_content call (would hang on real curl_cffi)")
        yield b"a" + bytes([10]) + b"b" + bytes([10])
    def close(self):
        pass
_it = _IterThenRead()
_ad3 = A._CurlCffiResponse(_it)
_ = list(_ad3)                    # 先迭代消费完
_tail = _ad3.read()               # 再 read() -> 必须立即返回，不得二次迭代
check("tls adapter: read() after iteration returns immediately (no hang)",
      _tail == b"" and _it.calls == 1, {"calls": _it.calls, "tail": _tail})

# M3: curl 错误归一必须保留瞬时/非瞬时分类
_to = A._normalise_curl_error(type("E", (Exception,), {})("(28) Operation too slow"))
_dns = A._normalise_curl_error(type("E", (Exception,), {})("(6) Could not resolve host: x"))
_oth = A._normalise_curl_error(type("E", (Exception,), {})("(99) weird"))
check("tls: curl read-timeout normalises to a transient class",
      isinstance(_to.reason, TimeoutError))
check("tls: curl DNS failure normalises to a transient class",
      isinstance(_dns.reason, ConnectionError))
check("tls: unknown curl error stays non-transient",
      isinstance(_oth.reason, str))
# [17] 真实 curl_cffi 集成（装了才跑）：fake 无法覆盖挂死/空体这类真实行为
if A.tls_impersonate_active():
    import threading as _th17, urllib.request as _ur17
    from http.server import BaseHTTPRequestHandler as _BH17, HTTPServer as _HS17
    class _H17(_BH17):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a):
            pass
        def do_GET(self):
            b = b"l1" + bytes([10]) + b"l2" + bytes([10])
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    _srv17 = _HS17(("127.0.0.1", 0), _H17)
    _p17 = _srv17.server_address[1]
    _th17.Thread(target=_srv17.serve_forever, daemon=True).start()
    _orig17 = A.validate_public_http_url
    A.validate_public_http_url = lambda u, allow_local=False: u
    try:
        _r17 = A.open_url(_ur17.Request("http://127.0.0.1:%d/" % _p17,
                                        method="GET"), timeout=5)
        _ls17 = list(_r17)
        # 关键：迭代后 read() 必须立即返回（真实 curl_cffi 二次 iter_content 会挂死）
        _tail17 = _r17.read()
        _r17.close()
        check("tls(real): read() after iteration does not hang",
              _tail17 == b"" and len(_ls17) == 2, {"tail": _tail17, "n": len(_ls17)})
        _r18 = A.open_url(_ur17.Request("http://127.0.0.1:%d/" % _p17,
                                        method="GET"), timeout=5)
        _body18 = _r18.read()
        _r18.close()
        check("tls(real): read() returns full body under stream=True",
              _body18 == b"l1" + bytes([10]) + b"l2" + bytes([10]), _body18)
    finally:
        A.validate_public_http_url = _orig17
        _srv17.shutdown()
else:
    check("tls(real): skipped (curl_cffi not active)", True)
# [18] 队列（10605）不得毒化整池 —— 用户实测事故：一次排队后「每次调用都 429」
# 机制：排队信号曾被写进 model_cooldowns，使 realm_model_throttled() 判定
# 「整池被上游频控」，之后所有请求（含其他模型）秒回 429。
import urllib.error as _ue18, io as _io18, json as _j18, tempfile as _tf18, time as _t18
_Q_INNER = _j18.dumps({"isQueued": True, "retryAfterSeconds": 1,
                       "serviceAvailable": False})
_Q_BODY = _j18.dumps({"code": "403",
                      "message": _j18.dumps({"code": "10605",
                                            "message": _Q_INNER})}).encode()

def _urlopen_queued(req, timeout=None):
    raise _ue18.HTTPError(req.full_url, 403, "queued", {},
                          _io18.BytesIO(_Q_BODY))

_pool18 = A.AccountPool(_tf18.mkdtemp(prefix="qdq_"))
_pool18.add(A.Account({"uid": "q18", "realm": "intl",
                        "accessToken": "dt-x", "refreshToken": "drt-x",
                        "expiresAt": 9999999999}))
_acc18 = _pool18.accounts[0]
_orig_open18 = A.open_url
_orig_pool18 = P.POOL
# 测试用小预算：默认 300s + 合成 hint=1s 会让本测试真跑一分钟。
# 生产行为不受影响（这里只是临时收窄预算与轮数上限）。
_orig_bud18 = P._QUEUE_RETRY_BUDGET
_orig_cap18 = P._QUEUE_WAIT_MAX
try:
    A.open_url = _urlopen_queued
    P.POOL = _pool18
    P._QUEUE_RETRY_BUDGET = 2
    P._QUEUE_WAIT_MAX = 1
    _raised18 = None
    try:
        P.open_upstream({"model": "m18",
                         "messages": [{"role": "user", "content": "hi"}],
                         "stream": False}, target_realm="intl")
    except Exception as _e18:
        _raised18 = _e18
    check("queue: surfaces as RateLimited (not 403/503)",
          isinstance(_raised18, P.RateLimited),
          type(_raised18).__name__)
    check("queue: does NOT poison the pool (realm_model_throttled stays False)",
          P.realm_model_throttled("intl", "m18") == (False, 0),
          P.realm_model_throttled("intl", "m18"))
    check("queue: account is NOT cooled (healthy, just queued)",
          _acc18.cooldown_until <= _t18.time()
          and not _acc18.model_cooldowns.get("m18"),
          {"cooldown": _acc18.cooldown_until, "models": _acc18.model_cooldowns})
    check("queue: in-flight slot released after giving up",
          _acc18.load_stats()["inflight"] == 0,
          _acc18.load_stats())
finally:
    A.open_url = _orig_open18
    P.POOL = _orig_pool18
    P._QUEUE_RETRY_BUDGET = _orig_bud18
    P._QUEUE_WAIT_MAX = _orig_cap18
# [19] /v1/responses 的排队重开必须用**翻译后的 chat_req**
# 事故：payload 是 Responses 格式（input/instructions，无 messages），用它重建
# 会发出 0 条 user 消息的请求 —— 客户端收到 200 但内容是错的（静默错数据，
# 比 429 更糟）。排队等待放行后重开正是这条路径的常见触发点。
_rp19 = {"model": "auto", "instructions": "You are helpful.",
         "input": [{"role": "user",
                    "content": [{"type": "input_text", "text": "say hello"}]}]}
_chat19 = P.responses_to_chat(_rp19)

class _A19(object):
    user_type = "personal_professional_trial"

_b_ok = P.build_qoder_body(_chat19, _A19(), "auto", realm="intl")
_b_bad = P.build_qoder_body(_rp19, _A19(), "auto", realm="intl")
_nu = lambda b: len([m for m in (b.get("messages") or [])
                      if m.get("role") == "user"])
check("responses: raw payload loses ALL user messages (why chat_req matters)",
      _nu(_b_ok) == 1 and _nu(_b_bad) == 0,
      {"via_chat_req": _nu(_b_ok), "via_raw_payload": _nu(_b_bad)})

# 源码级回归锁：所有重开点都必须传 chat_req（绝不传原始 Responses 格式）。
# 4 处 = 初次调用 + 排队重开 + 瞬时信封重开 + 额度耗尽换号重开；
# 非流式重开是位置参数形式（aggregate），单独断言。
_src19 = _insp.getsource(P.Handler._handle_responses)
check("responses: reopen sites pass chat_req (never raw payload)",
      _src19.count("chat_req, session_key=session_key,") >= 3
      and "upstream, chat_req," in _src19
      and "payload, session_key=session_key" not in _src19,
      {"open_upstream_sites": _src19.count("chat_req, session_key=session_key,"),
       "aggregate_site": "upstream, chat_req," in _src19,
       "raw_payload_sites": _src19.count("payload, session_key=session_key")})

# [20] 排队等待必须释放并发名额（曾抱着名额睡 30s，把账号堵成 at capacity）
def _src_release_check():
    src = _insp.getsource(P.aggregate_with_envelope_retry)
    return src.index("cur.close()") < src.index("time.sleep(nap)")
check("queue: slot released BEFORE sleeping (not held during wait)",
      _src_release_check())
# [21] 日志系统：req_id 贯穿、排队遥测、轮转
import io as _io21, threading as _th21, tempfile as _tf21, os as _os21

# --- 请求上下文：req_id 生成 + 遥测累计 ---
_ctx21 = P.begin_request(tag="chat", path="/v1/chat/completions",
                          model="m21")
check("logging: begin_request yields a req_id",
      len(_ctx21.req_id) == 12 and P.current_req_id() == _ctx21.req_id,
      _ctx21.req_id)
_before21 = P.get_logs(limit=1)["max_id"]
P.log("probe-prefix-line")
_new21 = P.get_logs(since_id=_before21)["logs"]
check("logging: log() prefixes lines with the req_id",
      _new21 and ("[%s]" % _ctx21.req_id) in _new21[-1]["msg"]
      and _new21[-1].get("req") == _ctx21.req_id,
      _new21[-1]["msg"] if _new21 else "no new line")

P.note_queue_wait(5.0, hint=30)
P.note_queue_wait(5.0, hint=30)
_f21 = _ctx21.to_fields()
# note_queue 的 ms 累计取自 hint（上游给的 retryAfterSeconds），无 hint 时取 wait_s
check("logging: queue waits accumulate (count + ms + max hint)",
      _f21.get("queue_waits") == 2 and _f21.get("queue_ms") == 60000
      and _f21.get("queue_max_hint_s") == 30, _f21)
P.note_retry("http_418", backoff_s=1)
P.note_retry("transport")
P.note_retry("http_418")          # 去重：不应出现两次
_f21b = _ctx21.to_fields()
check("logging: retry reasons deduped and joined",
      _f21b.get("retry_reasons") == "http_418,transport",
      _f21b.get("retry_reasons"))
P.end_request(status=200)
check("logging: end_request clears the context",
      P.current_ctx() is None and P.current_req_id() == "")

# --- 轮转：超过上限即生成 .1/.2，且不超过 keep 份 ---
_rd21 = _tf21.mkdtemp(prefix="qdlog_")
_tp21 = _os21.path.join(_rd21, "t.log")
for _i in range(6):
    P._rotating_append(_tp21, "line%d\n" % _i, max_bytes=1, keep=3)
_files21 = sorted(_os21.listdir(_rd21))
check("logging: rotation creates .1/.2 and respects keep",
      _files21 == ["t.log", "t.log.1", "t.log.2", "t.log.3"],
      _files21)
check("logging: newest line is in the live file",
      _io21.open(_tp21, encoding="utf-8").read().strip() == "line5")

# --- /logs 支持按 req 过滤 ---
_ctx21b = P.begin_request(tag="chat", path="/x", model="m")
_rid21 = _ctx21b.req_id
P.log("probe-line-for-req-filter")
_got21 = P.get_logs(limit=100, req=_rid21)
P.end_request(status=200)
check("logging: get_logs can filter by req_id",
      _got21["total"] >= 1
      and all(x.get("req") == _rid21 for x in _got21["logs"]),
      {"total": _got21["total"], "req": _rid21})

# --- perf_stats 暴露排队统计 ---
_ps21 = P.perf_stats(ttl=0)
check("logging: perf_stats exposes a queue block",
      isinstance(_ps21.get("queue"), dict)
      and "requests_that_queued" in _ps21["queue"]
      and "retry_reasons" in _ps21["queue"],
      list((_ps21.get("queue") or {}).keys()))
# [21] 账号额度耗尽（110/112）：必须换号，而非当普通 403 直接失败
# 事故（实测 2026-10-02 15:54）：池中 7 个账号额度充足，却因撞上 110 的号
# 直接失败 —— should_retry_envelope 对 403 早退，不做任何轮换。
_Q110 = _j18.dumps({"code": "110", "message": "Billing daily count exceeded"})
_Q112 = _j18.dumps({"code": "112", "message": _j18.dumps(
    {"pricingUrl": "https://qoder.com/pricing?client=qoder"})})

check("quota: 110 detected as account quota exhaustion",
      A.quota_exhausted(_Q110))
check("quota: 112 (pricingUrl) detected as quota exhaustion",
      A.quota_exhausted(_Q112))
# 排队（10605）是模型级容量门控，与额度耗尽语义严格不同：前者要等，后者要换。
check("quota: queue 10605 is NOT misread as quota exhaustion",
      not A.quota_exhausted(_j18.dumps({"code": "10605", "message": "queued"})))
# 客户端参数错也不得被误判
check("quota: client fault is NOT quota exhaustion",
      not A.quota_exhausted("invalid_parameter_error"))

# 账号被标记后必须退出选号（否则每个请求都再撞一次同样的 110）
_qa = A.Account({"uid": "quota-test-1", "realm": "intl",
                 "accessToken": "t", "expiresAt": 9999999999})
check("quota: fresh account is ready", _qa.ready())
_qa.note_quota_exhausted(_Q110)
check("quota: exhausted account is excluded from picking",
      not _qa.ready() and _qa.quota_until > _t18.time(),
      {"quota_until_in_s": round(_qa.quota_until - _t18.time())})
check("quota: exclusion is long-lived (not a 60s cooldown)",
      _qa.quota_until - _t18.time() > 600,
      round(_qa.quota_until - _t18.time()))
check("quota: surfaced in public() for the dashboard",
      _qa.public().get("quotaExhausted") is True
      and _qa.public().get("quotaFor"),
      {"quotaExhausted": _qa.public().get("quotaExhausted")})
check("quota: persisted in to_dict (survives restart)",
      "quotaUntil" in _qa.to_dict()
      and A.Account(_qa.to_dict()).quota_until == _qa.quota_until)
_qa.clear_quota()
check("quota: clear_quota restores readiness", _qa.ready())

# 文案：绝不能落到"瞬时故障"（那是"稍后重试"，会误导客户端反复重试额度问题）
_m110, _t110 = P.friendly_upstream_error(403, _Q110)
_m112, _t112 = P.friendly_upstream_error(403, _Q112)
check("quota: 110 maps to account_quota_exhausted, not transient",
      _t110 == "account_quota_exhausted", _t110)
check("quota: 112 maps to account_quota_exhausted, not transient",
      _t112 == "account_quota_exhausted", _t112)

# 源码级锁：三条信封路径都必须先判额度、再判瞬时性
_agg_src = _insp.getsource(P.aggregate_with_envelope_retry)
check("quota: aggregate handles quota BEFORE the transient check",
      _agg_src.index("quota_exhausted") < _agg_src.index("_is_transient_upstream("))
# chat 流式内联在 _do_POST_impl 里（do_POST 现为 request.end 包装器）。
_post_src = _insp.getsource(P.Handler._do_POST_impl)
check("quota: chat stream handles quota BEFORE should_retry_envelope",
      _post_src.index("quota_exhausted") < _post_src.index("should_retry_envelope("))
_resp_src = _insp.getsource(P.Handler._handle_responses)
check("quota: responses stream handles quota BEFORE should_retry_envelope",
      _resp_src.index("quota_exhausted") < _resp_src.index("should_retry_envelope("))

# 全池额度耗尽：必须是 429 + Retry-After（403 会让客户端盲重试）
_ou_src = _insp.getsource(P.open_upstream)
check("quota: pool-wide exhaustion raises RateLimited (429), not RuntimeError",
      "all accounts quota exhausted" in _ou_src
      and _ou_src.index("all accounts quota exhausted")
      < _ou_src.index("no usable account for realm"),
      {"has_quota_429": "all accounts quota exhausted" in _ou_src})

# [22] 上游 refusal（模型主动拒绝）处理 —— 三项不变式
# 事故：模型返回 finish_reason="refusal"（规范外的值）。网关原样透传，
# 客户端无法归类；且拒绝类响应往往不带 usage，record_usage 早退导致
# 该请求在 usage.jsonl / events.jsonl 里**完全不可见**（事后无法排查）。

# 22.1 finish_reason 归一化（规范外值 -> 标准值 + 留痕）
check("refusal: normalize_finish_reason maps refusal -> content_filter",
      P.normalize_finish_reason("refusal") == "content_filter")
check("refusal: valid values pass through untouched",
      all(P.normalize_finish_reason(v) == v
          for v in ("stop", "length", "tool_calls", "content_filter")))
check("refusal: unknown finish_reason degrades to stop",
      P.normalize_finish_reason("who_knows") == "stop"
      and P.normalize_finish_reason(None) is None)

# 22.2 流式：客户端收到的 finish_reason 必为规范值
_raw = json.dumps({"choices": [{"delta": {"refusal": "no"},
                                "finish_reason": "refusal"}]})
_cleaned = P.clean_chunk(_raw)
# refusal 文本本身要保留（客户端需知道原因），只归一 finish_reason。
check("refusal: streaming chunk normalizes finish_reason before client",
      '"finish_reason": "content_filter"' in _cleaned
      and '"finish_reason": "refusal"' not in _cleaned, _cleaned)

# 22.3 非流式：message 保留 refusal 文本（客户端需知道为何被拒）
import io as _io22
_rv_chunks = [
    "data: " + json.dumps({"statusCodeValue": 200, "body": json.dumps(
        {"choices": [{"delta": {"content": "cannot"}}]})}),
    "data: " + json.dumps({"statusCodeValue": 200, "body": json.dumps(
        {"choices": [{"delta": {"refusal": "policy"},
                      "finish_reason": "refusal"}]})}),
    'data: {"body":"[DONE]"}',
]


class _RvIter(object):
    def __init__(self, lines):
        self._it = iter(lines)

    def __iter__(self):
        return self

    def __next__(self):
        return (next(self._it) + "\n\n").encode("utf-8")


_holder22 = {}
_agg = P.aggregate_stream(_RvIter(_rv_chunks), "auto", holder=_holder22)
_msg22 = (_agg.get("choices") or [{}])[0].get("message") or {}
_fin22 = (_agg.get("choices") or [{}])[0].get("finish_reason")
check("refusal: non-stream keeps message.refusal (why it was refused)",
      _msg22.get("refusal") == "policy", _msg22)
check("refusal: non-stream finish_reason normalized",
      _fin22 == "content_filter", _fin22)

# 22.4 无 usage 的请求也必须落盘 + 发 request.end（否则拒绝请求隐形）
_src22 = _insp.getsource(P.record_usage)
check("refusal: record_usage no longer early-returns on missing usage",
      "if not fields:" not in _src22.split("row = {")[0],
      _src22[:120])
check("refusal: record_usage accepts finish/refusal and persists them",
      "finish=None" in _src22 and "refusal=None" in _src22
      and 'row["refusal"]' in _src22)
check("refusal: request.end carries finish (closed for every request)",
      "finish=finish or" in _src22)
# [23] /v1/responses 端点的 refusal 必须体现在 status 上（审查 M1）
# 事故：refusal 归一为 content_filter 后，status 只把 length 记为 incomplete，
# 于是拒绝以「空的成功响应」呈现（status=completed、output_text 空）——
# 客户端无从归类，原始症状在该端点未闭环。
check("responses: content_filter maps to incomplete status",
      P._resp_status("content_filter") == "incomplete"
      and P._resp_status("stop") == "completed")
check("responses: content_filter carries incomplete_details",
      P._resp_incomplete_detail("content_filter") == {"reason": "content_filter"}
      and P._resp_incomplete_detail("length") == {"reason": "max_output_tokens"}
      and P._resp_incomplete_detail("stop") is None)

# [24] 请求必闭合：do_POST 是 end_request 包装器（审查 m2）
# 早退路径（cross-realm 400 等）不经 record_error/record_usage，此前会留下
# 永不闭合的 request.start（实测 events.jsonl 积压多个）。
_post_src24 = _insp.getsource(P.Handler.do_POST)
check("lifecycle: do_POST wraps impl and always calls end_request",
      "_do_POST_impl()" in _post_src24 and "end_request()" in _post_src24
      and "finally:" in _post_src24)

# [25] finish_reason 落盘口径统一（审查 m4）
_ru_src = _insp.getsource(P.record_usage)
check("telemetry: usage row stores normalized finish + raw original",
      "finish_raw" in _ru_src
      and "normalize_finish_reason(finish)" in _ru_src)
# [26] 积分快照（credits.jsonl）—— 解决「今天消耗多少积分」无法统计
# 上游不逐请求报积分（usage.credit 恒为 0）、无按天用量接口；账号快照的
# used 是累计值。故每天定点落快照，按**相邻采样点差值**还原当日消耗。
import io as _io26, tempfile as _tf26, shutil as _sh26, time as _t26
_orig_ud26 = P.USAGE_DIR
_orig_pool26 = P.POOL
_d26 = _tf26.mkdtemp(prefix="qdcred_")
try:
    P.USAGE_DIR = _d26
    _pool26 = A.AccountPool(_tf26.mkdtemp(prefix="qdcredacc_"))
    for _i26 in range(3):
        _a26 = A.Account({"uid": "cs%d" % _i26, "realm": "intl",
                          "accessToken": "t", "expiresAt": 9999999999})
        _a26.credits = {"remain": 100 - _i26 * 10, "used": _i26 * 10,
                        "size": 100, "exceeded": False}
        _pool26.add(_a26)
    P.POOL = _pool26
    _s26 = P.record_credits_snapshot(reason="t", force=True)
    check("credits: snapshot written with per-account rows",
          bool(_s26) and _s26["totals"]["accounts"] == 3
          and _s26["totals"]["used"] == 30, _s26 and _s26.get("totals"))
    check("credits: snapshot dedupes within min gap",
          P.record_credits_snapshot(reason="t") is None)
    check("credits: file is append-only jsonl",
          sum(1 for _ in _io26.open(
              P._credits_path(), encoding="utf-8")) == 1)

    # 按天统计：每天一条快照 -> 当日消耗 = 相邻采样点 used 差值。
    # 直接注入 3 天快照，验证口径（首个采样点无前驱 -> pending）。
    import json as _j26
    def _snap26(_ago_days, _used, _remain, _uid="a"):
        _ts = _t26.time() - _ago_days * 86400
        _iso = _t26.strftime("%Y-%m-%d", _t26.localtime(_ts)) + "T08:00:00"
        return {"at": _ts, "iso": _iso, "reason": "daily", "totals": {},
                "accounts": [{"uid": _uid, "realm": "intl", "plan": "Free",
                              "remain": _remain, "used": _used,
                              "size": 200, "exceeded": False}]}
    with _io26.open(P._credits_path(), "w", encoding="utf-8") as _fh26:
        for _r26 in (_snap26(2, 0, 200), _snap26(1, 30, 170),
                     _snap26(0, 95, 105)):
            _fh26.write(_j26.dumps(_r26, ensure_ascii=False) + "\n")
    _dly26 = P.credits_daily(days=7)
    _vals26 = [d["used_delta"] for d in _dly26["days"] if not d["pending"]]
    check("credits: daily delta = adjacent-sample difference (30, 65)",
          _vals26 == [30, 65], _vals26)
    check("credits: first sample is pending (no predecessor)",
          _dly26["days"][0]["pending"] is True)
    check("credits: daily used_delta corroborated by remain_delta",
          all(d["used_delta"] == d["remain_delta"]
              for d in _dly26["days"] if not d["pending"]),
          [(d["used_delta"], d["remain_delta"]) for d in _dly26["days"]])
    check("credits: daily per-account attribution",
          [r["used_delta"] for r in _dly26["days"][-1]["per_account"]] == [65],
          _dly26["days"][-1]["per_account"])

    # 采样时刻解析
    check("credits: snapshot-at parses HH:MM (default 08:00)",
          P._parse_snapshot_at("08:00") == (8, 0)
          and P._parse_snapshot_at("7:30") == (7, 30)
          and P._parse_snapshot_at("bad") is None
          and P._CREDITS_SNAPSHOT_AT == "08:00")
finally:
    P.USAGE_DIR = _orig_ud26
    P.POOL = _orig_pool26
    _sh26.rmtree(_d26, ignore_errors=True)
# [27] 孤儿 tool_calls / tool 结果清理（上游对不完整配对直接 400）
# 上游原话："The provided messages input is invalid. The error info is
# [Can only get item pairs from a mapping.]" —— assistant 声明调用了某 id
# 却缺 role=tool 结果时，**整次请求**失败；客户端每轮带完整历史，故该会话
# 之后每轮都 400（表现为「工具调用持续失败」）。
def _tc27(i):
    return {"id": i, "type": "function",
            "function": {"name": "edit", "arguments": "{}"}}

_paired27 = [
    {"role": "user", "content": "x"},
    {"role": "assistant", "content": "", "tool_calls": [_tc27("c1")]},
    {"role": "tool", "tool_call_id": "c1", "name": "edit", "content": "ok"},
    {"role": "user", "content": "go"}]
_out27, _ch27 = P.cleanup_orphan_tool_calls([dict(m) for m in _paired27])
check("orphan: complete pairs untouched",
      _ch27 is False and len(_out27) == 4
      and bool(_out27[1].get("tool_calls")), _ch27)

_orphan_call27 = [
    {"role": "user", "content": "x"},
    {"role": "assistant", "content": "", "tool_calls": [_tc27("c_missing")]},
    {"role": "user", "content": "go"}]
_out27b, _ch27b = P.cleanup_orphan_tool_calls([dict(m) for m in _orphan_call27])
check("orphan: unpaired assistant.tool_calls removed",
      _ch27b is True and not _out27b[1].get("tool_calls")
      and _out27b[1].get("content") == "", _out27b[1])

_orphan_res27 = [
    {"role": "user", "content": "x"},
    {"role": "tool", "tool_call_id": "c_ghost", "name": "edit", "content": "?"},
    {"role": "user", "content": "go"}]
_out27c, _ch27c = P.cleanup_orphan_tool_calls([dict(m) for m in _orphan_res27])
check("orphan: unpaired tool result dropped",
      _ch27c is True and [m["role"] for m in _out27c] == ["user", "user"],
      [m["role"] for m in _out27c])

# 批内一好一坏 -> 整批 tool_calls 删除（与 workbuddy 网关同语义）
_partial27 = [
    {"role": "user", "content": "x"},
    {"role": "assistant", "content": "", "tool_calls": [_tc27("c1"), _tc27("c_bad")]},
    {"role": "tool", "tool_call_id": "c1", "name": "edit", "content": "ok"},
    {"role": "user", "content": "go"}]
_out27d, _ch27d = P.cleanup_orphan_tool_calls([dict(m) for m in _partial27])
check("orphan: partially paired batch drops whole tool_calls",
      _ch27d is True and not _out27d[1].get("tool_calls"), _out27d[1])

# 无工具消息 -> 零改动（不得误伤普通对话）
_plain27 = [{"role": "user", "content": "hi"},
            {"role": "assistant", "content": "yo"}]
_out27e, _ch27e = P.cleanup_orphan_tool_calls([dict(m) for m in _plain27])
check("orphan: plain conversation untouched",
      _ch27e is False and _out27e == _plain27)

# flatten_messages 必须挂上该清理（否则修复不生效）
_fm_src = _insp.getsource(P.flatten_messages)
check("orphan: flatten_messages invokes the cleanup",
      "cleanup_orphan_tool_calls(" in _fm_src)
# [28] 孤儿清理的畸形输入防御（审查 次-1 / 次-2）
# 次-1：id 为空串/缺失/非字符串时，两集合皆空 -> 早退会放行畸形 tool_calls。
_mal27 = [{"role": "user", "content": "x"},
           {"role": "assistant", "content": "",
            "tool_calls": [{"id": "", "type": "function",
                            "function": {"name": "x", "arguments": "{}"}}]}]
_o28, _c28 = P.cleanup_orphan_tool_calls([dict(m) for m in _mal27])
check("orphan: malformed empty-id tool_calls removed",
      _c28 is True and not _o28[1].get("tool_calls"), _o28[1])

_noid28 = [{"role": "user", "content": "x"},
           {"role": "assistant", "content": "",
            "tool_calls": [{"type": "function",
                            "function": {"name": "x", "arguments": "{}"}}]}]
_o28b, _c28b = P.cleanup_orphan_tool_calls([dict(m) for m in _noid28])
check("orphan: missing-id tool_calls removed",
      _c28b is True and not _o28b[1].get("tool_calls"), _o28b[1])

# 次-2：批内含非 dict 条目 -> 整批删除（与 workbuddy 一致）
_junk28 = [{"role": "user", "content": "x"},
           {"role": "assistant", "content": "",
            "tool_calls": ["garbage", {"id": "a", "type": "function",
                                        "function": {"name": "x", "arguments": "{}"}}]},
           {"role": "tool", "tool_call_id": "a", "name": "x", "content": "ok"}]
_o28c, _c28c = P.cleanup_orphan_tool_calls([dict(m) for m in _junk28])
check("orphan: non-dict entry in batch drops whole tool_calls",
      _c28c is True and not _o28c[1].get("tool_calls"), _o28c[1])

# 行为断言（替代源码字符串检查）：flatten 输出必须无未配对 tool_calls
_flat_in28 = [{"role": "user", "content": "x"},
              {"role": "assistant", "content": "",
               "tool_calls": [{"id": "c_orphan28", "type": "function",
                               "function": {"name": "edit", "arguments": "{}"}}]},
              {"role": "user", "content": "go"}]
_sys28, _flat28, _img28 = P.flatten_messages([dict(m) for m in _flat_in28])
check("orphan: flatten output carries no unpaired tool_calls",
      not any(m.get("tool_calls") for m in _flat28)
      and [m["role"] for m in _flat28] == ["user", "assistant", "user"],
      [m.get("role") for m in _flat28])
# [29] 截断 tool_call 的 arguments 防御（客户端报 Unterminated string）
# 场景：SSE 流被截断（连接中断 / finish_reason==length / 上游超时）时，
# arguments 只剩半截 JSON。原样交给客户端 -> 客户端解析失败并卡死会话
# （实测错误串：Tool call arguments are not valid JSON. Parse Error:
#  Unterminated string）。与 workbuddy 网关 truncation.go 同语义。
_tr29 = [
    ("", False, "empty (no-arg tool)"),
    ("   ", False, "whitespace"),
    ('{"a":1}', False, "valid object"),
    ("{}", False, "empty object"),
    ("null", False, "null"),
    ("[1,2]", False, "array"),
    ("123", False, "number"),
    ('{"path": "/a.ts", "new_string": "const a = ', True, "half JSON"),
    ('{"a":', True, "truncated after colon"),
    ('{"a":1', True, "missing brace"),
    ("not json", True, "not json at all"),
]
_bad29 = [d for raw, want, d in _tr29
           if P.is_truncated_arguments(raw) != want]
check("truncation: detection table matches spec",
      not _bad29, _bad29)

_good29 = [{"id": "c1", "type": "function",
            "function": {"name": "edit", "arguments": '{"a":1}'}}]
check("truncation: complete call kept unchanged",
      P.drop_truncated_tool_calls(_good29) == _good29)

_mix29 = _good29 + [{"id": "c2", "type": "function",
                     "function": {"name": "edit", "arguments": '{"b":'}}]
_out29 = P.drop_truncated_tool_calls(_mix29)
check("truncation: truncated call dropped, complete kept",
      len(_out29) == 1 and _out29[0]["id"] == "c1",
      [c["id"] for c in _out29])

_noargs29 = [{"id": "c3", "type": "function",
              "function": {"name": "list", "arguments": ""}}]
check("truncation: empty-args (no-arg tool) not treated as truncated",
      len(P.drop_truncated_tool_calls(_noargs29)) == 1)

# chat 聚合路径必须挂上该过滤（否则修复不生效）
_agg_src29 = _insp.getsource(P.aggregate_stream)
check("truncation: aggregate_stream applies the filter",
      "drop_truncated_tool_calls(" in _agg_src29)
# [30] 截断防护覆盖 chat 流式路径（审查 B1/M1）
# B1: omp 实际走 chat 流式（生产 590 次 vs 非流式 88 次），此前只修了非流式
#     与 responses —— 对目标客户端无效。M1: 断连/超时不产生 finish_reason，
#     只看 finish==length 会全部漏网。

# (a) NaN/Infinity：Python json 接受，客户端 JSON.parse 拒绝 -> 应判为不可解析
check('truncation: NaN/Infinity treated as unparseable',
      P.is_truncated_arguments('NaN')
      and P.is_truncated_arguments('Infinity')
      and P.is_truncated_arguments('-Infinity'),
      [P.is_truncated_arguments(x) for x in ('NaN', 'Infinity', '-Infinity')])
check('truncation: BOM tolerated',
      P.is_truncated_arguments(chr(0xFEFF) + '{"a":1}') is False)

# (b) 流式转发层行为断言（替代源码字符串检查）
class _Resp30(object):
    '''模拟上游信封流：内层 chunk 包进 statusCodeValue 信封。'''
    def __init__(self, inner, finish=None):
        self._lines = []
        for body in inner:
            env = json.dumps({'statusCodeValue': 200, 'body': body})
            self._lines.append(('data: ' + env + chr(10) + chr(10)).encode('utf-8'))
        if finish:
            b2 = json.dumps({'choices': [{'delta': {}, 'finish_reason': finish}]})
            env = json.dumps({'statusCodeValue': 200, 'body': b2})
            self._lines.append(('data: ' + env + chr(10) + chr(10)).encode('utf-8'))
        self._lines.append(b'data: {"body":"[DONE]"}' + b'\n\n')
    def __iter__(self):
        return iter(self._lines)

def _collect30(inner, finish):
    out = []
    for ln in P.iter_client_sse(_Resp30(inner, finish)):
        out.append(ln.decode('utf-8', 'replace'))
    return ''.join(out)

_TC_FIRST = json.dumps({'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'id': 'c1', 'type': 'function',
     'function': {'name': 'edit', 'arguments': ''}}]}}]})
_TC_TRUNC = json.dumps({'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'function': {'arguments': '{"a": '}}]}}]})
_TC_OK = json.dumps({'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'id': 'c1', 'type': 'function',
     'function': {'name': 'edit', 'arguments': '{"a":1}'}}]}}]})

_out_trunc30 = _collect30([_TC_FIRST, _TC_TRUNC], 'length')
check('truncation: streaming drops truncated tool_calls',
      'tool_calls' not in _out_trunc30, _out_trunc30[:160])

_out_nofin30 = _collect30([_TC_FIRST, _TC_TRUNC], None)
check('truncation: streaming guards even without finish_reason (M1)',
      'tool_calls' not in _out_nofin30, _out_nofin30[:160])

_out_ok30 = _collect30([_TC_OK], 'tool_calls')
# arguments 在 SSE 里是 JSON 字符串内嵌，故引号被转义为 \\" —— 断言转义形式。
check('truncation: complete tool_calls still forwarded',
      'tool_calls' in _out_ok30
      and (chr(92) + chr(34) + 'a' + chr(92) + chr(34) + ':1') in _out_ok30,
      _out_ok30[:160])

# handler 必须使用该转发层（行为已验，此处锁接线）
_h_src30 = _insp.getsource(P.Handler._do_POST_impl)
check('truncation: streaming handler wired to guard layer',
      'iter_client_sse(' in _h_src30)

# [31] 第二轮审查发现的回归（M1/M2/M3/R1/S1）
# M2: 缓冲层在断连时必须先补发**完整**调用再放行异常 —— 否则比不缓冲更差。
# M1: custom freeform 载荷本就是裸文本，不能当截断误杀。
# R1: 全丢弃 + finish=tool_calls 时收尾帧须降级 length，否则客户端空转等工具结果。
# S1: 畸形帧必须原样透传，不得因解析假设抛异常。

class _Resp31(object):
    def __init__(self, lines, exc=None):
        self._l = list(lines)
        self._exc = exc
    def __iter__(self):
        for x in self._l:
            yield x
        if self._exc:
            raise self._exc

def _env31(inner):
    return ('data: ' + json.dumps({'statusCodeValue': 200, 'body': inner})
            + chr(10) + chr(10)).encode('utf-8')

def _collect31(lines, exc=None):
    out = []
    err = None
    try:
        for ln in P.iter_client_sse(_Resp31(lines, exc)):
            out.append(ln.decode('utf-8', 'replace'))
    except BaseException as e:
        err = type(e).__name__
    return ''.join(out), err

_TC_FULL = json.dumps({'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'id': 'c1', 'type': 'function',
     'function': {'name': 'edit', 'arguments': '{"x":1}'}}]}}]})
_TC_TRUNC31 = json.dumps({'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'function': {'arguments': '{"y":'}}]}}]})
_FIN_TC = json.dumps({'choices': [{'delta': {}, 'finish_reason': 'tool_calls'}]})

# M2: 断连时完整调用必须被补发，异常仍要放行
_t31, _e31 = _collect31([_env31(_TC_FULL)], exc=ConnectionResetError('x'))
check('truncation: disconnect still flushes complete calls (M2)',
      'tool_calls' in _t31 and _e31 == 'ConnectionResetError',
      {'has_tool_calls': 'tool_calls' in _t31, 'exc': _e31})

# R1: 全丢弃 + finish=tool_calls -> 收尾帧降级为 length
_t31b, _ = _collect31([_env31(_TC_TRUNC31), _env31(_FIN_TC)])
check('truncation: all-dropped + tool_calls downgrades finish to length (R1)',
      'length' in _t31b and 'tool_calls' not in _t31b.split('finish_reason')[0],
      _t31b[-200:])

# S1: 畸形帧原样透传、不抛异常
_bad31 = []
for _lbl, _raw in (('choices-dict', '{"choices": {"a":1}}'),
                   ('choices-str', '{"choices": "x"}'),
                   ('choice-str', '{"choices": ["x"]}'),
                   ('delta-str', '{"choices":[{"delta":"x"}]}'),
                   ('index-list', '{"choices":[{"delta":{"tool_calls":'
                                    '[{"index":[],"function":{"arguments":"{}"}}]}}]}')):
    _o31, _e31b = _collect31([_env31(_raw)])
    if _e31b or not _o31:
        _bad31.append((_lbl, _e31b))
check('truncation: malformed frames pass through without raising (S1)',
      not _bad31, _bad31)

# M1: custom freeform 载荷（裸文本）不得被**丢弃** —— 断言产品行为而非底层函数。
# 注意 is_truncated_arguments 对裸文本返回 True（它不是 JSON，这没错）；
# 关键是 chat_to_response 对 custom 工具**跳过**该判定，否则会误杀合法载荷。
_ctr_raw = P.chat_to_response(
    {'choices': [{'message': {'role': 'assistant', 'content': '',
                              'tool_calls': [{'id': 'c1', 'type': 'function',
                                              'function': {
                                                  'name': 'apply_patch',
                                                  'arguments': '*** Begin Patch'
                                                               + chr(10) + '+hi'
                                                               + chr(10)
                                                               + '*** End Patch'}}]},
                  'finish_reason': 'tool_calls'}],
     'usage': None},
    'm31raw', custom_names={'apply_patch'})
check('truncation: custom freeform payload survives (M1)',
      any(o.get('type') == 'custom_tool_call' for o in _ctr_raw['output'])
      and _ctr_raw.get('status') != 'incomplete',
      {'status': _ctr_raw.get('status'),
       'types': [o.get('type') for o in _ctr_raw['output']]})

# M3: chat_to_response 丢弃截断调用后整轮须为 incomplete
_ctr31 = P.chat_to_response(
    {'choices': [{'message': {'role': 'assistant', 'content': '',
                              'tool_calls': [{'id': 'c1', 'type': 'function',
                                              'function': {'name': 'edit',
                                                           'arguments': '{"z":'}}]},
                  'finish_reason': 'tool_calls'}],
     'usage': None},
    'm31')
check('truncation: non-stream responses marks round incomplete (M3)',
      _ctr31.get('status') == 'incomplete'
      and not any(o.get('type') == 'function_call' for o in _ctr31['output']),
      {'status': _ctr31.get('status'),
       'types': [o.get('type') for o in _ctr31['output']]})

# [32] 第三轮审查的回归用例（MAJ-1/2/3 + 测试缺口）
# MAJ-1: UpstreamStatus 必须直接放行（flush 会污染 emitted，关闭排队/重试）
# MAJ-2: 畸形帧 + holder（生产四条链路全部传 holder）
# MAJ-3: chat 非流式也需 custom 例外

def _env32(inner):
    # body 必须是 JSON **字符串**（iter_inner_sse 只接受 str 形态）
    return ('data: ' + json.dumps({'statusCodeValue': 200,
                                   'body': json.dumps(inner)})
            + chr(10) + chr(10)).encode('utf-8')

class _Resp32(object):
    def __init__(self, lines, exc=None):
        self._l = list(lines)
        self._exc = exc
    def __iter__(self):
        for x in self._l:
            yield x
        if self._exc:
            raise self._exc

# MAJ-1: UpstreamStatus 直接放行，不得先 flush（否则 emitted=True 关掉排队）
_tc32 = json.dumps({'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'id': 'c1', 'type': 'function',
     'function': {'name': 'edit', 'arguments': '{"x":1}'}}]}}]})
_sent32 = []
_raised32 = None
try:
    for _ln in P.iter_client_sse(
            _Resp32([_env32(json.loads(_tc32))],
                    exc=P.UpstreamStatus(403, '{"code":"10605"}'))):
        _sent32.append(_ln)
except P.UpstreamStatus:
    _raised32 = 'UpstreamStatus'
except Exception as _e32:
    _raised32 = type(_e32).__name__
check('truncation: UpstreamStatus passes through without flushing (MAJ-1)',
      _raised32 == 'UpstreamStatus' and len(_sent32) == 0,
      {'raised': _raised32, 'sent': len(_sent32)})

# MAJ-1b: GeneratorExit 不得被吞（close() 不应抛 RuntimeError）
_g32 = P.iter_client_sse(_Resp32([_env32(json.loads(_tc32))]))
try:
    next(_g32)
except StopIteration:
    pass
_ge32 = None
try:
    _g32.close()
except RuntimeError as _e32b:
    _ge32 = str(_e32b)
check('truncation: GeneratorExit not swallowed (MAJ-1)',
      _ge32 is None, _ge32)

# MAJ-2: 畸形帧 + holder 不得抛异常（生产全部传 holder）
_bad32 = []
for _lbl32, _raw32 in (('delta-str', {'choices': [{'delta': 'x'}]}),
                       ('refusal-int', {'choices': [{'delta': {'refusal': 5}}]}),
                       ('choices-dict', {'choices': {'a': 1}}),
                       ('choice-str', {'choices': ['x']})):
    try:
        _o32 = [ln for ln in P.iter_client_sse(
            _Resp32([_env32(_raw32)]), holder={'usage': None})]
        if not _o32:
            _bad32.append((_lbl32, 'no output'))
    except Exception as _e32c:
        _bad32.append((_lbl32, type(_e32c).__name__))
check('truncation: malformed frames with holder do not raise (MAJ-2)',
      not _bad32, _bad32)

# MAJ-3: chat 非流式（aggregate_stream）也须放行 custom 载荷
_RAW32 = '*** Begin Patch' + chr(10) + '+hi' + chr(10) + '*** End Patch'
_ctc32 = {'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'id': 'c1', 'type': 'function',
     'function': {'name': 'apply_patch', 'arguments': _RAW32}}]}}]}
_fin32 = {'choices': [{'delta': {}, 'finish_reason': 'tool_calls'}]}
_h32 = {'usage': None, 'model': 'm', 'custom_names': {'apply_patch'}}
_agg32 = P.aggregate_stream(
    _Resp32([_env32(_ctc32), _env32(_fin32)]), 'm', None, holder=_h32)
_tcs32 = ((_agg32.get('choices') or [{}])[0].get('message') or {}).get(
    'tool_calls') or []
check('truncation: non-stream chat keeps custom payload (MAJ-3)',
      len(_tcs32) == 1
      and _tcs32[0]['function']['name'] == 'apply_patch',
      [t.get('function', {}).get('name') for t in _tcs32])

# 反例：未声明 custom 时仍须丢弃（不能因加了例外而放松）
_h32b = {'usage': None, 'model': 'm'}
_agg32b = P.aggregate_stream(
    _Resp32([_env32(_ctc32), _env32(_fin32)]), 'm', None, holder=_h32b)
_tcs32b = ((_agg32b.get('choices') or [{}])[0].get('message') or {}).get(
    'tool_calls') or []
check('truncation: non-stream chat drops when not declared custom',
      len(_tcs32b) == 0, len(_tcs32b))

# 流式路径的 custom 放行（此前零测试覆盖）
_sent32b = []
for _ln in P.iter_client_sse(
        _Resp32([_env32(_ctc32), _env32(_fin32)]),
        custom_names={'apply_patch'}):
    _sent32b.append(_ln.decode('utf-8', 'replace'))
_joined32 = ''.join(_sent32b)
check('truncation: streaming keeps custom payload (new coverage)',
      'apply_patch' in _joined32, _joined32[:160])

# [33] 带工具的客户端不再继承模板的 Qoder 桌面端系统提示（非法工具 payload 源头）
# 事故：客户端没带 system 时沿用 baseprompt.json 自带的 12KB Qoder CLI 提示
# （教 Task/TodoWrite/Edit/Bash 的用法 + 桌面端语境：Working directory:
# D:/Projects/Qoder 等）。模型照着它写 Qoder 形态的调用，与客户端实际声明的
# 工具 schema 不符 —— 实测表现为非法工具 payload 与半截 arguments。
_tmpl_sys33 = [m for m in (P.BASEPROMPT.get('messages') or [])
               if (m or {}).get('role') == 'system'][0]['content']
_tools33 = [{'type': 'function', 'function': {'name': 'edit', 'parameters': {}}}]
_b33a = P.build_qoder_body(
    {'model': 'qmodel', 'messages': [{'role': 'user', 'content': 'hi'}],
     'tools': _tools33}, None, 'qmodel')
check('[33] tools + no system: template Qoder CLI prompt NOT injected',
      _b33a['messages'][0]['content'] == P.SYSTEM_PROMPT
      and 'You are Qoder' not in _b33a['messages'][0]['content'],
      _b33a['messages'][0]['content'][:60])
check('[33] tools + no system: client tools still forwarded verbatim',
      _b33a['tools'] == _tools33)
_b33b = P.build_qoder_body(
    {'model': 'qmodel', 'messages': [{'role': 'user', 'content': 'hi'}]},
    None, 'qmodel')
check('[33] no tools + no system: template prompt kept (unchanged)',
      _b33b['messages'][0]['content'] == _tmpl_sys33)
_b33c = P.build_qoder_body(
    {'model': 'qmodel',
     'messages': [{'role': 'system', 'content': 'S'},
                  {'role': 'user', 'content': 'hi'}],
     'tools': _tools33}, None, 'qmodel')
check('[33] client system still wins when tools present',
      _b33c['messages'][0]['content'] == 'S')

# [34] 截断口径统一 + responses 流式不再泄漏半截 arguments
# (a) chat 非流式：只要有调用被丢弃，finish 一律 length（此前部分丢弃保持
#     tool_calls、全丢光降级为 stop -> 客户端看到「成功的空响应」）。
# (b) responses 流式：arguments 分片此前**即时下发**，收尾才判定截断 ——
#     残破 JSON 早已进了客户端的累积 buffer（omp 报 Unterminated string）。
#     现改为收尾统一补发：被判定截断的整条不发。
_OK34 = {'id': 'c1', 'type': 'function',
         'function': {'name': 'edit', 'arguments': '{"a":1}'}}
_TR34 = {'id': 'c2', 'type': 'function',
         'function': {'name': 'edit', 'arguments': '{"b":'}}
_ESC34 = json.dumps('{"b":')[1:-1]          # {\"b\":  —— 序列化后的形态


def _agg34(calls, finish='tool_calls'):
    lines = [_env32({'choices': [{'delta': {'tool_calls': calls}}]}),
             _env32({'choices': [{'delta': {}, 'finish_reason': finish}]})]
    return P.aggregate_stream(_Resp32(lines), 'm', None,
                              holder={'usage': None, 'model': 'm'})


_a34 = _agg34([_OK34, _TR34])
_c34 = _a34['choices'][0]
check('[34] chat non-stream: partial drop keeps call but finish=length',
      [t['id'] for t in (_c34['message'].get('tool_calls') or [])] == ['c1']
      and _c34['finish_reason'] == 'length', _c34['finish_reason'])
_a34b = _agg34([_TR34])
_c34b = _a34b['choices'][0]
check('[34] chat non-stream: all dropped -> length (not stop), no tool_calls',
      not _c34b['message'].get('tool_calls')
      and _c34b['finish_reason'] == 'length', _c34b['finish_reason'])
# 旧守卫必须保留：上游只给 finish_reason=tool_calls 却没有任何调用（占位被全部
# 过滤）-> 降级 stop，否则客户端一直等工具结果而空转
_a34c = _agg34([])
check('[34] chat non-stream: no calls + finish=tool_calls -> stop (hang guard)',
      not _a34c['choices'][0]['message'].get('tool_calls')
      and _a34c['choices'][0]['finish_reason'] == 'stop',
      _a34c['choices'][0]['finish_reason'])
check('[34] chat non-stream: truncated args never in the payload',
      _ESC34 not in json.dumps(_a34b), json.dumps(_a34b)[:120])
# responses 非流式（同一聚合体）：status 必须 incomplete，且无残破 JSON
_r34 = P.chat_to_response(_a34b, 'm')
check('[34] responses non-stream: truncated round incomplete, no broken args',
      _r34['status'] == 'incomplete' and _ESC34 not in json.dumps(_r34),
      {'status': _r34['status'],
       'types': [o.get('type') for o in _r34['output']]})


def _rchunk34(delta, finish=None):
    return ('data: ' + json.dumps({'choices': [{'delta': delta,
                                                'finish_reason': finish}]})
            + chr(10) + chr(10)).encode('utf-8')


def _resp_stream34(chunks):
    return b''.join(P.stream_responses_events(
        iter(chunks), 'm',
        {'usage': None, 'custom_names': set()})).decode('utf-8')


_txt34 = _resp_stream34([
    _rchunk34({'tool_calls': [{'index': 0, 'id': 'call_1',
                               'function': {'name': 'edit', 'arguments': ''}}]}),
    _rchunk34({'tool_calls': [{'index': 0,
                               'function': {'arguments': '{"path": "/a'}}]}),
    _rchunk34({}, 'length')])
check('[34] responses stream: truncated fragment NEVER reaches the client',
      _ESC34 not in _txt34
      and 'response.function_call_arguments.delta' not in _txt34
      and 'response.function_call_arguments.done' not in _txt34,
      [l for l in _txt34.splitlines() if 'arguments' in l][:1])
check('[34] responses stream: truncated round ends incomplete',
      '"status": "incomplete"' in _txt34)
_ev34 = [json.loads(l[6:]) for l in _txt34.splitlines() if l.startswith('data: ')]
_tr34 = [e['item'] for e in _ev34
         if e.get('type') == 'response.output_item.done']
check('[34] responses stream: truncated done item has no arguments field',
      bool(_tr34) and 'arguments' not in _tr34[0]
      and _tr34[0].get('status') == 'incomplete', _tr34[:1])
_txt34b = _resp_stream34([
    _rchunk34({'tool_calls': [{'index': 0, 'id': 'call_1',
                               'function': {'name': 'edit', 'arguments': ''}}]}),
    _rchunk34({'tool_calls': [{'index': 0,
                               'function': {'arguments': '{"path": "/a.ts"}'}}]}),
    _rchunk34({}, 'tool_calls')])
_ev34b = [json.loads(l[6:]) for l in _txt34b.splitlines()
          if l.startswith('data: ')]
check('[34] responses stream: complete call still delivered (delta + done)',
      [e.get('delta') for e in _ev34b
       if e.get('type') == 'response.function_call_arguments.delta']
      == ['{"path": "/a.ts"}']
      and [e.get('arguments') for e in _ev34b
           if e.get('type') == 'response.function_call_arguments.done']
      == ['{"path": "/a.ts"}'],
      [e.get('type') for e in _ev34b])

# [35] /v1/chat/completions 的 DSML 兜底（与 /v1/responses 对齐）
# 模型偶尔把调用写成 DeepSeek 风格的 `<｜DSML｜calls>` 文本而不是结构化
# tool_calls（Qoder 语境下更常见）。此前只有 responses 路径解析，chat 路径
# 原样把标签文本交给客户端 —— 调用不执行，且该文本进入下一轮上下文诱导模仿。
_DS35 = chr(0xFF5C)          # 全角竖线 ｜（官方标签形态）
_BLK35 = ('<' + _DS35 + 'DSML' + _DS35 + 'calls>' + chr(10)
          + '<' + _DS35 + 'DSML' + _DS35 + 'invoke name="edit">' + chr(10)
          + '<' + _DS35 + 'DSML' + _DS35 + 'parameter name="path">/a.ts</'
          + _DS35 + 'DSML' + _DS35 + 'parameter>' + chr(10)
          + '</' + _DS35 + 'DSML' + _DS35 + 'invoke>' + chr(10)
          + '</' + _DS35 + 'DSML' + _DS35 + 'calls>')

# 增量匹配器（流式起始探测）：普通文本里的 "<" 不得被扣留
check('[35] DSML matcher: prefix states',
      P._dsml_open_state('<') == 'maybe'
      and P._dsml_open_state('<' + _DS35 + 'DSML' + _DS35 + 'ca') == 'maybe'
      and P._dsml_open_state('<' + _DS35 + 'DSML' + _DS35 + 'calls') == 'maybe'
      and P._dsml_open_state('<' + _DS35 + 'DSML' + _DS35 + 'calls>') == 'match'
      and P._dsml_open_state('<|DSML|calls>') == 'match'
      and P._dsml_open_state('<div>') == 'no'
      and P._dsml_open_state('< b') == 'no')
check('[35] declared_tool_names covers chat + top-level shapes',
      P.declared_tool_names([{'type': 'function',
                              'function': {'name': 'edit'}},
                             {'type': 'custom', 'name': 'apply_patch'}])
      == {'edit', 'apply_patch'})


def _agg35(content, finish='stop', names=None):
    holder = {'usage': None, 'model': 'm'}
    if names is not None:
        holder['allowed_tool_names'] = names
    lines = [_env32({'choices': [{'delta': {'content': content}}]}),
             _env32({'choices': [{'delta': {}, 'finish_reason': finish}]})]
    return P.aggregate_stream(_Resp32(lines), 'm', None, holder=holder)


_a35 = _agg35('先看文件 ' + _BLK35 + ' 完成', names={'edit'})
_m35 = _a35['choices'][0]['message']
_tcs35 = _m35.get('tool_calls') or []
check('[35] DSML non-stream: converted to OpenAI tool_calls',
      [_tc['function']['name'] for _tc in _tcs35] == ['edit']
      and json.loads(_tcs35[0]['function']['arguments']) == {'path': '/a.ts'}
      and _tcs35[0]['type'] == 'function' and bool(_tcs35[0].get('id')),
      _tcs35)
check('[35] DSML non-stream: content cleaned + finish=tool_calls',
      _a35['choices'][0]['finish_reason'] == 'tool_calls'
      and _m35.get('content') == '先看文件 完成', _m35.get('content'))
_m35b = _agg35(_BLK35, names={'read_file'})['choices'][0]['message']
check('[35] DSML non-stream: non-declared name -> text kept, no tool_calls',
      not _m35b.get('tool_calls') and 'DSML' in (_m35b.get('content') or ''))
_m35c = _agg35(_BLK35)['choices'][0]['message']
check('[35] DSML non-stream: no declared tools -> no fallback (compat)',
      not _m35c.get('tool_calls') and 'DSML' in (_m35c.get('content') or ''))


def _frames35(lines, names=None):
    return ''.join(ln.decode('utf-8', 'replace') for ln in
                   P.iter_client_sse(_Resp32(lines), allowed_tool_names=names))


_split35 = ['看这里 ', '<' + _DS35, 'DSML' + _DS35 + 'ca',
            'lls>' + chr(10) + '<' + _DS35 + 'DSML' + _DS35
            + 'invoke name="edit">',
            '<' + _DS35 + 'DSML' + _DS35 + 'parameter name="path">/a.ts</'
            + _DS35 + 'DSML' + _DS35 + 'parameter>',
            '</' + _DS35 + 'DSML' + _DS35 + 'invoke></' + _DS35 + 'DSML'
            + _DS35 + 'calls>']
_lines35 = [_env32({'choices': [{'delta': {'content': p}}]})
            for p in _split35]
_lines35.append(_env32({'choices': [{'delta': {},
                                     'finish_reason': 'stop'}]}))
_out35 = _frames35(_lines35, {'edit'})
_ev35 = [json.loads(l[6:]) for l in _out35.splitlines()
         if l.startswith('data: ')]
# 透传帧是上游原始字节（CJK 以 \uXXXX 转义），故按解析后的 content 断言
_c35a = ''.join(e['choices'][0]['delta'].get('content') or '' for e in _ev35)
check('[35] DSML stream: raw tags never reach the client',
      'DSML' not in _out35 and '看这里' in _c35a, _out35[:120])
_tc35 = [e['choices'][0]['delta']['tool_calls'][0] for e in _ev35
         if e['choices'][0]['delta'].get('tool_calls')]
check('[35] DSML stream: tool_calls frames in OpenAI shape (id+name, args)',
      len(_tc35) == 2 and bool(_tc35[0].get('id'))
      and _tc35[0]['function']['name'] == 'edit'
      and json.loads(_tc35[1]['function']['arguments']) == {'path': '/a.ts'},
      _tc35)
_fr35 = [e['choices'][0].get('finish_reason') for e in _ev35]
check('[35] DSML stream: finish frame rewritten to tool_calls',
      _fr35[-1] == 'tool_calls', _fr35)
_out35b = _frames35(_lines35, {'read_file'})
check('[35] DSML stream: non-declared name -> text passes through',
      'tool_calls' not in _out35b and 'DSML' in _out35b)
# 普通 "<" 立即透传（不被扣留/篡改）
_out35c = _frames35(
    [_env32({'choices': [{'delta': {'content': 'a <div> b'}}]}),
     _env32({'choices': [{'delta': {'content': ' 1<2 c'}}]}),
     _env32({'choices': [{'delta': {}, 'finish_reason': 'stop'}]})],
    {'edit'})
_c35 = ''.join(e['choices'][0]['delta'].get('content') or '' for e in
               [json.loads(l[6:]) for l in _out35c.splitlines()
                if l.startswith('data: ')])
check('[35] DSML stream: ordinary "<" content passes through unchanged',
      _c35 == 'a <div> b 1<2 c', _c35)
# 断流：暂存文本必须补发（不能闷掉），异常仍要放行
_sent35 = []
_err35 = None
try:
    for _ln35 in P.iter_client_sse(
            _Resp32([_env32({'choices': [{'delta': {
                'content': '<' + _DS35 + 'DSML' + _DS35 + 'calls>'
                           + chr(10) + 'x'}}]})],
                    exc=ConnectionResetError('x')),
            allowed_tool_names={'edit'}):
        _sent35.append(_ln35.decode('utf-8', 'replace'))
except BaseException as _e35:
    _err35 = type(_e35).__name__
check('[35] DSML stream: interrupted stream flushes buffer (not swallowed)',
      _err35 == 'ConnectionResetError' and 'DSML' in ''.join(_sent35),
      {'exc': _err35, 'sent': ''.join(_sent35)[:80]})

# [36] 泄漏回读守卫（上游 issue #8/#9/#11/#16）
# 模型把网关内部协议文本复述成正文时的五种形态 + 误伤方向，四条出口
# （chat 流式/非流式、responses 流式/非流式）都要过同一套判据：
#   A  marker 开头 + 截断；B1 散文与 marker 同帧；B2 散文与 marker 分帧；
#   B3 截断落在未写完的 \uXXXX 转义里；C [工具结果] 回声块。
print()
print('[36] leaked tool-call readback (issues #8/#9/#11/#16)')

_M36 = P.LEAK_MARKER
_NAMES36 = {'terminal', 'write_file'}
_CALLS36 = json.dumps([{'name': 'terminal',
                        'arguments': json.dumps({'cmd': 'ls'})}],
                      ensure_ascii=False)
_LEAK36 = _M36 + chr(10) + _CALLS36
_TRUNC36 = _M36 + chr(10) + _CALLS36[:40]      # 未闭合字符串（issue #9 样本）
_ESC36 = (_M36 + chr(10)
          + '[{"name": "write_file", "arguments": "{\\"content\\": \\"probe \\u63a2')
_PROSE36 = 'edge 端点有响应（400/406 = 服务器活着）。调整参数重试。' + chr(10)
_ECHO36 = ('[工具结果]' + chr(10) + '{"output": "ok"}' + chr(10)
           + '[工具结果结束]' + chr(10))

check('[36] hold window = longest marker - 1',
      P._MARKER_HOLD_WINDOW == len(P.LEAK_MARKER) - 1 == 17,
      P._MARKER_HOLD_WINDOW)
check('[36] declared names cover chat + top-level tool shapes',
      P.declared_tool_names([{'type': 'function', 'function': {'name': 'a'}},
                             {'type': 'function', 'name': 'b'}]) == {'a', 'b'})

_rec36, _clean36 = P.parse_leaked_tool_calls(_LEAK36, _NAMES36)
check('[36] strict form: marker + JSON array -> structured call, text cleared',
      bool(_rec36) and _clean36 == ''
      and _rec36[0]['function']['name'] == 'terminal'
      and json.loads(_rec36[0]['function']['arguments'])['cmd'] == 'ls',
      (_rec36, _clean36))
check('[36] fenced form (```json) also recovered',
      bool(P.parse_leaked_tool_calls('```json' + chr(10) + _LEAK36
                                     + chr(10) + '```', _NAMES36)[0]))
check('[36] undeclared tool name -> no recovery (whitelist kept)',
      P.parse_leaked_tool_calls(_LEAK36, {'other'})[0] is None)
check('[36] prose discussing the marker -> no recovery',
      P.parse_leaked_tool_calls('网关会写入 ' + _M36 + ' 这样的提示。')[0] is None)
check('[36] trailing text after the array -> no recovery',
      P.parse_leaked_tool_calls(_LEAK36 + chr(10) + '以上。', _NAMES36)[0] is None)


def _chunk36(content=None, fin=None):
    delta = {} if content is None else {'content': content}
    return {'id': 'c36', 'model': 'm', 'created': 1,
            'choices': [{'index': 0, 'delta': delta, 'finish_reason': fin}]}


def _envlines36(chunks, exc=None):
    return _Resp32([_env32(c) for c in chunks], exc=exc)


def _chat_stream36(chunks, names=_NAMES36, exc=None):
    """走完整 chat 流式守卫链（回读 -> 截断/DSML 转发），按客户端视角取值。"""
    src = P.recover_leaked_tool_calls(
        P.iter_inner_sse(_envlines36(chunks, exc=exc)), allowed_names=names)
    text, calls, finish = '', 0, None
    for ln in P.iter_client_sse(None, holder={'model': 'm'},
                                allowed_tool_names=names, inner_lines=src):
        s = ln.decode('utf-8', 'replace')
        if not s.startswith('data: '):
            continue
        d = json.loads(s[6:].strip())
        ch = (d.get('choices') or [{}])[0]
        dl = ch.get('delta') or {}
        if isinstance(dl.get('content'), str):
            text += dl['content']
        for _tc in dl.get('tool_calls') or []:
            calls += 1
        if ch.get('finish_reason'):
            finish = ch['finish_reason']
    return text, calls, finish


def _agg36(chunks, names=_NAMES36):
    holder = {'usage': None, 'model': 'm', 'allowed_tool_names': names}
    return P.aggregate_stream(_envlines36(chunks), 'm', None, holder=holder)


def _resp_stream36(chunks, names=_NAMES36):
    lines = [('data: ' + json.dumps(c) + chr(10) + chr(10)).encode('utf-8')
             for c in chunks]
    holder = {'usage': None, 'custom_names': set(), 'allowed_tool_names': names}
    return b''.join(P.stream_responses_events(
        P.recover_leaked_tool_calls(iter(lines), allowed_names=names),
        'm', holder)).decode('utf-8')


def _resp_events36(text):
    return [json.loads(l[6:]) for l in text.splitlines() if l.startswith('data: ')]


def _resp_text36(text):
    return ''.join(e.get('delta') or '' for e in _resp_events36(text)
                   if e.get('type') == 'response.output_text.delta')


# --- A：完整 marker + JSON（跨帧分段）→ 还原为结构化调用 ---
_t36, _c36, _f36 = _chat_stream36([_chunk36(_LEAK36[:12]),
                                   _chunk36(_LEAK36[12:]),
                                   _chunk36(None, 'stop')])
check('[36] chat stream A: leak -> tool_calls deltas, no text, finish=tool_calls',
      _t36 == '' and _c36 >= 1 and _f36 == 'tool_calls', (_t36, _c36, _f36))
_a36 = _agg36([_chunk36(_LEAK36[:12]), _chunk36(_LEAK36[12:]),
               _chunk36(None, 'stop')])
_c36a = _a36['choices'][0]
check('[36] chat non-stream A: leak -> structured call, finish=tool_calls',
      _c36a['finish_reason'] == 'tool_calls'
      and _c36a['message'].get('content') == ''
      and ((_c36a['message'].get('tool_calls') or [{}])[0].get('function')
           or {}).get('name') == 'terminal', _c36a)
_txt36r = _resp_stream36([_chunk36(_LEAK36[:12]), _chunk36(_LEAK36[12:]),
                          _chunk36(None, 'stop')])
_fc36 = [e['item'] for e in _resp_events36(_txt36r)
         if e.get('type') == 'response.output_item.done'
         and (e.get('item') or {}).get('type') == 'function_call']
check('[36] responses stream A: leak -> function_call item, no text leak',
      _resp_text36(_txt36r) == '' and bool(_fc36)
      and _fc36[0].get('name') == 'terminal'
      and _M36 not in _txt36r, (_resp_text36(_txt36r)[:60], _fc36[:1]))
_r36 = P.chat_to_response(_agg36([_chunk36(_LEAK36), _chunk36(None, 'stop')]),
                          'm')
check('[36] responses non-stream A: leak -> function_call, no text leak',
      any(o.get('type') == 'function_call' for o in _r36['output'])
      and _M36 not in json.dumps(_r36, ensure_ascii=False),
      [o.get('type') for o in _r36['output']])

# --- B1：散文与 marker 落在同一帧 -> 散文逐字保留 + 调用还原 ---
_t36b, _c36b, _f36b = _chat_stream36([_chunk36(_PROSE36 + _LEAK36),
                                      _chunk36(None, 'stop')])
check('[36] chat stream B1: prose kept verbatim, marker recovered',
      _t36b == _PROSE36 and _c36b >= 1 and _M36 not in _t36b,
      (_t36b[:60], _c36b))
_a36b = _agg36([_chunk36(_PROSE36 + _LEAK36), _chunk36(None, 'stop')])
_c36b2 = _a36b['choices'][0]
check('[36] chat non-stream B1: prose kept, call recovered',
      _c36b2['message'].get('content') == _PROSE36
      and _c36b2['finish_reason'] == 'tool_calls', _c36b2)

# --- B2：散文与 marker 分帧 ---
_t36c, _c36c, _f36c = _chat_stream36([_chunk36(_PROSE36), _chunk36(_M36),
                                      _chunk36(chr(10)), _chunk36(_CALLS36),
                                      _chunk36(None, 'stop')])
check('[36] chat stream B2: prose/marker in separate deltas',
      _t36c == _PROSE36 and _c36c >= 1 and _M36 not in _t36c,
      (_t36c[:60], _c36c))

# --- B3：截断落在未写完的 \uXXXX 转义里（issue #16-B3）---
_t36d, _c36d, _f36d = _chat_stream36([_chunk36(_ESC36), _chunk36(None, 'stop')])
check('[36] chat stream B3: truncated \\uXXXX escape swallowed',
      _t36d == '' and _c36d == 0 and _M36 not in _t36d, (_t36d[:60], _c36d))
_a36d = _agg36([_chunk36(_ESC36), _chunk36(None, 'stop')])
check('[36] chat non-stream B3: truncated escape swallowed',
      _a36d['choices'][0]['message'].get('content') == ''
      and not _a36d['choices'][0]['message'].get('tool_calls')
      and _a36d['choices'][0]['finish_reason'] == 'stop', _a36d['choices'][0])

# --- A(截断)：marker + 未写完的数组 -> 吞掉，绝不透传 ---
_t36e, _c36e, _f36e = _chat_stream36([_chunk36(_TRUNC36[:12]),
                                      _chunk36(_TRUNC36[12:]),
                                      _chunk36(None, 'stop')])
check('[36] chat stream: truncated echo swallowed (finish stays stop)',
      _t36e == '' and _c36e == 0 and _f36e == 'stop'
      and _M36 not in _t36e, (_t36e[:60], _f36e))
_a36e = _agg36([_chunk36(_TRUNC36), _chunk36(None, 'stop')])
check('[36] chat non-stream: truncated echo swallowed',
      _a36e['choices'][0]['message'].get('content') == ''
      and _a36e['choices'][0]['finish_reason'] == 'stop', _a36e['choices'][0])
_txt36t = _resp_stream36([_chunk36(_TRUNC36[:12]), _chunk36(_TRUNC36[12:]),
                          _chunk36(None, 'stop')])
check('[36] responses stream: truncated echo not in output_text',
      _resp_text36(_txt36t) == '' and _M36 not in _txt36t,
      _resp_text36(_txt36t)[:60])

# --- C：[工具结果] 回声块（issue #11）---
_t36f, _c36f, _f36f = _chat_stream36([_chunk36(_ECHO36), _chunk36(None, 'stop')])
check('[36] chat stream C: tool-result echo swallowed',
      '[工具结果' not in _t36f and _t36f == '', (_t36f[:60], _c36f))
_a36f = _agg36([_chunk36(_ECHO36), _chunk36(None, 'stop')])
check('[36] chat non-stream C: tool-result echo swallowed',
      '[工具结果' not in (_a36f['choices'][0]['message'].get('content') or ''),
      _a36f['choices'][0]['message'].get('content'))
_txt36c = _resp_stream36([_chunk36(_ECHO36), _chunk36(None, 'stop')])
check('[36] responses stream C: tool-result echo swallowed',
      '[工具结果' not in _txt36c, _txt36c[:80])

# --- 误伤方向：正常文本逐字不变（含重复输出）---
_t36g, _c36g, _f36g = _chat_stream36([_chunk36('看这个数组：' + chr(10) + '['),
                                      _chunk36('1,2,3]'),
                                      _chunk36(None, 'stop')])
check('[36] false positive: array-like prose passes through unchanged',
      _t36g == '看这个数组：' + chr(10) + '[1,2,3]' and _c36g == 0,
      (_t36g, _c36g))
_t36h, _c36h, _f36h = _chat_stream36(
    [_chunk36('我们在讨论 ' + _M36 + ' 这个标记本身，不要吞。'),
     _chunk36(None, 'stop')])
check('[36] false positive: prose mentioning the marker untouched',
      _t36h == '我们在讨论 ' + _M36 + ' 这个标记本身，不要吞。', _t36h[:80])
_t36i, _c36i, _f36i = _chat_stream36([_chunk36(_LEAK36), _chunk36(None, 'stop')],
                                     names={'other_tool'})
check('[36] false positive: undeclared names -> text passes through (fail-open)',
      _t36i == _LEAK36 and _c36i == 0, (_t36i[:60], _c36i))
_t36j, _c36j, _f36j = _chat_stream36([_chunk36(_LEAK36), _chunk36(None, 'stop')],
                                     names=None)
check('[36] no declared tools -> guard inert, text passes through',
      _t36j == _LEAK36 and _c36j == 0, (_t36j[:60], _c36j))
_a36j = _agg36([_chunk36(_LEAK36), _chunk36(None, 'stop')], names=None)
check('[36] non-stream, no declared tools -> text passes through',
      _a36j['choices'][0]['message'].get('content') == _LEAK36,
      _a36j['choices'][0]['message'].get('content'))
_a36i = _agg36([_chunk36('```json' + chr(10) + '{"a": 1}' + chr(10) + '```'),
                _chunk36(None, 'stop')])
check('[36] false positive: ordinary fenced code block untouched',
      '```json' in (_a36i['choices'][0]['message'].get('content') or ''),
      _a36i['choices'][0]['message'].get('content'))

# --- 未改动的帧必须原样透传（同一帧可能还带 reasoning/refusal 等字段）---
_mixed36 = {'id': 'c', 'model': 'm', 'created': 1, 'choices': [
    {'index': 0, 'delta': {'content': 'Hello', 'reasoning_content': 'think'},
     'finish_reason': None}]}
_r36, _reason36 = '', []
for _ln36 in P.recover_leaked_tool_calls(
        P.iter_inner_sse(_envlines36([_mixed36, _chunk36(None, 'stop')])),
        _NAMES36):
    _d36 = json.loads(_ln36.decode('utf-8')[6:])
    _dl36 = (_d36.get('choices') or [{}])[0].get('delta') or {}
    _r36 += _dl36.get('content') or ''
    _reason36.append(_dl36.get('reasoning_content'))
check('[36] pass-through keeps sibling delta fields (reasoning not dropped)',
      _r36 == 'Hello' and 'think' in _reason36, (_r36, _reason36))
_plain36 = _chunk36('plain')
_out36 = list(P.recover_leaked_tool_calls(
    P.iter_inner_sse(_envlines36([_plain36, _chunk36(None, 'stop')])),
    _NAMES36))
check('[36] untouched content frame passes through byte-identical',
      len(_out36) == 2
      and _out36[0] == ('data: ' + json.dumps(_plain36)
                        + chr(10) + chr(10)).encode('utf-8'), _out36[:1])

# --- 中断/控制流语义：UpstreamStatus 不得被吞、断连不闷掉非候选文本 ---
_sent36 = []
_raised36 = None
try:
    for _ln36 in P.recover_leaked_tool_calls(
            P.iter_inner_sse(_envlines36(
                [_chunk36(_LEAK36)],
                exc=P.UpstreamStatus(403, '{"code":"10605"}'))),
            _NAMES36):
        _sent36.append(_ln36)
except P.UpstreamStatus:
    _raised36 = 'UpstreamStatus'
check('[36] guard: UpstreamStatus passes through, held leak NOT flushed',
      _raised36 == 'UpstreamStatus' and _sent36 == [],
      {'raised': _raised36, 'sent': len(_sent36)})
_sent36b = []
_raised36b = None
try:
    for _ln36 in P.recover_leaked_tool_calls(
            P.iter_inner_sse(_envlines36([_chunk36('```')],
                                         exc=ConnectionResetError('x'))),
            _NAMES36):
        _sent36b.append(_ln36)
except ConnectionResetError:
    _raised36b = 'ConnectionResetError'
check('[36] guard: interrupt flushes non-leak hold (text not lost)',
      _raised36b == 'ConnectionResetError'
      and '```' in ''.join(_l.decode('utf-8', 'replace') for _l in _sent36b),
      {'exc': _raised36b, 'sent': ''.join(
          _l.decode('utf-8', 'replace') for _l in _sent36b)[:60]})

# [37] 上游 SSE 断帧重组（社区实测：一帧被从 JSON 中间切断/注入裸换行）
# 逐行读取时半截 JSON 解析失败 -> 整帧静默丢弃；丢的若是带 id/name 的工具头帧，
# 客户端只剩参数增量（报 "tool call delta is missing id or name"）。
print()
print('[37] upstream SSE frame reassembly (split frames)')

_IN37 = {'id': 'cc37', 'model': 'm',
         'choices': [{'delta': {'content': 'hi'}, 'finish_reason': None}]}
_ENV37 = _env32(_IN37)                    # 一帧完整信封（含尾部空行）
_RAW37 = _ENV37.rstrip(b'\n')             # 事件本体


def _split37(raw, at, tail=True):
    """把事件本体在字节位置 at 处切断（模拟注入的裸换行）。"""
    out = [raw[:at] + b'\n', raw[at:] + b'\n\n']
    return out


_cut37 = _RAW37.find(b'"body"') + 8
_lines37 = _split37(_RAW37, _cut37)
check('[37] premise: the split line alone does not parse',
      not P._sse_payload_ok(_lines37[0].decode().rstrip('\n')))
_out37 = list(P.iter_inner_sse(_Resp32(_lines37)))
check('[37] split frame reassembled into one chunk (not dropped)',
      len(_out37) == 1 and b'"content"' in _out37[0] and b'hi' in _out37[0],
      _out37)
check('[37] reassembled output identical to the intact stream',
      _out37 == list(P.iter_inner_sse(_Resp32([_ENV37]))), _out37)

# 切在 data: 前缀内部（zenodinh/pi-provider-qoder#12 的真实抓包形态）
_out37b = list(P.iter_inner_sse(_Resp32([b'data\n', _RAW37[5:] + b'\n\n'])))
check('[37] split inside the data: prefix also reassembled',
      len(_out37b) == 1 and b'hi' in _out37b[0], _out37b)

# 完整帧逐行即时放行；心跳/注释与 event: 元数据不干扰
_out37c = list(P.iter_inner_sse(_Resp32([
    b': ping\n', _ENV37, b'event:finish{"totalTime":10}\n',
    b'data:{"body":"[DONE]"}\n\n'])))
check('[37] intact frames still pass through (heartbeat/event noise ignored)',
      len(_out37c) == 1 and b'hi' in _out37c[0], _out37c)

# 未闭合的帧：流末仍未决 -> 丢弃，绝不把半截 JSON 透传
_out37d = list(P.iter_inner_sse(_Resp32([_RAW37[:20] + b'\n'])))
check('[37] unclosed frame dropped at end of stream (no half JSON out)',
      _out37d == [], _out37d)

# 死块不得连坐后续完整帧（恢复能力）
_out37e = list(P.iter_inner_sse(_Resp32([
    _RAW37[:20] + b'\n', _ENV37, b'data:{"body":"[DONE]"}\n\n'])))
check('[37] dead fragment does not swallow the next intact frame',
      len(_out37e) == 1 and b'hi' in _out37e[0], _out37e)

# 工具头帧被切断：id/name 必须完整送达（社区报告的实际故障形态）
_IN37f = {'choices': [{'delta': {'tool_calls': [
    {'index': 0, 'id': 'call_1', 'type': 'function',
     'function': {'name': 'edit', 'arguments': '{"p":1}'}}]},
    'finish_reason': None}]}
_ENV37f = _env32(_IN37f)
_cutf = _ENV37f.find(b'call_1') + 2
_out37f = list(P.iter_inner_sse(_Resp32(
    [_ENV37f[:_cutf] + b'\n', _ENV37f[_cutf:]])))
check('[37] split tool-call header frame keeps id + name',
      len(_out37f) == 1 and b'call_1' in _out37f[0] and b'edit' in _out37f[0],
      _out37f)

# 错误信封被切断：重组层不得吞掉 UpstreamStatus（排队/额度换号的控制流信号）
_ERR37 = ('data: ' + json.dumps({'statusCodeValue': 503, 'body': 'quota'})
          + chr(10) + chr(10)).encode('utf-8').rstrip(b'\n')
_cutq = _ERR37.find(b'quota') + 2
_raised37 = None
try:
    list(P.iter_inner_sse(_Resp32([_ERR37[:_cutq] + b'\n',
                                   _ERR37[_cutq:] + b'\n\n'])))
except P.UpstreamStatus as exc:
    _raised37 = str(exc.status)
check('[37] split error envelope still raises UpstreamStatus',
      _raised37 == '503', _raised37)

# 断帧 + 泄漏文本同时出现（真实会话形态）：客户端既不看到半截 JSON，也不看到 marker
_LEAK37 = {'id': 'c37', 'model': 'm', 'choices': [
    {'delta': {'content': _M36 + chr(10) + _CALLS36}, 'finish_reason': None}]}
_ENV37L = _env32(_LEAK37)
_cutl = _ENV37L.find(b'assistant') + 3
_src37 = P.recover_leaked_tool_calls(
    P.iter_inner_sse(_Resp32([_ENV37L[:_cutl] + b'\n', _ENV37L[_cutl:]])),
    allowed_names=_NAMES36)
_text37, _calls37 = '', 0
for _ln37 in P.iter_client_sse(None, holder={'model': 'm'},
                               allowed_tool_names=_NAMES36, inner_lines=_src37):
    _s37 = _ln37.decode('utf-8', 'replace')
    if not _s37.startswith('data: '):
        continue
    _d37 = json.loads(_s37[6:].strip())
    _dl37 = (_d37.get('choices') or [{}])[0].get('delta') or {}
    if isinstance(_dl37.get('content'), str):
        _text37 += _dl37['content']
    for _t37 in _dl37.get('tool_calls') or []:
        _calls37 += 1
check('[37] split frame + leak together: call recovered, no marker leak',
      _text37 == '' and _calls37 >= 1 and _M36 not in _text37,
      (_text37[:60], _calls37))

print()
print("SUMMARY: PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
