"""qoder_fingerprint.py —— 统一设备指纹稳定派生模块 (derive_id)

无论是国内版 (qoder.com.cn / gateway.qoder.com.cn) 还是国际版
(qoder.com / api3.qoder.sh)，均通过本模块基于账号 UID 和加盐哈希单向派生
固定的伪物理设备特征 (machineId / sessionId)，确保每个账号长期来自同一台
虚拟物理设备，且多账号之间天然隔离，阻断跨账号关联风控。

COSY 推理签名会携带 cosy-machineid / cosy-machinetoken / cosy-machinetoken，
这里提供与 WorkBuddy 网关同构的稳定派生逻辑：
  - machineId  : 由 uid 稳定派生（同一账号永远相同）
  - sessionId  : 由 uid 稳定派生（会话隔离）
  - request id : 每请求随机 UUID4（不带账号级恒定前缀，避免被聚类）
"""
import hashlib
import time


def derive_id(uid: str, salt: str) -> str:
    """由 uid + salt 稳定派生一个 36 位十六进制设备/会话标识。

    幂等：同一账号每次调用产生相同值，彻底避免随机机器码导致的上游风控。
    """
    seed = f"{salt}:{uid or 'anonymous'}"
    return hashlib.md5(seed.encode("utf-8")).hexdigest()[:36]


def generate_request_id(uid: str) -> str:
    """生成每个请求唯一的 request id（UUID4）。

    原先用「uid 派生前缀 + 微秒时间戳」——同一账号所有业务请求共享同一恒定
    前缀，可被一键聚类，且格式非 UUID，与官方客户端（每请求随机 UUID）不符。
    这是每个业务请求都会带的头，收益高于多数改造项。
    """
    import uuid as _uuid
    return str(_uuid.uuid4())


def derive_machine_type(uid: str) -> str:
    """稳定派生 18 位去横线的 machine_type（cosy-machinetoken 同形）。"""
    return derive_id(uid, "machinetype").replace("-", "")[:18]


def derive_machine_token(uid: str) -> str:
    """稳定派生 machine_token（base64url 风格的随机串外观）。"""
    raw = hashlib.sha512(f"machinetoken:{uid}".encode("utf-8")).digest()
    import base64
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")[:43]


def get_desktop_fingerprint(uid: str, nickname: str = "", os_name: str = "win32") -> dict:
    """生成上报事件所需的标准完整桌面端指纹（行为事件上报用）。"""
    now = int(time.time() * 1000)
    return {
        "timezone": "Asia/Shanghai",
        "reportDelay": 2000,
        "userId": uid,
        "username": nickname,
        "userNickname": nickname,
        "product": "SaaS",
        "releaseDate": 1789036585355,
        "commit": "5f9692923c93033111c51ad7b003eb80204a9b75",
        "ideName": "Qoder",
        "ideType": "Qoder",
        "ideVersion": "1.1.34",
        "machineId": derive_id(uid, "machine"),
        "sessionId": derive_id(uid, "session"),
        "extName": "qoder-desktop",
        "extVersion": "1.1.34",
        "os": os_name,
        "arch": "x64",
        "osVersion": "10.0.26220",
        "cpuCores": 20,
        "memorySize": 24,
        "timestamp": now,
        "presentAt": now,
    }
