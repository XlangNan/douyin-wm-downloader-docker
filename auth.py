# -*- coding: utf-8 -*-
"""可选的账号密码登录。

启用方式：同时设置环境变量 AUTH_USER 和 AUTH_PASS。
  · 都没设置  -> 不启用登录（保持原有行为，本机使用不受影响）
  · 只设置一个 -> 直接报错退出（宁可起不来，也不要悄悄裸奔）

会话是「HMAC 签名的 Cookie」，不依赖服务端存储：
  · 签名密钥 = 持久化的随机密钥 + 当前密码摘要，所以改密码会让所有旧登录立刻失效
  · 密钥默认保存在数据目录（WM_DL_DATA_DIR）的 auth_secret 文件里，也可用 AUTH_SECRET 指定
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Dict, Optional, Tuple

import runtime_paths

USER = (os.environ.get("AUTH_USER") or "").strip()
PASSWORD = os.environ.get("AUTH_PASS") or ""

if bool(USER) != bool(PASSWORD):
    raise RuntimeError("AUTH_USER 和 AUTH_PASS 必须同时设置（或都不设置）。")

ENABLED = bool(USER and PASSWORD)

COOKIE_NAME = "wm_session"
SHORT_TTL = 24 * 3600            # 不勾选「保持登录」：1 天（浏览器会话 Cookie）
LONG_TTL = 30 * 24 * 3600        # 勾选「保持登录」：30 天

# 这些路径不需要登录；其余一律拦截
PUBLIC_PATHS = frozenset({"/login", "/api/login", "/favicon.ico", "/healthz"})

# 本进程内部回环请求（/api/save 取自己的流）使用的凭证，每次启动随机生成
INTERNAL_HEADER = "X-WM-Internal"
INTERNAL_TOKEN = secrets.token_urlsafe(32)


def _load_secret() -> str:
    env = (os.environ.get("AUTH_SECRET") or "").strip()
    if env:
        return env
    path = os.path.join(runtime_paths.data_dir(), "auth_secret")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
            if value:
                return value
    except OSError:
        pass
    value = secrets.token_hex(32)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value)
        os.chmod(path, 0o600)
    except OSError:
        pass  # 写不进去就只在本次进程内有效（重启后需重新登录）
    return value


_KEY = b""
if ENABLED:
    _KEY = hashlib.sha256(
        (_load_secret() + "\0" + hashlib.sha256(PASSWORD.encode("utf-8")).hexdigest()).encode("utf-8")
    ).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def check_credentials(username: str, password: str) -> bool:
    """常量时间比较；用户名和密码都比完再下结论，避免泄露「哪个错了」。"""
    ok_user = hmac.compare_digest((username or "").encode("utf-8"), USER.encode("utf-8"))
    ok_pass = hmac.compare_digest((password or "").encode("utf-8"), PASSWORD.encode("utf-8"))
    return ok_user and ok_pass


def make_token(ttl: int) -> str:
    body = _b64(json.dumps({"u": USER, "exp": int(time.time()) + ttl}).encode("utf-8"))
    sig = _b64(hmac.new(_KEY, body.encode("ascii"), hashlib.sha256).digest())
    return body + "." + sig


def verify_token(token: str) -> bool:
    try:
        body, sig = (token or "").split(".", 1)
        want = _b64(hmac.new(_KEY, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, want):
            return False
        data = json.loads(_unb64(body))
        return data.get("u") == USER and int(data.get("exp", 0)) > time.time()
    except Exception:
        return False


def is_authed(request) -> bool:
    if not ENABLED:
        return True
    internal = request.headers.get(INTERNAL_HEADER) or ""
    if internal and hmac.compare_digest(internal, INTERNAL_TOKEN):
        return True
    return verify_token(request.cookies.get(COOKIE_NAME) or "")


def safe_next(value: Optional[str]) -> str:
    """只允许站内相对路径，防止「登录后跳转到别的网站」。"""
    value = (value or "").strip()
    if value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


# ---- 防暴力破解：同一 IP 连续失败 5 次，锁 10 分钟 ----
_MAX_FAILS = 5
_WINDOW = 600
_LOCK = threading.Lock()
_FAILS: Dict[str, Tuple[int, float]] = {}   # ip -> (失败次数, 首次失败时间)


def locked_seconds(ip: str) -> int:
    with _LOCK:
        count, first = _FAILS.get(ip, (0, 0.0))
        if count >= _MAX_FAILS:
            left = int(first + _WINDOW - time.time())
            if left > 0:
                return left
            _FAILS.pop(ip, None)
        return 0


def record_fail(ip: str) -> None:
    now = time.time()
    with _LOCK:
        count, first = _FAILS.get(ip, (0, now))
        if now - first > _WINDOW:
            count, first = 0, now
        _FAILS[ip] = (count + 1, first)
        if len(_FAILS) > 2000:  # 简单封顶，避免被刷爆内存
            for key in list(_FAILS)[:500]:
                _FAILS.pop(key, None)


def record_ok(ip: str) -> None:
    with _LOCK:
        _FAILS.pop(ip, None)
