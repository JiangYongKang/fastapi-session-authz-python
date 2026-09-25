"""凭证生成与哈希工具：明文只在签发瞬间出现，存储与日志一律用哈希。"""
from __future__ import annotations

import hashlib
import secrets


def generate_token(num_bytes: int) -> str:
    """生成密码学安全的随机明文凭证（URL 安全编码）。"""
    return secrets.token_urlsafe(num_bytes)


def hash_token(plaintext: str) -> str:
    """对明文凭证做不可逆哈希，用于存储与比对。"""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def fingerprint(plaintext: str) -> str:
    """返回可安全打印的凭证指纹（哈希前 12 位），日志中绝不出现明文。"""
    return hash_token(plaintext)[:12]
