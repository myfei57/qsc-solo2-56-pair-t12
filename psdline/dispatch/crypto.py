"""凭据加密与令牌散列。

订户回调签名密钥与自定义认证头不能明文落盘。运行期零三方依赖，因此这里内置
一套 AES-256-CTR + HMAC-SHA256（encrypt-then-MAC）的实现，并附 NIST 向量自测。
生产部署应当通过 ``PSDLINE_DISPATCH_KEY`` 注入主密钥（32 字节的 base64）；
未注入时在状态目录生成一次性主密钥文件（权限 0600），密钥文件本身的保护交给
磁盘与主机边界。

令牌（管理 API 的 bearer token）只存 SHA-256 散列，明文只在签发时返回一次。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from ..errors import ConfigError

# AES S 盒在模块导入时由 GF(2^8) 求逆 + 仿射变换生成，避免手抄大表出错。
_SBOX = bytearray(256)
for _i in range(256):
    # 扩展欧几里得求 GF(2^8) 乘法逆元（0 的逆元定义为 0）。
    if _i == 0:
        _inv = 0
    else:
        _a, _b = _i, 0x11B
        _x0, _x1 = 1, 0
        while _a != 1:
            _q = _a.bit_length() - _b.bit_length()
            if _q < 0:
                _a, _b = _b, _a
                _x0, _x1 = _x1, _x0
                _q = -_q
            _a ^= _b << _q
            _x0 ^= _x1 << _q
        _inv = _x0 & 0xFF
    _v = _inv
    for _j in range(4):
        _v ^= ((_inv << ((_j + 1) * 1)) | (_inv >> (8 - (_j + 1)))) & 0xFF
    _SBOX[_i] = (_v ^ 0x63) & 0xFF
_INV_SBOX = bytes(_SBOX.index(i) for i in range(256))
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(value: int) -> int:
    return ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF


def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _sub_word(word: bytes) -> bytes:
    return bytes(_SBOX[b] for b in word)


def _key_expansion(key: bytes) -> list[bytes]:
    """AES-256 密钥扩展，返回 60 个 4 字节字。"""

    words = [key[i : i + 4] for i in range(0, 32, 4)]
    for index in range(8, 60):
        temp = bytearray(words[index - 1])
        if index % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = bytearray(_sub_word(bytes(temp)))
            temp[0] ^= _RCON[index // 8 - 1]
        elif index % 8 == 4:
            temp = bytearray(_sub_word(bytes(temp)))
        words.append(bytes(a ^ b for a, b in zip(words[index - 8], temp)))
    return words


def _add_round_key(state: bytearray, words: list[bytes], round_index: int) -> None:
    for column in range(4):
        word = words[round_index * 4 + column]
        for row in range(4):
            state[row + 4 * column] ^= word[row]


def _sub_bytes(state: bytearray) -> None:
    for index, value in enumerate(state):
        state[index] = _SBOX[value]


def _shift_rows(state: bytearray) -> None:
    # 状态按列存放：state[r + 4c]；逐行循环左移 r 位。
    for row in range(1, 4):
        row_values = [state[row + 4 * column] for column in range(4)]
        row_values = row_values[row:] + row_values[:row]
        for column in range(4):
            state[row + 4 * column] = row_values[column]


def _mix_columns(state: bytearray) -> None:
    for column in range(4):
        a = [state[row + 4 * column] for row in range(4)]
        state[0 + 4 * column] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        state[1 + 4 * column] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        state[2 + 4 * column] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        state[3 + 4 * column] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)


def aes256_encrypt_block(block: bytes, key: bytes) -> bytes:
    """加密单个 16 字节分组（供自测与 CTR 模式使用）。"""

    if len(block) != 16 or len(key) != 32:
        raise ValueError("AES-256 需要 16 字节分组与 32 字节密钥")
    words = _key_expansion(key)
    state = bytearray(block)
    _add_round_key(state, words, 0)
    for round_index in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, words, round_index)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, words, 14)
    return bytes(state)


def _derive(master: bytes, usage: bytes, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", usage, master, iterations=10_000, dklen=length)


def seal(plaintext: bytes, master_key: bytes) -> str:
    """AES-256-CTR 加密 + HMAC-SHA256，返回自描述的 base64 密文串。"""

    if len(master_key) != 32:
        raise ConfigError("主密钥必须是 32 字节", component="dispatch")
    enc_key = _derive(master_key, b"psdline-dispatch-v1-aes")
    mac_key = _derive(master_key, b"psdline-dispatch-v1-mac")
    nonce = os.urandom(12)
    counter_initial = int.from_bytes(b"\x00\x00\x00\x00" + nonce, "big")
    stream = bytearray()
    for block_index in range((len(plaintext) + 15) // 16):
        counter = (counter_initial + block_index) & ((1 << 128) - 1)
        stream.extend(aes256_encrypt_block(counter.to_bytes(16, "big"), enc_key))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(mac_key, b"v1" + nonce + ciphertext, hashlib.sha256).digest()
    blob = b"v1" + nonce + tag + ciphertext
    return "enc$" + base64.b64encode(blob).decode("ascii")


def open_seal(sealed: str, master_key: bytes) -> bytes:
    """解密 :func:`seal` 产生的密文，MAC 不通过时抛错。"""

    if len(master_key) != 32:
        raise ConfigError("主密钥必须是 32 字节", component="dispatch")
    enc_key = _derive(master_key, b"psdline-dispatch-v1-aes")
    mac_key = _derive(master_key, b"psdline-dispatch-v1-mac")
    try:
        blob = base64.b64decode(sealed[4:] if sealed.startswith("enc$") else sealed, validate=True)
        version, nonce, tag, ciphertext = blob[:2], blob[2:14], blob[14:46], blob[46:]
        if version != b"v1":
            raise ValueError
    except (ValueError, IndexError) as error:
        raise ConfigError("密文格式无法识别", component="dispatch") from error
    expected = hmac.new(mac_key, b"v1" + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ConfigError("密文完整性校验失败（主密钥不匹配或被篡改）", component="dispatch")
    counter_initial = int.from_bytes(b"\x00\x00\x00\x00" + nonce, "big")
    plaintext = bytearray()
    for block_index in range((len(ciphertext) + 15) // 16):
        counter = (counter_initial + block_index) & ((1 << 128) - 1)
        plaintext.extend(aes256_encrypt_block(counter.to_bytes(16, "big"), enc_key))
    return bytes(a ^ b for a, b in zip(ciphertext, plaintext))


def random_secret(length: int = 32) -> str:
    """生成订户签名密钥（hex，明文只在登记/轮换时返回一次）。"""

    if length < 16:
        raise ValueError("密钥长度过短")
    return os.urandom(length).hex()


def random_token() -> tuple[str, str]:
    """生成管理 API 令牌，返回 ``(明文, 散列)``；明文只出现一次。"""

    raw = os.urandom(24).hex()
    return f"psdl_{raw}", hash_token(raw)


def hash_token(raw: str) -> str:
    """对令牌明文做 SHA-256 散列（比对用常量时间比较）。"""

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compare_token(stored_hash: str, presented: str) -> bool:
    """常量时间比较令牌散列。"""

    raw = presented.removeprefix("psdl_")
    return hmac.compare_digest(stored_hash, hash_token(raw))


def load_or_create_master_key(path: str, env_value: str | None = None) -> bytes:
    """解析主密钥：优先环境变量，否则读取（或生成）0600 权限的密钥文件。"""

    if env_value:
        try:
            key = base64.b64decode(env_value, validate=True)
        except ValueError as error:
            raise ConfigError("PSDLINE_DISPATCH_KEY 必须是 base64", component="dispatch") from error
        if len(key) != 32:
            raise ConfigError("PSDLINE_DISPATCH_KEY 解码后必须为 32 字节", component="dispatch")
        return key
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            key = base64.b64decode(handle.read().strip(), validate=True)
        if len(key) != 32:
            raise ConfigError(f"主密钥文件内容非法: {path}", component="dispatch")
        return key
    key = os.urandom(32)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = _atomic_targets(path)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(base64.b64encode(key))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except OSError as error:
        raise ConfigError(f"写入主密钥文件失败: {error}", component="dispatch") from error
    return key


def _atomic_targets(path: str) -> tuple[int, str]:
    import tempfile

    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".key.", dir=directory)
    return fd, tmp
