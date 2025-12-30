#!/usr/bin/env bash
set -euo pipefail

# 切换到脚本所在目录，避免硬编码路径
cd "$(dirname "$0")"

# 选择编译器：优先 clang，其次 gcc，可被环境变量 CC 覆盖
if [[ -z "${CC:-}" ]]; then
  if command -v clang >/dev/null 2>&1; then
    CC=clang
  else
    CC=gcc
  fi
fi

# 常用安全与诊断编译参数
CFLAGS=(
  -O2
  -Wall -Wextra -Wformat -Wformat-security
  -Werror
  -fstack-protector-strong
  -fno-omit-frame-pointer
  -D_FORTIFY_SOURCE=2
  -std=c11
  -s
)

# 通过 pkg-config 获取 OpenSSL 编译/链接参数；
# 优先使用模块 openssl，不存在则尝试 libcrypto；最后回退 -lcrypto
OPENSSL_FLAGS=()
if command -v pkg-config >/dev/null 2>&1; then
  if pkg-config --exists openssl; then
    # read -a 按 IFS 分词到数组，避免作为一个参数整体传递
    read -r -a OPENSSL_FLAGS <<< "$(pkg-config --cflags --libs openssl)"
  elif pkg-config --exists libcrypto; then
    read -r -a OPENSSL_FLAGS <<< "$(pkg-config --cflags --libs libcrypto)"
  fi
fi

if [[ ${#OPENSSL_FLAGS[@]} -eq 0 ]]; then
  OPENSSL_FLAGS=(-lcrypto)
fi

echo "> 编译器: $CC"
echo "> CFLAGS: ${CFLAGS[*]}"
echo "> OpenSSL flags: ${OPENSSL_FLAGS[*]}"

"$CC" enc_hand.c -o out "${CFLAGS[@]}" "${OPENSSL_FLAGS[@]}"

echo "> 构建完成: ./out"
ls -l out || true
command -v ldd >/dev/null 2>&1 && echo "> 依赖检查:" && ldd ./out || true