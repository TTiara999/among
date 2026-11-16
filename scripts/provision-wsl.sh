#!/usr/bin/env bash
# 靶场环境预置（P0-#2 / P1-#11 / P1-#10）：补编译工具链 + dev 头 + semgrep
set -x
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y \
  build-essential cmake pkg-config \
  libssl-dev libcurl4-openssl-dev uuid-dev libevent-dev libatomic1 \
  autoconf automake libtool bison flex \
  python3-venv python3-dev zlib1g-dev
# semgrep（PEP668：--break-system-packages 装到 ~/.local/bin）
pip3 install --user --break-system-packages semgrep 2>&1 | tail -3
echo "=== VERIFY ==="
for h in openssl/ssl.h curl/curl.h uuid/uuid.h event2/event.h; do
  echo "#include <$h>" | gcc -E -x c - >/dev/null 2>&1 && echo "$h OK" || echo "$h MISSING"
done
command -v cmake && cmake --version | head -1
"$HOME/.local/bin/semgrep" --version 2>/dev/null || semgrep --version 2>/dev/null || echo "semgrep MISSING"
echo "=== PROVISION DONE ==="