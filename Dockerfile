FROM python:3.11-slim

# 在国内网络本地构建时：docker compose build --build-arg USE_CN_MIRROR=1
ARG USE_CN_MIRROR=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8787 \
    WM_DL_DATA_DIR=/data \
    TZ=Asia/Shanghai

RUN if [ "$USE_CN_MIRROR" = "1" ]; then \
      sed -i "s|deb.debian.org|mirrors.aliyun.com|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN if [ "$USE_CN_MIRROR" = "1" ]; then \
      pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

COPY . .

VOLUME ["/data"]
EXPOSE 8787

CMD ["python", "server.py", "--no-browser"]
