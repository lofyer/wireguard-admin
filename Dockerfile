FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/wireguard-admin

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8000/tcp 51820/udp

ENTRYPOINT ["./entrypoint.sh"]
