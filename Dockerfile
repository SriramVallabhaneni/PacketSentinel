FROM python:3.12-slim

# Required for Scapy raw socket access
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Needs to run as root for raw packet capture
CMD ["python", "-m", "ids.sniffer"]