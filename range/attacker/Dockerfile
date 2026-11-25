# Attacker box for range drills. Tools are installed at build time because the range network has no internet.
FROM kalilinux/kali-rolling
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nmap curl sqlmap nikto ca-certificates iputils-ping \
 && rm -rf /var/lib/apt/lists/*
