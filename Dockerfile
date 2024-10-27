# Install packages and set locale
FROM kalilinux/kali-linux-docker

LABEL version="1.0" \
      author="Mike Flynn" \
      description="Custom Kali Linux docker"

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list && \
    echo "kali-docker" > /etc/hostname && \
    set -x && \
    apt-get -yqq update && \
    apt-get -yqq dist-upgrade && \
    apt-get clean && \
    apt-get install -yqq vim telnet nmap metasploit-framework sqlmap wpscan

WORKDIR /root


RUN DEBIAN_FRONTEND=noninteractive    
ARG NGROK_AUTH_TOKEN
ENV SSH_PASS=${SSH_PASS}
ENV NGROK_AUTH_TOKEN=$NGROK_AUTH_TOKEN}
ENV NGROK_TIMEOUT=$NGROK_TIMEOUT}

# Install packages and set locale
RUN apt-get update \
    && apt-get install -y locales nano ssh sudo python3 curl wget \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH tunnel using ngrok
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.utf8



# Create directory for SSH daemon's runtime files

RUN service ssh start
RUN chmod 755 kali.sh

EXPOSE 22/tcp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sleep", "infinity"]
