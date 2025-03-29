# Install packages and set locale
FROM kalilinux/kali-linux-docker


RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list && \
    echo "kali-docker" > /etc/hostname && \
    set -x && \
    apt-get -yqq update && \
    apt-get -yqq dist-upgrade && \
    apt-get clean && \
    apt-get install -yqq vim telnet nmap metasploit-framework sqlmap wpscan

WORKDIR /root

RUN curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"[^"]*' | sed 's/"public_url":"//'


RUN DEBIAN_FRONTEND=noninteractive    
ARG NGROK_AUTH_TOKEN
ENV SSH_PASS=${SSH_PASS}
ENV NGROK_AUTH_TOKEN=$NGROK_AUTH_TOKEN}
ENV NGROK_TIMEOUT=$NGROK_TIMEOUT}

# Install packages and set locale
s

RUN service ssh start
RUN chmod 755 kali.sh

EXPOSE 22/tcp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sleep", "infinity"]
