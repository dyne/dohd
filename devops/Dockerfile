# docker build . -t dyne/dohd
# docker run -p 8053:8053 -it dyne/dohd
FROM dyne/devuan:chimaera

RUN apt-get update -y -q \
    && apt-get install --no-install-recommends -y -q libwolfssl-dev \
    git gcc make libc6-dev bind9 daemontools gdb libnghttp2-dev \
    && apt-get clean && rm -rf /var/cache/apt
COPY . dohd/
WORKDIR dohd
RUN make clean && make && cp src/dohd /usr/bin/
RUN adduser dohd --shell=/bin/false --no-create-home --disabled-password
RUN openssl req -nodes -newkey rsa:4096 -keyout /etc/test.key -out /etc/test.csr \
    -subj "/C=IT/ST=Rome/L=Rome/O=Local Host/OU=Testing Department/CN=example.com" \
    && openssl x509 -req -sha256 -days 365 \
    -in /etc/test.csr -signkey /etc/test.key -out /etc/test.crt \
    && chown dohd:dohd /etc/test.*
CMD dohd -c /etc/test.crt -k /etc/test.key -p 8053 -u dohd -d 8.8.8.8 -F -v
