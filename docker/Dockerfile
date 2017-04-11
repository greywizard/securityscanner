FROM golang:1.8

RUN apt-get update && apt-get install -y libgeoip-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/

