# Client Image
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y gcc g++ make
WORKDIR /app
COPY src/ToyVpnPing.c src/Makefile ./
RUN make ToyVpnPing

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y iputils-ping net-tools dnsutils && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/ToyVpnPing .
COPY docker/client/client_entrypoint.sh .
RUN chmod +x client_entrypoint.sh
ENTRYPOINT ["./client_entrypoint.sh"]
CMD ["192.168.0.1"]
