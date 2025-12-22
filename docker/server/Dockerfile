# Server Image
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y gcc g++ make
WORKDIR /app
COPY src/ToyVpnServer.cpp src/Makefile ./
RUN make ToyVpnServer

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y iptables iproute2 net-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/ToyVpnServer .
COPY docker/server/server_entrypoint.sh .
RUN chmod +x server_entrypoint.sh
ENTRYPOINT ["./server_entrypoint.sh"]
