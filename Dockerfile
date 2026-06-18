FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libmicrohttpd-dev \
    libjansson-dev \
    libsodium-dev \
    libsqlite3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cmake -S . -B build && cmake --build build --config Release -j

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmicrohttpd12 \
    libjansson4 \
    libsodium23 \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/build/jinxiaocun-server /app/jinxiaocun-server

ENV PORT=8080
ENV DB_PATH=/app/data/app.db
ENV USER_DATA_KEY_FILE=/app/data/user_key.b64
ENV SESSION_TTL_HOURS=12

EXPOSE 8080
VOLUME ["/app/data"]

CMD ["/app/jinxiaocun-server"]
