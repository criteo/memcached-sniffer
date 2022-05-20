#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <cerrno>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netinet/tcp.h>
#include <netdb.h>


namespace cnx {

static auto logger = spdlog::stdout_color_mt("sockets");

std::optional<int> connect_to(std::string_view host, int port) {

    // Fill information regarding destination and connect
    addrinfo hints{}, *infoptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if(int ret = getaddrinfo(host.data(), fmt::format("{}", port).c_str(), &hints, &infoptr); ret != 0) {
        logger->error("Cannot resolve hostname {} -- {}", host, gai_strerror(ret));
        return std::nullopt;
    }

    int sock_fd = -1;
    for (addrinfo* p = infoptr; p != nullptr; p = p->ai_next) {
        sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock_fd < 0) continue;

        if(connect(sock_fd, p->ai_addr, p->ai_addrlen) < 0) {
            close(sock_fd);
            sock_fd = -1;
            continue;
        }

        break;
    }

    if(sock_fd < 0) {
        logger->error("Impossible to connect to {}:{} -- {}", host, port, strerror(errno));
        return std::nullopt;
    }

    logger->info("Connected to {}:{}", host, port);

    //Disable Nagle algorithm
    int nodelay = 1;
    socklen_t len = sizeof(nodelay);
    if(setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, len) < 0) {
        logger->error("Cannot disable Nagle algorithm -- {}", strerror(errno));
        return std::nullopt;
    }

    // Increase send buffer
    // Max payload for memcached is 1m so match it
    int size = 1024 * 1024 * 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, len) < 0) {
        logger->error("Cannot increase send buffer of the socket -- {}", strerror(errno));
        return std::nullopt;
    }

    // Set the socket in non blocking mode
    int flags = fcntl(sock_fd, F_GETFL, 0);
    flags = fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);
    if(flags < 0) {
        logger->error("Cannot set socket as non blocking -- {}", strerror(errno));
        return std::nullopt;
    }

    // We are interested only by sending requests, we do not care of response
    // So close the read buffer it will avoid us syscalls to empty read buffer
    shutdown(sock_fd, SHUT_RD);

    return {sock_fd};
}




}
