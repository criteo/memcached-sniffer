#pragma once

#include <spdlog/spdlog.h>
#include <map>
#include "protocols/headers.h"
#include "protocols/memcachedl.h"
#include "utils/pcap.h"

namespace sniffer {

    static auto logger = spdlog::stdout_color_mt("sniffer");
    static const size_t INITIAL_ON_FLIGHT_REQUEST = 1000000; // 1 million baby

    static std::function<void(std::string_view)> on_data;

    void filter_get_miss(u_char * /*args*/, const struct pcap_pkthdr *header, const u_char *packet) {

        // Drop invalid packets
        if (packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // We are interested only by packets that contains memcached protocol header and are of type Get
        if (!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;

        static std::unordered_map <uint32_t, std::string> requests(INITIAL_ON_FLIGHT_REQUEST);
        switch (request->magic) {
            case memcached::MSG_TYPE::Request:
                if (memcached::has_key(request)) {
                    requests[request->opaque] = memcached::get_key(request);
                }
                break;

            case memcached::MSG_TYPE::Response:
                auto it = requests.find(request->opaque);
                if (it != requests.end()) {
                    if (memcached::get_value(request) == "Not found") {
                        on_data(fmt::format("{};not_found", it->second));

                    } else {
                        on_data(fmt::format("{};found", it->second));
                    }

                    requests.erase(request->opaque);
                }
                break;
        }

    }

    void filter_keys(u_char * /*args*/, const struct pcap_pkthdr *header, const u_char *packet) {

        // Drop invalid packets
        if (packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // We are interested only by packets that contains memcached protocol header
        if (!memcached::is_valid_header(request)) return;

        if (memcached::has_key(request)) {
            on_data(memcached::get_key(request));
        }
    }

    void filter_errors(u_char * /*args*/, const struct pcap_pkthdr *header, const u_char *packet) {

        // Drop invalid packets
        if (packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only response contains status code of operations
        if (!memcached::is_valid_header(request) || request->magic != memcached::MSG_TYPE::Response) return;

        uint16_t status_code = ntohs(request->rsp_status);
        if (status_code > (uint8_t) memcached::RSP_STATUS::Key_not_found) {
            better_enums::optional <memcached::RSP_STATUS> status = memcached::RSP_STATUS::_from_integral_nothrow(
                    status_code);
            if (status) {
                on_data(fmt::format("{} : {}", status->_to_string(), memcached::get_value(request)));
            }
        }
    }

    void filter_latencies(u_char * /*args*/, const struct pcap_pkthdr *header, const u_char *packet) {

        // Drop invalid packets
        if (packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only requests that Get commands
        if (!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


        static std::unordered_map<uint32_t, struct timeval> requests_durations(INITIAL_ON_FLIGHT_REQUEST);
        switch (request->magic) {
            case memcached::MSG_TYPE::Request:
                requests_durations[request->opaque] = header->ts;
                break;

            case memcached::MSG_TYPE::Response:
                auto it = requests_durations.find(request->opaque);
                if (it != std::end(requests_durations)) {
                    struct timeval now{};
                    timersub(&header->ts, &it->second, &now);

                    on_data(fmt::format("{}", now.tv_usec));
                    requests_durations.erase(request->opaque);
                }
                break;
        }
    }

    void filter_commands(u_char * /*args*/, const struct pcap_pkthdr *header, const u_char *packet) {

        // Drop invalid packets
        if (packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only response contains status code of operations
        if (!memcached::is_valid_header(request)) return;

        better_enums::optional <memcached::COMMANDS> status = memcached::COMMANDS::_from_integral_nothrow(
                static_cast<uint8_t >(request->opcode));
        if (status) {
            on_data(status->_to_string());
        }
    }

    void filter_ttls(u_char * /*args*/, const struct pcap_pkthdr *header, const u_char *packet) {

        // Drop invalid packets
        if (packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only response contains status code of operations
        if (!memcached::is_valid_header(request) || !memcached::has_extra(*request)) return;

        auto foo = memcached::get_extra<memcached::MSG_TYPE::Request, memcached::COMMAND::Set>(request)->expiration;

        switch (request->opcode) {
            case memcached::COMMAND::Set:
            case memcached::COMMAND::Add:
            case memcached::COMMAND::Replace:
                on_data(fmt::format("{}",
                                    ::ntohl(foo)));
                break;

            default:
                break;
        }

    }

    int sniff_memcached_traffic(const std::string &interface_name, int port, const pcap_handler &handler,
                                int packet_limit) {

        // Basically aggregate results or stream them to stdout
        std::unordered_map <std::string, size_t> counters(packet_limit);
        on_data = (packet_limit > 0)
                  ? on_data = [&counters](std::string_view data) { counters[std::string(data)]++; }
                  : on_data = [](std::string_view data) { std::cout << data << '\n'; };


        // Filter only packets directed toward a specific port and that has an TCP payload
        std::string pcap_filter = fmt::format(
                "port {} and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", port);
        std::optional < pcap_t * > handleOpt = pcap_utils::start_live_capture(interface_name, port, pcap_filter);
//    pcap_t* handle = pcap_open_offline("dump.pcap", pcap_err.data());

        if (!handleOpt) return EXIT_FAILURE;

        pcap_t *handle = *handleOpt;

        pcap_loop(handle, packet_limit, handler, nullptr);
        for (const auto &kv: counters) {
            std::cout << kv.first << " : " << kv.second << '\n';
        }

        /* And close the session */
        pcap_close(handle);

        return EXIT_SUCCESS;
    }


}
