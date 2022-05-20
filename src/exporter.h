#pragma once

#include <chrono>
#include <unordered_map>
#include <functional>
#include <csignal>

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>

#include "protocols/memcachedl.h"
#include "protocols/headers.h"
#include "utils/pcap.h"

namespace exporter {
    static auto logger = spdlog::stdout_color_mt("exporter");

    static std::function<void(double)> on_data_exporter;
    static const size_t INITIAL_ON_FLIGHT_REQUEST = 1000000; // 1 million baby
    static pcap_t* handle = nullptr;

    void filter_latencies_system_clock(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

        // Drop invalid packets
        if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only requests that Get commands
        if(!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


        static std::unordered_map<uint32_t, long> requests_durations(INITIAL_ON_FLIGHT_REQUEST);
        switch(request->magic) {
            case memcached::MSG_TYPE::Request:
                requests_durations[request->opaque] = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                break;

            case memcached::MSG_TYPE::Response:
                auto it = requests_durations.find(request->opaque);
                if (it != std::end(requests_durations)) {
                    long now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                    on_data_exporter(now - it->second);
                    requests_durations.erase(request->opaque);
                }
                break;
        }
    }

    void filter_latencies_packet_clock(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

        // Drop invalid packets
        if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only requests that Get commands
        if(!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


        static std::unordered_map<uint32_t, struct timeval> requests_durations(INITIAL_ON_FLIGHT_REQUEST);
        switch(request->magic) {
            case memcached::MSG_TYPE::Request:
                requests_durations[request->opaque] = header->ts;
                break;

            case memcached::MSG_TYPE::Response:
                auto it = requests_durations.find(request->opaque);
                if (it != std::end(requests_durations)) {
                    struct timeval now{};
                    timersub(&header->ts, &it->second, &now);

                    on_data_exporter(now.tv_usec);
                    requests_durations.erase(request->opaque);
                }
                break;
        }
    }


    int exporter_memcached_latencies(const std::string& interface_name, int port, const pcap_handler& handler, int listenPort, const std::string& clusterName) {

        logger->info("Starting prometheus endpoint on 0.0.0.0:{}", listenPort);
        prometheus::Exposer exposer{fmt::format("0.0.0.0:{}", listenPort)};
        auto registry = std::make_shared<prometheus::Registry>();
        exposer.RegisterCollectable(registry);
        auto& latencies_family = prometheus::BuildHistogram()
                .Name("memcached_latencies_us")
                .Help("Seen latencies in microseconds")
                .Labels({{ "cluster", clusterName }})
                .Register(*registry);


        auto& latencies = latencies_family.Add({}, prometheus::Histogram::BucketBoundaries{1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55,
                                                                                           60, 65, 70, 75, 80, 85, 90, 95, 100, 150, 200,
                                                                                           250, 300, 350, 400, 450, 500, 550, 600, 650, 700,
                                                                                           750, 800, 850, 900, 950, 1000, 1050, 1100, 1150,
                                                                                           1200, 1250, 1300, 1350, 1400, 1450, 1500, 1550,
                                                                                           1600, 1650, 1700, 1750, 1800, 1850, 1900, 1950, 2000,
                                                                                           2100, 2200, 2300, 2400, 2500, 2600, 2700, 2800, 2900,
                                                                                           3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 15000,
                                                                                           20000, 30000, 40000, 50000, 75000, 100000, 150000, 200000});
        on_data_exporter = [&latencies](double value) { latencies.Observe(value); };


        // Filter only packets directed toward a specific port and that has an TCP payload
        std::string pcap_filter = fmt::format("port {} and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", port);
        std::optional<pcap_t*> handleOpt = pcap_utils::start_live_capture(interface_name, port, pcap_filter);
        if(!handleOpt) return EXIT_FAILURE;

        handle = *handleOpt;

        // Register signal handler to exit properly
        const auto stop_pcap_capture = [](int signal) { pcap_close(handle); };
        std::signal(SIGINT, stop_pcap_capture);
        std::signal(SIGTERM, stop_pcap_capture);
        std::signal(SIGKILL, stop_pcap_capture);

        // Start capturing packets
        pcap_loop(handle, 0, handler, nullptr);

        /* And close the session */
        pcap_close(handle);

        return EXIT_SUCCESS;
    }

}
