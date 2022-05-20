#pragma once

#include <iostream>
#include <optional>
#include <string>
#include <pcap.h>
#include <netinet/in.h>

#include <spdlog/spdlog.h>


namespace pcap_utils {
    static auto logger = spdlog::stdout_color_mt("pcap");

    std::optional<pcap_t*> start_live_capture(const std::string &interface_name, const int port,
                                              const std::string &filter) {
        std::array<char, PCAP_ERRBUF_SIZE> pcap_err{};
        bpf_u_int32 network_mask = 0;
        bpf_u_int32 network_ip = 0;

        /* Find the properties for the device */
        if (pcap_lookupnet(interface_name.c_str(), &network_ip, &network_mask, pcap_err.data()) == -1) {
            logger->error("Couldn't get netmask for device {} -- {}", interface_name, pcap_err.data());
            return std::nullopt;
        }

        /* Open the session */
        pcap_t* handle = pcap_open_live(interface_name.c_str(), 0, 0, 1000, pcap_err.data());
        if (handle == nullptr) {
            logger->error("Couldn't open device {} -- {}", interface_name.c_str(), pcap_err.data());
            return std::nullopt;
        }

        /* PCAP filter that will be compiled to an eBPF filter */
        struct bpf_program fp{};
        if (pcap_compile(handle, &fp, filter.c_str(), 0, network_ip) == -1) {
            logger->error("Couldn't parse filter {} -- {}", filter, pcap_geterr(handle));
            return std::nullopt;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            logger->error("Couldn't install filter {} -- {}", filter, pcap_geterr(handle));
            return std::nullopt;
        }

        return {handle};
}



}
