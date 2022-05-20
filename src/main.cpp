#include <iostream>
#include <chrono>
#include <string>
#include <pcap.h>

#include <clipp.h>
#include <spdlog/spdlog.h>
#include <map>

#include "utils/socket.h"
#include "exporter.h"
#include "forwarder.h"
#include "sniffer.h"

static auto logger = spdlog::stdout_color_mt("main");




int main(int argc, char *argv[]){
    using namespace clipp;

    enum class mode {sniff, forward, exporter, help};
    mode selected = mode::help;
    bool verbose = false;

    std::string memcached_hostname;
    int memcached_port;
    size_t memcached_nb_cnx = 200;
    size_t len;

    std::string interface_name;
    int port, listenPort;
    std::string filter;
    int nb_msg = 0;
    std::string destination;
    std::string clusterName;
    std::map<std::string, pcap_handler> callbacks{ { "key",       sniffer::filter_keys },
                                                   { "error",     sniffer::filter_errors },
                                                   { "command",   sniffer::filter_commands },
                                                   { "ttl",       sniffer::filter_ttls },
                                                   { "latencies", sniffer::filter_latencies },
                                                   { "miss",      sniffer::filter_get_miss },
                                                  };

    const auto sniffMode = (
            command("sniff").set(selected, mode::sniff),
            required("-i", "--interface").doc("Interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("Port on which memcached instance is listening") & value("port", port),
            required("-f", "--filter").doc("Filter memcached packets based on {key, error, ttl, command, miss}") & value("filter", filter),
            option("-s", "--stats").doc("Display stats every x packets instead of streaming") & value("number_of_packets", nb_msg),
            option("-v", "--verbose").doc("verbose mode").set(verbose)
            );

    const auto forward = (
            command("forward").set(selected, mode::forward),
            required("-i", "--interface").doc("interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("port on which memcached instance is listening") & value("port", port),
            required("-d", "--destination").doc("Remote memcached that will receive the SETs requests") & value("remote_memcached:port", destination),
            option("-n", "--connections").doc("Number of remote connections to open") & value("number_connection", memcached_nb_cnx),
            option("-v", "--verbose").doc("verbose mode").set(verbose)
            );

    const auto exporter = (
            command("exporter").set(selected, mode::exporter),
                    required("-i", "--interface").doc("interface name to sniff packets on") & value("interface_name", interface_name),
                    required("-p", "--port").doc("port on which memcached instance is listening") & value("port", port),
                    required("-l", "--listen").doc("port on which prometheus endpoint is listening on") & value("listen", listenPort),
                    required("-c", "--clustername").doc("name of the cluster where this node belong") & value("cluster_name", clusterName),
                    option("-v", "--verbose").doc("verbose mode").set(verbose)
    );

    const auto cli = (sniffMode | forward | exporter | command("help").set(selected, mode::help));

    if(!parse(argc, argv, cli)) {
        std::cout << make_man_page(cli, "memcache_sniffer");
        return EXIT_FAILURE;
    }

    if(verbose) {
            spdlog::set_level(spdlog::level::debug);
    }

    switch(selected) {
        case mode::sniff:
            if(callbacks.count(filter) <= 0) {
                logger->error("Requested filter {} does not exist", filter);
                return EXIT_FAILURE;
            }

            return sniffer::sniff_memcached_traffic(interface_name, port, callbacks[filter], nb_msg);

        case mode::forward:
            len = destination.find(':');
            if(len >= destination.size() - 1) {
                logger->error("Invalid memcached remote destination {}. Should respect `hostname:port` format", destination);
                return EXIT_FAILURE;
            }
            memcached_hostname = destination.substr(0, len);
            memcached_port = std::stoi(destination.substr(len+1, destination.size() - len + 1));
            return forwarder::forward_memcached_traffic(interface_name, port, memcached_nb_cnx, [&memcached_hostname, &memcached_port](){
                return cnx::connect_to(memcached_hostname, memcached_port);
            });

        case mode::help:
            std::cout << make_man_page(cli, "memcache_sniffer");
            return EXIT_SUCCESS;

        case mode::exporter:
            return exporter::exporter_memcached_latencies(interface_name, port, exporter::filter_latencies_system_clock,
                                                          listenPort, clusterName);
    }

}
