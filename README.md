# Purpose

This app sniff memcached binary traffic in order filter certains kind of informations (keys, commands, ttls, errors)
It also offer the possibility to forward store commands to an other memcached instance (still in binary format)

# How to build

- docker build -t memcache_sniffer .
- docker run --rm -ti -v (pwd):/data memcache_sniffer cp memcache_sniffer /data
- sudo setcap cap_net_raw,cap_net_admin=eip ./memcache_sniffer

# How to start

- docker run --rm --net=host --cap-add cap_net_admin -ti memcached_sniffer ./memcache_sniffer xxx

# How to use

    SYNOPSIS
            memcache_sniffer sniff -i <interface_name> -p <port> -f <filter> [-s <number_of_packets>] [-v]
            memcache_sniffer forward -i <interface_name> -p <port> -d <remote_memcached:port> [-n <number_connection>] [-v]
            memcache_sniffer exporter -i <interface_name> -p <port> -l <listen> [-v]
            memcache_sniffer help
    
    OPTIONS
            -i, --interface
                        Interface name to sniff packets on
    
            -p, --port  Port on which memcached instance is listening
    
            -f, --filter
                        Filter memcached packets based on {key, error, ttl, command}
    
            -s, --stats Display stats every x packets instead of streaming
    
            -v, --verbose
                        verbose mode
    
            -i, --interface
                        interface name to sniff packets on
    
            -p, --port  port on which memcached instance is listening
    
            -d, --destination
                        Remote memcached that will receive the SETs requests
    
            -n, --connections
                        Number of remote connections to open
    
            -v, --verbose
                        verbose mode
    
            -i, --interface
                        interface name to sniff packets on
    
            -p, --port  port on which memcached instance is listening
    
            -l, --listen
                        port on which prometheus endpoint is listening on
    
            -v, --verbose
                        verbose mode
