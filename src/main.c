/*
 * modgrep - MODBUS TCP traffic analyzer
 * Inspired by sngrep: https://github.com/irontec/sngrep
 *
 * Copyright (c) 2026 Rodolfo Santos
 * Licensed under the MIT License.
 */

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MODBUS_DEFAULT_PORT 502
#define MODBUS_MBAP_HEADER 7

static void usage(const char *program) {
    fprintf(stderr,
            "Usage:\n"
            "  %s -i <interface> [-f <bpf filter>]\n"
            "  %s -r <capture.pcap> [-f <bpf filter>]\n"
            "  %s --list-interfaces\n\n"
            "Options:\n"
            "  -i <interface>  Capture from a network interface\n"
            "  -r <file>       Read packets from a PCAP file\n"
            "  -f <filter>     BPF capture filter (default: tcp port 502)\n"
            "  --list-interfaces  List available capture interfaces\n",
            program, program, program);
}

static const char *function_name(uint8_t code) {
    switch (code & 0x7f) {
    case 0x01: return "Read Coils";
    case 0x02: return "Read Discrete Inputs";
    case 0x03: return "Read Holding Registers";
    case 0x04: return "Read Input Registers";
    case 0x05: return "Write Single Coil";
    case 0x06: return "Write Single Register";
    case 0x0f: return "Write Multiple Coils";
    case 0x10: return "Write Multiple Registers";
    default: return "Unknown or vendor-specific";
    }
}

static void print_time(const struct pcap_pkthdr *header) {
    time_t seconds = (time_t)header->ts.tv_sec;
    struct tm tm_value;
    char buffer[32];

    localtime_r(&seconds, &tm_value);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_value);
    printf("%s.%06ld ", buffer, (long)header->ts.tv_usec);
}

static void parse_modbus(const uint8_t *payload, size_t length,
                         const char *source, const char *destination,
                         const struct pcap_pkthdr *header) {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t mbap_length;
    uint8_t unit_id;
    uint8_t function_code;
    int exception;

    if (length < MODBUS_MBAP_HEADER + 1)
        return;

    transaction_id = ((uint16_t)payload[0] << 8) | payload[1];
    protocol_id = ((uint16_t)payload[2] << 8) | payload[3];
    mbap_length = ((uint16_t)payload[4] << 8) | payload[5];
    unit_id = payload[6];
    function_code = payload[7];
    exception = (function_code & 0x80) != 0;

    if (protocol_id != 0)
        return;

    print_time(header);
    printf("%s -> %s\n", source, destination);
    printf("  MODBUS TCP transaction=%u unit=%u function=%s (0x%02x)\n",
           transaction_id, unit_id, function_name(function_code), function_code);

    if (exception) {
        if (length >= 9)
            printf("  MODBUS exception code=0x%02x\n", payload[8]);
    } else if ((function_code & 0x7f) == 0x03 ||
               (function_code & 0x7f) == 0x04) {
        if (length >= 10)
            printf("  byte count=%u\n", payload[8]);
    } else if ((function_code & 0x7f) == 0x06 && length >= 12) {
        uint16_t address = ((uint16_t)payload[8] << 8) | payload[9];
        uint16_t value = ((uint16_t)payload[10] << 8) | payload[11];
        printf("  register address=%u value=%u\n", address, value);
    }

    printf("\n");
}

static void process_packet(const struct pcap_pkthdr *header,
                           const uint8_t *packet) {
    const struct ether_header *ethernet;
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    const uint8_t *payload;
    size_t ip_header_length;
    size_t tcp_header_length;
    size_t payload_length;
    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];

    if (header->caplen < sizeof(struct ether_header))
        return;

    ethernet = (const struct ether_header *)packet;
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP)
        return;

    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
        return;

    ip_header = (const struct ip *)(packet + sizeof(struct ether_header));
    if (ip_header->ip_v != 4 || ip_header->ip_p != IPPROTO_TCP)
        return;

    ip_header_length = (size_t)ip_header->ip_hl * 4;
    if (header->caplen < sizeof(struct ether_header) + ip_header_length + sizeof(struct tcphdr))
        return;

    tcp_header = (const struct tcphdr *)
        ((const uint8_t *)ip_header + ip_header_length);
    tcp_header_length = (size_t)tcp_header->th_off * 4;

    payload = (const uint8_t *)tcp_header + tcp_header_length;
    payload_length = header->caplen -
        sizeof(struct ether_header) - ip_header_length - tcp_header_length;

    if (payload_length == 0)
        return;

    if (!inet_ntop(AF_INET, &ip_header->ip_src, source, sizeof(source)) ||
        !inet_ntop(AF_INET, &ip_header->ip_dst, destination, sizeof(destination)))
        return;

    parse_modbus(payload, payload_length, source, destination, header);
}

static int run_capture(pcap_t *handle, const char *filter) {
    struct bpf_program compiled_filter;
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int result;

    if (filter && filter[0] != '\0') {
        if (pcap_compile(handle, &compiled_filter, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
            return 1;
        }

        if (pcap_setfilter(handle, &compiled_filter) == -1) {
            fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
            pcap_freecode(&compiled_filter);
            return 1;
        }

        pcap_freecode(&compiled_filter);
    }

    while ((result = pcap_next_ex(handle, &header, &packet)) == 1)
        process_packet(header, packet);

    if (result == -1)
        fprintf(stderr, "Capture error: %s\n", pcap_geterr(handle));

    return result == -2 ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *interface_name = NULL;
    const char *pcap_file = NULL;
    const char *filter = "tcp port 502";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int option;
    int status;

    while ((option = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (option) {
        case 'i': interface_name = optarg; break;
        case 'r': pcap_file = optarg; break;
        case 'f': filter = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    if (argc > optind && strcmp(argv[optind], "--list-interfaces") == 0) {
        pcap_if_t *devices;
        pcap_if_t *device;

        if (pcap_findalldevs(&devices, error_buffer) == -1) {
            fprintf(stderr, "pcap_findalldevs: %s\n", error_buffer);
            return 1;
        }

        for (device = devices; device; device = device->next)
            printf("%s\n", device->name);

        pcap_freealldevs(devices);
        return 0;
    }

    if (!interface_name && !pcap_file) {
        usage(argv[0]);
        return 1;
    }

    if (pcap_file) {
        handle = pcap_open_offline(pcap_file, error_buffer);
        if (!handle) {
            fprintf(stderr, "Cannot open %s: %s\n", pcap_file, error_buffer);
            return 1;
        }
    } else {
        handle = pcap_create(interface_name, error_buffer);
        if (!handle) {
            fprintf(stderr, "Cannot open %s: %s\n", interface_name, error_buffer);
            return 1;
        }

        if (pcap_set_promisc(handle, 1) == -1 ||
            pcap_set_timeout(handle, 1000) == -1 ||
            pcap_activate(handle) == -1) {
            fprintf(stderr, "Cannot activate %s: %s\n",
                    interface_name, pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
    }

    status = run_capture(handle, filter);
    pcap_close(handle);
    return status;
}
