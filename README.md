# modgrep

**modgrep** is a MODBUS TCP traffic analyzer for the terminal. It reads PCAP files or captures live traffic and shows each client/server conversation as a ladder diagram, in the spirit of sngrep.

## Credits

This project is a **spin-off inspired by [sngrep](https://github.com/irontec/sngrep)** by [Irontec](https://www.irontec.com/), the ncurses SIP message flow viewer. modgrep is an independent implementation for MODBUS TCP and does not contain sngrep source code. Many thanks to the sngrep authors for the idea and the user experience that inspired this tool.

## Features

- Live capture (`-i`) and PCAP analysis (`-r`).
- List of client/server conversations.
- Ladder diagram: requests in green, responses in yellow, exceptions in red.
- Decoded address, quantity and value fields for common function codes.
- Request/response latency, matched by Transaction ID.
- Raw hex view of the selected message.
- Ethernet, VLAN, Linux cooked and raw IPv4 captures.

## Build

Debian / Ubuntu / Kali:

```bash
sudo apt update
sudo apt install -y build-essential cmake git libpcap-dev libncurses-dev
git clone https://github.com/RodolfoCDSantos/modgrep.git
cd modgrep
cmake -S . -B build
cmake --build build
```

## Usage

```bash
./build/modgrep -r capture.pcap
sudo ./build/modgrep -i eth0
./build/modgrep -r capture.pcap -p 1502
./build/modgrep -r capture.pcap -f "tcp port 502 and host 192.168.88.31"
```

Options:

- `-r <file>`: analyze a PCAP file.
- `-i <interface>`: capture live traffic (needs root).
- `-p <port>`: MODBUS TCP server port (default 502).
- `-f <filter>`: BPF filter (default: tcp port of -p).

## Keys

- Up/Down or j/k: move selection.
- Enter: open the ladder diagram (conversation list) or toggle raw hex (diagram).
- PgUp/PgDn: scroll faster in the diagram.
- q or Esc: go back / quit.

## Limitations

IPv4 only. MODBUS frames split across several TCP segments are not reassembled yet.

## License

MIT. See [LICENSE](LICENSE).
