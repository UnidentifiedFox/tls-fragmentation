# TLS Fragmentation

TLS Fragmentation Through a SOCKS5 Proxy Server for DPI Circumvention

For a detailed explanation of the technique, read the [article](https://upb-syssec.github.io/blog/2023/record-fragmentation/) by Niklas Niere.


## How It Works

Internet Service Providers (ISPs) can restrict access by inspecting the SNI extension within TLS ClientHello packets. SNI will reveal the domain name of the destination server the client is trying to reach. If the ISP does not reassemble TCP packets, you can bypass inspection by fragmenting the ClientHello packet.

The Python script works as follows:
- A simple SOCKS5 proxy captures packets exchanged between the client and the server.
- The TLS ClientHello packet is split into two parts and transmitted separately.