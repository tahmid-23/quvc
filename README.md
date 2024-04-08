# QUVC: QUIC UDP VPN Connections
QUVC is an async, general-purpose VPN written in Rust that uses QUIC as a transport. Currently only supports Linux.

## Compiling
Compile the client with `cargo build --package quvc-client --release`.

Compile the server with `cargo build --package quvc-server --release`.

## Setup
1. First, you must generate self-signed X509 certificates. [rcgen](https://github.com/rustls/rcgen) is a reasonable way to do this.

   By default, the server name is `quvc`.

   Generate `cert.der` and `key.der`. Place both `cert.der` and `key.der` in the working directory of the VPN server, and place `cert.der` in the working directory of the VPN client.

2. Then, set up TUN interfaces on the client and the server. These should be part of the same private network.

   For example, on the client:
   ```
   ip tuntap add quvc mode tun
   ip address add 10.69.42.1/24 dev quvc
   ```

   On the server:
   ```
   ip tuntap add quvc mode tun
   ip address add 10.69.42.2/24 dev quvc
   ```

3. Configure the VPN server host to proxy traffic.

   First, make sure that IPv4 forwarding is enabled:
   ```
   sysctl net.ipv4.ip_forward=1
   ```

   Then, enable IP masquerade on the NAT table (replacing `<INTERFACE>` with the name of the desired outbound interface):
   ```
   iptables -t nat -A POSTROUTING -s 10.69.42.0/24 -o <INTERFACE> -j MASQUERADE
   ```

   If you want to redirect DNS (you probably do), run the following:
   ```
   iptables -t nat -A PREROUTING -s 10.69.42.0/24 -p udp --dport 53 -j DNAT --to 1.1.1.1:53
   iptables -t nat -A PREROUTING -s 10.69.42.0/24 -p tcp --dport 53 -j DNAT --to 1.1.1.1:53
   ```

4. Run the VPN server and client. Check usage on each of the binaries for more information.

6. Set up routing on the client to go through the TUN device.

   If you want to route ALL traffic through the VPN, you may do so as follows:
   ```
   ip route add default dev quvc
   ```

   Undo the routing when you are finished.
   ```
   ip route del default dev quvc
   ```
