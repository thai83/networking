# Local Network ARP Scanner

A low-level Linux networking project that demonstrates manual Ethernet and ARP packet construction, raw socket communication, and direct interaction with the kernel ARP table. This project is designed to show practical networking fundamentals in a Linux environment.

This scanner performs the following:
- enumerates active network interfaces
- checks the system ARP cache
- sends an ARP request to a target host
- parses the ARP reply
- inserts the discovered MAC/IP mapping into the kernel neighbor table

It is intended to showcase hands-on experience with networking fundamentals and low-level Linux system programming.

## Skills Demonstrated

- Linux raw socket programming
- Ethernet and ARP frame construction
- Layer 2 networking
- Network interface discovery and filtering
- Kernel ARP cache manipulation with `ioctl`
- WSL2 networking and debugging
- Low-level protocol analysis

## Features

- Dynamic interface discovery: scans active interfaces and ignores loopback or inactive adapters
- Low-level packet crafting: builds Ethernet and ARP frames byte-by-byte
- ARP cache inspection: checks the system ARP table before sending a request
- Kernel integration: populates discovered entries into the Linux neighbor table
- Timeout handling: gracefully handles missing or delayed replies
- WSL2 compatibility: optimized for mirrored networking mode on Windows 11

## Requirements

- Linux environment
- Root privileges or the capabilities:
  - `CAP_NET_RAW`
  - `CAP_NET_ADMIN`
- WSL2 on Windows 11 (recommended) with mirrored networking enabled

## Setup

Traditional VM networking often uses NAT, which blocks Layer 2 traffic such as ARP from reaching the physical router. To run this project on Windows 11 with WSL2, enable Mirrored Networking Mode so the Linux guest can communicate at Layer 2 with local network peers.

### 1. Enable WSL2 mirrored mode

Create or edit `.wslconfig` in your Windows user profile directory:

```ini
[wsl2]
networkingMode=mirrored
```

Then restart WSL:

```powershell
wsl --shutdown
```

### 2. Allow raw packet traffic through the Windows firewall

Run this in an elevated Windows PowerShell session:

```powershell
Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow
```

## Build

Compile the project with GCC:

```bash
gcc -O2 arp_test.c -o arp_test
```

## Grant Required Capabilities

Instead of running the binary as root, grant only the minimum privileges needed:

```bash
sudo setcap 'cap_net_raw,cap_net_admin+ep' ./arp_test
```

## Usage

Run the scanner against a live device on your local network:

```bash
./arp_test 192.168.1.254
```

Optionally, specify a network interface:

```bash
./arp_test 192.168.1.254 eth1
```

## Technical Notes

- MAC randomization detection: when testing against devices like modern iPhones, the second character of a MAC address may indicate address randomization behavior.
- ARP cache inspection: you can inspect the current kernel neighbor table with:

```bash
cat /proc/net/arp
```

- To force a fresh ARP lookup for a target, remove its entry from the cache:

```bash
sudo ip neigh del <TARGET_IP> dev <INTERFACE_NAME>
```

## Why This Project Matters

This project reflects practical experience with low-level networking concepts and demonstrates the ability to work directly with protocol headers, interface discovery, and kernel networking internals.

## License

This project is provided for educational and research purposes only.
