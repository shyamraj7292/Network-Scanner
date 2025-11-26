# Network Scanner

A Python-based network scanner that detects active devices in a given IP range using ARP requests, multi-threading, and socket programming.

## Project Overview

Network scanning is essential for cybersecurity professionals to monitor active devices in a network. This project builds a network scanner using Python's Scapy library to send ARP requests and retrieve IP addresses, MAC addresses, and hostnames of connected devices. The tool supports multi-threading to speed up scanning in large networks.

## Features

- ✅ **CIDR-based Network Scanning**: Accepts network addresses in CIDR notation (e.g., 192.168.1.0/24)
- ✅ **ARP Request Scanning**: Uses ARP (Address Resolution Protocol) to discover active devices
- ✅ **MAC Address Retrieval**: Collects MAC addresses of active devices
- ✅ **Hostname Resolution**: Attempts reverse DNS lookup to get device hostnames
- ✅ **Multi-threading**: Parallel scanning using multiple threads for faster results
- ✅ **Thread-safe Operations**: Uses Python's Queue module for safe concurrent access
- ✅ **Tabular Results Display**: Shows discovered devices in a formatted table

## How It Works

1. **User Input**: The user provides a CIDR-based network address (e.g., 192.168.1.0/24)
2. **IP Address Extraction**: The script extracts all valid host IPs from the provided subnet
3. **ARP Request**: Each IP address is scanned using an ARP (Address Resolution Protocol) request
4. **MAC Address Retrieval**: If the device is active, its MAC address is collected
5. **Hostname Resolution**: The scanner attempts to fetch the hostname using reverse DNS lookup
6. **Multi-threading**: The script uses multiple threads to scan multiple devices in parallel
7. **Results Display**: The discovered devices are displayed in a tabular format with their IP address, MAC address, and hostname

## Key Concepts Covered

- **Networking Basics**: Understanding ARP and network scanning
- **Python Networking**: Using Scapy for network communication
- **Multi-threading**: Implementing parallel execution to speed up scanning
- **Socket Programming**: Resolving hostnames from IP addresses
- **Queue Management**: Using Python's Queue module for thread-safe result storage

## Installation

### Prerequisites

- Python 3.6 or higher
- Administrator/root privileges (required to send ARP packets)

### Setup

1. Clone or download this repository

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:
   ```bash
   pip install scapy tabulate
   ```

## Usage

### Basic Usage

Run the scanner script:

```bash
python network_scanner.py
```

The script will prompt you for:
- Network address in CIDR notation (e.g., `192.168.1.0/24`)
- Timeout in seconds (default: 2)
- Number of threads (default: 50)

### Example

```
Enter network address in CIDR notation (e.g., 192.168.1.0/24): 192.168.1.0/24
Enter timeout in seconds (default: 2): 2
Enter number of threads (default: 50): 50
```

### Output Example

```
================================================================================
SCAN RESULTS
================================================================================
+-----------------+-------------------+------------------+
| IP Address      | MAC Address       | Hostname         |
+=================+===================+==================+
| 192.168.1.1     | aa:bb:cc:dd:ee:ff | router.local     |
| 192.168.1.100   | 11:22:33:44:55:66 | laptop.local     |
| 192.168.1.101   | 77:88:99:aa:bb:cc | N/A              |
+-----------------+-------------------+------------------+

[*] Found 3 active device(s)
```

## Important Notes

### Permissions

**This tool requires administrator/root privileges** to send ARP packets. On most systems, you'll need to run the script with elevated permissions:

- **Windows**: Run PowerShell or Command Prompt as Administrator
- **Linux/Mac**: Use `sudo python network_scanner.py`

### Network Considerations

- Scanning large networks (e.g., /16 or /8) may take a significant amount of time
- Some devices may not respond to ARP requests due to firewall settings
- The scanner respects network boundaries and only scans the specified subnet

## Project Structure

```
Network-Scanner/
│
├── network_scanner.py    # Main scanner implementation
├── requirements.txt      # Python dependencies
└── README.md            # Project documentation
```

## Code Structure

### NetworkScanner Class

The main class that handles all scanning operations:

- `__init__()`: Initializes the scanner with network CIDR, timeout, and thread count
- `get_host_ips()`: Extracts all valid host IPs from the CIDR network
- `get_hostname()`: Performs reverse DNS lookup to get hostname
- `scan_ip()`: Scans a single IP address using ARP request
- `worker_thread()`: Worker thread function for parallel scanning
- `scan_network()`: Orchestrates the multi-threaded network scan
- `display_results()`: Formats and displays results in a table

## Dependencies

- **scapy**: Network packet manipulation library for ARP requests
- **tabulate**: Library for creating formatted tables
- **ipaddress**: Built-in Python library for IP address manipulation
- **socket**: Built-in Python library for hostname resolution
- **threading**: Built-in Python library for multi-threading
- **queue**: Built-in Python library for thread-safe queues

## Troubleshooting

### "Permission denied" or "Operation not permitted" errors

- Ensure you're running the script with administrator/root privileges
- On Linux/Mac, use `sudo`
- On Windows, run as Administrator

### No devices found

- Verify the network address is correct
- Check if you're on the same network segment
- Some devices may not respond to ARP requests
- Try increasing the timeout value

### Import errors

- Make sure all dependencies are installed: `pip install -r requirements.txt`
- Verify Python version is 3.6 or higher: `python --version`

## Educational Value

This project demonstrates:

1. **Network Protocol Understanding**: How ARP works at the network layer
2. **Concurrent Programming**: Multi-threading for performance optimization
3. **Network Programming**: Using libraries like Scapy for low-level network operations
4. **Error Handling**: Graceful handling of network timeouts and errors
5. **Data Structures**: Using queues for thread-safe data sharing

## License

This project is for educational purposes.

## Disclaimer

This tool is intended for educational purposes and authorized network scanning only. Always ensure you have permission to scan the network you're testing. Unauthorized network scanning may be illegal in your jurisdiction.
