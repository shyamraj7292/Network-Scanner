#!/usr/bin/env python3
"""
Network Scanner - A Python-based tool to detect active devices in a network
Uses ARP requests, multi-threading, and socket programming for network discovery.
"""

import ipaddress
import socket
import threading
import queue
import time
from scapy.all import ARP, Ether, srp
from tabulate import tabulate
import sys


class NetworkScanner:
    """Network scanner class that uses ARP requests to discover active devices."""
    
    def __init__(self, network_cidr, timeout=2, max_threads=50):
        """
        Initialize the network scanner.
        
        Args:
            network_cidr (str): Network address in CIDR notation (e.g., '192.168.1.0/24')
            timeout (int): Timeout for ARP requests in seconds (default: 2)
            max_threads (int): Maximum number of threads for parallel scanning (default: 50)
        """
        self.network_cidr = network_cidr
        self.timeout = timeout
        self.max_threads = max_threads
        self.results_queue = queue.Queue()
        self.active_devices = []
        
    def get_host_ips(self):
        """
        Extract all valid host IP addresses from the CIDR network.
        
        Returns:
            list: List of IP address strings (excluding network and broadcast addresses)
        """
        try:
            network = ipaddress.ip_network(self.network_cidr, strict=False)
            # Exclude network and broadcast addresses
            host_ips = [str(ip) for ip in network.hosts()]
            return host_ips
        except ValueError as e:
            print(f"Error: Invalid network address format. {e}")
            sys.exit(1)
    
    def get_hostname(self, ip_address):
        """
        Attempt to resolve hostname from IP address using reverse DNS lookup.
        
        Args:
            ip_address (str): IP address to resolve
            
        Returns:
            str: Hostname if found, 'N/A' otherwise
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return 'N/A'
    
    def scan_ip(self, ip_address):
        """
        Scan a single IP address using ARP request.
        
        Args:
            ip_address (str): IP address to scan
            
        Returns:
            tuple: (ip_address, mac_address, hostname) if device is active, None otherwise
        """
        try:
            # Create ARP request packet
            arp_request = ARP(pdst=ip_address)
            # Create Ethernet frame with broadcast MAC
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            # Combine Ethernet and ARP
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive response (timeout in seconds)
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]
            
            if answered_list:
                # Extract MAC address from response
                mac_address = answered_list[0][1].hwsrc
                # Attempt hostname resolution
                hostname = self.get_hostname(ip_address)
                return (ip_address, mac_address, hostname)
            return None
        except Exception as e:
            print(f"Error scanning {ip_address}: {e}")
            return None
    
    def worker_thread(self, ip_queue):
        """
        Worker thread function that processes IP addresses from the queue.
        
        Args:
            ip_queue (queue.Queue): Queue containing IP addresses to scan
        """
        while True:
            try:
                ip_address = ip_queue.get(timeout=1)
                result = self.scan_ip(ip_address)
                if result:
                    self.results_queue.put(result)
                ip_queue.task_done()
            except queue.Empty:
                break
    
    def scan_network(self):
        """
        Scan the entire network using multi-threading.
        
        Returns:
            list: List of tuples containing (IP, MAC, Hostname) for active devices
        """
        print(f"\n[*] Scanning network: {self.network_cidr}")
        print(f"[*] Starting scan with {self.max_threads} threads...")
        print(f"[*] This may take a while depending on network size...\n")
        
        # Get all host IPs from the network
        host_ips = self.get_host_ips()
        total_ips = len(host_ips)
        print(f"[*] Found {total_ips} IP addresses to scan\n")
        
        # Create queue and add all IPs
        ip_queue = queue.Queue()
        for ip in host_ips:
            ip_queue.put(ip)
        
        # Start worker threads
        threads = []
        for _ in range(min(self.max_threads, total_ips)):
            thread = threading.Thread(target=self.worker_thread, args=(ip_queue,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect results from queue
        active_devices = []
        while not self.results_queue.empty():
            active_devices.append(self.results_queue.get())
        
        return active_devices
    
    def display_results(self, devices):
        """
        Display scan results in a tabular format.
        
        Args:
            devices (list): List of tuples containing device information
        """
        if not devices:
            print("\n[!] No active devices found on the network.")
            return
        
        # Sort devices by IP address
        devices.sort(key=lambda x: ipaddress.IPv4Address(x[0]))
        
        # Prepare table data
        table_data = []
        for ip, mac, hostname in devices:
            table_data.append([ip, mac, hostname])
        
        # Display table
        headers = ["IP Address", "MAC Address", "Hostname"]
        print("\n" + "="*80)
        print("SCAN RESULTS")
        print("="*80)
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\n[*] Found {len(devices)} active device(s)\n")


def main():
    """Main function to run the network scanner."""
    print("="*80)
    print("NETWORK SCANNER")
    print("="*80)
    print("\nThis tool scans a network to discover active devices using ARP requests.")
    print("Note: This tool requires administrator/root privileges to send ARP packets.\n")
    
    # Get network input from user
    while True:
        network_input = input("Enter network address in CIDR notation (e.g., 192.168.1.0/24): ").strip()
        if network_input:
            break
        print("[!] Please enter a valid network address.")
    
    # Optional: Get timeout and thread count
    try:
        timeout_input = input("Enter timeout in seconds (default: 2): ").strip()
        timeout = int(timeout_input) if timeout_input else 2
    except ValueError:
        timeout = 2
        print("[!] Invalid timeout, using default: 2 seconds")
    
    try:
        threads_input = input("Enter number of threads (default: 50): ").strip()
        max_threads = int(threads_input) if threads_input else 50
    except ValueError:
        max_threads = 50
        print("[!] Invalid thread count, using default: 50")
    
    # Create scanner instance
    scanner = NetworkScanner(network_input, timeout=timeout, max_threads=max_threads)
    
    # Record start time
    start_time = time.time()
    
    # Perform network scan
    try:
        active_devices = scanner.scan_network()
        
        # Record end time
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Display results
        scanner.display_results(active_devices)
        
        print(f"[*] Scan completed in {scan_duration:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

