from scapy.all import *
import csv

# File name of the PCAP file
pcap_file = "PCAP_General.pcap"

# Output file name
csv_file = "output.csv"

# Open the PCAP file
pkts = rdpcap(pcap_file)

# Open the CSV file for writing
with open(csv_file, 'w', newline='') as csvfile:
    # Create the CSV writer
    csvwriter = csv.writer(csvfile)
    # Write the header row
    csvwriter.writerow(['Source IP', 'Source MAC', 'Destination IP', 'Destination MAC', 'Protocol'])
    # Iterate through the packets in the PCAP file
    for pkt in pkts:
        # Extract the IP and MAC addresses, protocols
        src_ip = pkt[IP].src
        src_mac = pkt[Ether].src
        dst_ip = pkt[IP].dst
        dst_mac = pkt[Ether].dst
        protocol = pkt[IP].proto
        # Write the extracted information to the CSV file
        csvwriter.writerow([src_ip, src_mac, dst_ip, dst_mac, protocol])

print("Data is written to the csv file.")
