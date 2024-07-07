Overview of the SMBv2 Packet Extractor

A Python script called the SMBv2 Packet Extractor is made to read a PCAP file, parse SMBv2 packets, extract file data and metadata, and store the information that is retrieved into a JSON file. Without the requirement for Wireshark, this script is helpful for studying network traffic, particularly SMBv2 write and read requests and responses.



Features
Parse SMBv2 write and read requests and responses from PCAP files.
Extract metadata including:
   File name
   File size
   Source IP address
   Source port number
   Destination IP address
   Destination port number
   Timestamp
   Save extracted data to a JSON file.

Prerequisites
	Python 3.x
	scapy library
	impacket library

Installation
	Install Python 3.x from the official Python website.
	Install the required libraries using pip(pip install scapy impacket)
Usage
Clone or download the repository containing the script.
Ensure you have a PCAP file with SMBv2 packets to analyze.
Run the script from the command line with the input PCAP file and output JSON file as arguments:
 example:  
Suppose you have a PCAP file named smb.pcap in the directory C:\Users\YourName\Documents
cd C:\Users\YourName\Documents\python assignment.py smb.pcap "extracted data.json"


