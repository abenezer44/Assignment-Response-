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
	Make sure you have a PCAP file containing SMBv2 packets for examination.
	Enter the path to your PCAP file and the desired output JSON file name in the file_path and output_file variables of the script.
	Launch the script.


