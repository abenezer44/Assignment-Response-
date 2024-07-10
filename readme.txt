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

Steps to Run the Script
stwp 1: Open the Command Line Interface (CLI)
step 2:Navigate to the Directory Containing the Script
	cd path/to/your/script
step 3: Run the Script with Command Line Arguments
Run the script from the command line with the input PCAP file, output JSON file, and output directory as arguments:
	python smb_extractor.py "path to the pcap file/smb.pcap" "extracted_data.json" output_dir
If the file is saved in C:/Users/abenezer/Documents on a Windows OS the command will be   
	python smb_extractor.py "C:/Users/YourName/Documents/smb.pcap" "extracted_data.json" output_dir




