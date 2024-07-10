import json
import argparse
import os
from scapy.all import rdpcap, TCP, IP
from impacket.smb3structs import *
from impacket.smb3 import SMB3

def extract_smb_write(smb_packet):
    if smb_packet['Command'] == SMB2_WRITE:
        return {
            'type': 'write',
            'session_id': smb_packet['SessionID'],
            'file_id': smb_packet['FileID'],
            'offset': smb_packet['Offset'],
            'length': smb_packet['Length'],
            'data': smb_packet['Buffer']
        }
    return None

def extract_smb_write_response(smb_packet):
    if smb_packet['Command'] == SMB2_WRITE_RESPONSE:
        return {
            'type': 'write_response',
            'session_id': smb_packet['SessionID'],
            'file_id': smb_packet['FileID'],
            'written_length': smb_packet['DataRemaining']
        }
    return None

def extract_smb_read(smb_packet):
    if smb_packet['Command'] == SMB2_READ:
        return {
            'type': 'read',
            'session_id': smb_packet['SessionID'],
            'file_id': smb_packet['FileID'],
            'offset': smb_packet['Offset'],
            'length': smb_packet['Length']
        }
    return None

def extract_smb_read_response(smb_packet):
    if smb_packet['Command'] == SMB2_READ_RESPONSE:
        return {
            'type': 'read_response',
            'session_id': smb_packet['SessionID'],
            'file_id': smb_packet['FileID'],
            'data': smb_packet['Buffer']
        }
    return None

def parse_smb_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 445:
        raw_data = bytes(packet[TCP].payload)
        smb = SMB3(raw_data)
        if smb.get_command() in [SMB2_WRITE, SMB2_WRITE_RESPONSE, SMB2_READ, SMB2_READ_RESPONSE]:
            if smb.get_command() == SMB2_WRITE:
                return extract_smb_write(smb)
            elif smb.get_command() == SMB2_WRITE_RESPONSE:
                return extract_smb_write_response(smb)
            elif smb.get_command() == SMB2_READ:
                return extract_smb_read(smb)
            elif smb.get_command() == SMB2_READ_RESPONSE:
                return extract_smb_read_response(smb)
    return None

def read_pcap(file_path, output_dir):
    packets = rdpcap(file_path)
    extracted_data = []
    file_id_data_map = {}  # To store data fragments by file_id

    for packet in packets:
        data = parse_smb_packet(packet)
        if data:
            data['source_ip'] = packet[IP].src
            data['source_port'] = packet[TCP].sport
            data['destination_ip'] = packet[IP].dst
            data['destination_port'] = packet[TCP].dport
            data['timestamp'] = packet.time

            if data['type'] in ['write', 'read_response']:
                file_id = data['file_id']
                if file_id not in file_id_data_map:
                    file_id_data_map[file_id] = []
                file_id_data_map[file_id].append(data['data'])

            extracted_data.append(data)

    for file_id, data_fragments in file_id_data_map.items():
        file_data = b''.join(data_fragments)
        file_name = f'file_{file_id}.dat'
        file_path = os.path.join(output_dir, file_name)
        with open(file_path, 'wb') as f:
            f.write(file_data)

        file_metadata = {
            'file_name': file_name,
            'file_size': len(file_data),
            'source_ip': packet[IP].src,
            'source_port': packet[TCP].sport,
            'destination_ip': packet[IP].dst,
            'destination_port': packet[TCP].dport,
            'timestamp': packet.time
        }
        extracted_data.append(file_metadata)

    return extracted_data

def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Extract SMBv2 packet data and metadata from a PCAP file.")
    parser.add_argument("input_pcap", help="Path to the input PCAP file")
    parser.add_argument("output_json", help="Path to the output JSON file")
    parser.add_argument("output_dir", help="Directory to save the extracted files")
    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    extracted_data = read_pcap(args.input_pcap, args.output_dir)
    save_to_json(extracted_data, args.output_json)

    print(f"Data extracted and saved to {args.output_json}")

if __name__ == "__main__":
    main()
