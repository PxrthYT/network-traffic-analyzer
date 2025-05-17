# Network Traffic Analyzer

A Python-based network traffic analysis tool that processes PCAP files to analyze network protocols, visualize traffic patterns, and detect potential security issues.

## Features

- PCAP file analysis and processing
- Protocol distribution visualization
- ICMP packet fragmentation handling
- UDP flood detection
- Network security analysis
- Traffic pattern visualization

## Project Structure
network-traffic-analyzer/
├── pcap_analyzer.py # Main analysis script
├── generate_icmp.py # ICMP packet generation utility
├── correct_frags.pcap # Sample PCAP with correct fragments
├── fragmented_icmp.pcap # Sample PCAP with ICMP fragments
├── udp-flood.pcap # Sample PCAP for UDP flood analysis
└── .png # Generated visualization outputs

## Requirements

- Python 3.x
- Required Python packages:
  - scapy (for packet manipulation)
  - matplotlib (for visualization)
  - numpy (for data processing)

## Usage

### Running the PCAP Analyzer

```bash
python pcap_analyzer.py <input_pcap_file>
```

This will:
- Analyze the network traffic in the PCAP file
- Generate protocol distribution visualizations
- Detect potential security issues
- Create analysis reports

### Generating ICMP Packets

```bash
python generate_icmp.py
```

This utility helps in generating ICMP packets for testing and analysis purposes.

## Visualization Outputs

The analyzer generates several types of visualizations:
- Protocol distribution charts (*_protocols.png)
- Security analysis graphs (*_security.png)
- Traffic pattern plots (protocol_plot.png)

## Sample Files

The repository includes sample PCAP files for testing:
- correct_frags.pcap: Contains properly fragmented packets
- fragmented_icmp.pcap: Demonstrates ICMP fragmentation
- udp-flood.pcap: Sample file for UDP flood analysis

## Contributing

Feel free to fork this repository and submit pull requests. You can also open issues for bugs or feature requests.

## Author

[PxrthYT](https://github.com/PxrthYT)
