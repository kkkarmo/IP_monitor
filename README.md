# IP Address Reputation Checker

This Python script monitors a list of IP addresses and checks their reputation using the VirusTotal API. It's designed to run continuously, watching for changes in the IP list and performing checks at regular intervals.

## Features

- Monitors a file (`Public_IPs.txt`) for changes in IP addresses
- Checks IP reputation using VirusTotal API
- Avoids redundant checks by tracking previously checked IPs
- Implements rate limiting to comply with API usage restrictions
- Logs results and errors for easy monitoring
- Can be run as a Docker container for easy deployment

## Prerequisites

- Python 3.11+
- Docker (optional, for containerized deployment)
- VirusTotal API key

## Installation

1. Clone this repository:
2. Install required Python packages:
3. Create a file named `api_key.txt` in the project root and add your VirusTotal API key to it.

## Usage

### Running Locally

1. Ensure your list of IP addresses is in a file named `Public_IPs.txt` in the project root.
2. Run the script:
### Running with Docker
1. Build the Docker image:
2. Run the Docker container:
docker run --rm -v /path/to/your/api_key.txt:/app/config/api_key.txt -v /path/to/your/Public_IPs.txt:/app/Public_IPs.txt ip-monitor
Replace `/path/to/your/api_key.txt` and `/path/to/your/Public_IPs.txt` with the actual paths on your system.

## Example Use Case

Imagine you're a network administrator for a medium-sized company. You want to continuously monitor the reputation of IP addresses that are interacting with your network. This could include:

- IP addresses of your servers
- IP addresses of your clients' servers
- IP addresses that frequently appear in your firewall logs

1. Create a `Public_IPs.txt` file with the IP addresses you want to monitor:
203.0.113.1
198.51.100.2
192.0.2.3
2. Run the script as described in the Usage section.
3. The script will start monitoring these IPs and check their reputation. If any changes occur (e.g., an IP is flagged as malicious), it will be logged.
4. You can set up alerts based on the log file or the `vt_results.txt` file to be notified of any concerning changes in IP reputation.
5. If you need to add or remove IPs from monitoring, simply edit the `Public_IPs.txt` file. The script will detect the changes and adjust its monitoring accordingly.
This setup allows you to have a constant, automated watch on the reputation of important IP addresses, helping you to quickly identify and respond to potential security threats.
## Output

The script generates two main output files:

1. `debug.log`: Contains detailed logs of the script's operation.
2. `vt_results.txt`: Contains the latest reputation check results for each IP.

A typical result in `vt_results.txt` looks like this:
IP: 203.0.113.1, Malicious: 0, Suspicious: 0
IP: 198.51.100.2, Malicious: 1, Suspicious: 0
IP: 192.0.2.3, Malicious: 0, Suspicious: 1

This indicates that 198.51.100.2 has been flagged as malicious by one security vendor, and 192.0.2.3 has been flagged as suspicious by one vendor.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
