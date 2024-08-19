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
