# File Integrity Monitoring System (Python)

A lightweight **File Integrity Monitoring (FIM)** tool written in **Python** that detects file changes and potential security risks in monitored directories.

This project monitors files and folders by calculating **SHA-256 hashes** and comparing them against a stored baseline. It supports **real-time monitoring**, **scheduled integrity checks**, and **basic suspicious file detection** based on file extensions and naming patterns.

The tool can be used as a **basic host-based intrusion detection component** to detect unauthorized file modifications.

## Features

### File Integrity Monitoring

- Calculates **SHA-256 hashes** for files
- Stores a **baseline in a JSON file**
- Detects:
  - file modifications
  - file deletions
  - newly created files
