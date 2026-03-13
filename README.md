File Integrity Monitoring System (Python)

A lightweight File Integrity Monitoring (FIM) tool written in Python that detects file changes, suspicious files, and potential security risks in monitored directories.

This project monitors files and folders by calculating SHA-256 hashes and comparing them against a stored baseline. It supports real-time monitoring, scheduled integrity checks, and basic suspicious file detection based on file extensions and naming patterns.

The tool can be used as a basic host-based intrusion detection component for detecting unauthorized file modifications.

Features
File Integrity Monitoring

Calculates SHA-256 hashes for files

Stores a baseline in a JSON file

Detects:

file modifications

file deletions

newly created files

Real-Time Monitoring

Uses the watchdog library to monitor filesystem events instantly:

file creation

file modification

file deletion

file movement

Scheduled Monitoring

Performs automated integrity checks at user-defined time intervals.

Suspicious File Detection

Flags potentially suspicious files based on heuristics such as:

suspicious extensions (.exe, .bat, .ps1, .dll, etc.)

double file extensions (invoice.pdf.exe)

suspicious filename patterns

unusually large executable/script files

File Metadata Analysis

The system stores additional file metadata including:

file size

file extension

SHA-256 hash

File Type Categorization

Files can be classified into categories such as:

documents

images

source code

archives

executables

Logging System

All detected events are recorded in a log file (integrity.log) with timestamps.

Desktop Notifications

Alerts are displayed using system notifications when suspicious or unexpected changes occur.

Technologies Used

Python 3

hashlib for cryptographic hashing

watchdog for real-time filesystem monitoring

plyer for desktop notifications

logging for event logging

pathlib for filesystem management

Installation

Clone the repository:

git clone https://github.com/yourusername/file-integrity-monitor.git
cd file-integrity-monitor

Install dependencies:

pip install watchdog plyer
Usage

Run the program:

python file_integrity_monitor.py

You will be prompted to select one of the following options:

1. Create baseline
2. Check integrity
3. Automatic monitoring every X minutes
4. Real-time monitoring
Example Output
[INFO] Real-time monitoring started for folder: monitored_directory

[NEW FILES]
 - invoice.pdf.exe (.exe)
   [ALERT] Suspicious file detected: suspicious extension, double extension detected

[CHANGED FILES]
 - config.json (.json) -> content modified
Project Structure
file-integrity-monitor/
│
├── file_integrity_monitor.py
├── file_hashes.json
├── integrity.log
└── README.md
Security Use Cases

This project can help detect:

unauthorized file changes

potential malware drops

suspicious executable files

tampering with configuration files

unexpected new files appearing in monitored directories

Limitations

This tool uses heuristic detection and hash comparison.
It does not perform deep malware analysis or antivirus scanning.

Suspicious file detection is based on patterns and should not be treated as definitive malware identification.
