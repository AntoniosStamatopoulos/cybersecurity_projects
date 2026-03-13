# File Integrity Monitoring System (Python)

A lightweight **File Integrity Monitoring (FIM)** tool written in **Python** that detects file changes and potential security risks in monitored directories.

The system monitors files and folders by calculating **SHA-256 hashes** and comparing them against a stored **baseline**. It supports **real-time monitoring**, **scheduled integrity checks**, and **basic suspicious file detection** based on file extensions and filename patterns.

The tool can be used as a basic **host-based intrusion detection component** to detect unauthorized file modifications.

---

# Features

## File Integrity Monitoring

- Calculates **SHA-256 hashes** for files
- Stores a **baseline in a JSON file**
- Detects:
  - file modifications
  - file deletions
  - newly created files

---

## Real-Time Monitoring

Uses the **watchdog library** to monitor filesystem events instantly.

- Detects **file creation**
- Detects **file modification**
- Detects **file deletion**
- Detects **file movement**

---

## Scheduled Monitoring

Performs automated integrity checks at **user-defined time intervals**.

- Allows **periodic verification of file integrity**
- Useful when **real-time monitoring is not required**
- Helps detect **delayed or unnoticed file changes**

---

## Suspicious File Detection

Detects potentially suspicious files using **heuristic analysis**.

- Flags files with **suspicious extensions**
  - `.exe`
  - `.bat`
  - `.ps1`
  - `.dll`
  - `.js`

- Detects **double file extensions**
  - example: `invoice.pdf.exe`

- Identifies **suspicious filename patterns**

- Detects **unusually large executable/script files**

---

## File Metadata Analysis

The system stores additional metadata for each file including:

- **file size**
- **file extension**
- **SHA-256 hash**

This allows detection of:

- **content changes**
- **size changes**
- **file replacements**

---

## File Type Categorization

Files can be categorized based on their extension.

Examples include:

- **documents**
  - `.txt`
  - `.pdf`
  - `.doc`
  - `.docx`

- **images**
  - `.jpg`
  - `.png`
  - `.gif`

- **source code**
  - `.py`
  - `.js`
  - `.java`

- **archives**
  - `.zip`
  - `.rar`

- **executables**
  - `.exe`
  - `.bat`

---

## Logging System

All detected events are recorded in the log file:



Each event contains:

- **timestamp**
- **event type**
- **affected file**

This makes the tool useful for **security auditing and incident investigation**.

---

## Desktop Notifications

The system displays **desktop alerts** when important events occur.

Examples include:

- suspicious files detected
- unauthorized file changes
- unexpected new files

These notifications allow administrators to **react quickly to potential threats**.

---

# Technologies Used

The project is built using the following Python libraries:

- **Python 3**
- **hashlib** – cryptographic hashing
- **watchdog** – real-time filesystem monitoring
- **plyer** – desktop notifications
- **logging** – event logging
- **pathlib** – filesystem path handling
- **json** – baseline storage

---

Install dependencies:

pip install watchdog plyer
Usage

Run the program:

python file_integrity_monitor.py

You will be prompted to select an option:

- **Create baseline**
- **Check integrity**
- **Automatic monitoring every X minutes**
- **Real-time monitoring**

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
This tool can help detect:

- unauthorized file changes
- potential malware drops
- suspicious executable files
- configuration tampering

unexpected files appearing in monitored directories

**Limitations**

This tool uses hash comparison and heuristic detection.

It does not perform deep malware analysis or antivirus scanning, therefore suspicious file detection should be treated as indicative rather than definitive.



