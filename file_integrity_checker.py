import os
import json
import hashlib
from pathlib import Path
import time
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification

HASH_FILE = "file_hashes.json"
CHUNK_SIZE = 4096
LOG_FILE = "integrity.log"
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".msi", ".dll", ".jar"
}

def detect_suspicious_file(file_path, file_info):
    """
    Returns a list of reasons why a file may be suspicious.
    """
    reasons = []

    extension = file_info.get("extension", "").lower()
    filename = Path(file_path).name.lower()

    if extension in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"suspicious extension: {extension}")

    # Double extension, e.g. invoice.pdf.exe
    parts = filename.split(".")
    if len(parts) >= 3:
        reasons.append("double extension detected")

    # Very large executable/script file
    if extension in SUSPICIOUS_EXTENSIONS and file_info.get("size", 0) > 10 * 1024 * 1024:
        reasons.append("large executable/script file")

    # Misleading names often used in phishing/dropper files
    suspicious_keywords = ["invoice", "payment", "document", "scan", "urgent", "resume"]
    if any(word in filename for word in suspicious_keywords) and extension in SUSPICIOUS_EXTENSIONS:
        reasons.append("suspicious filename pattern")

    return reasons

class IntegrityEventHandler(FileSystemEventHandler):
    def __init__(self, folder_path, ignored_folders=None):
        super().__init__()
        self.folder_path = folder_path
        self.ignored_folders = ignored_folders or []
        self.current_hashes = load_hashes()

    def _is_ignored(self, path):
        path_obj = Path(path)
        return any(ignored in path_obj.parts for ignored in self.ignored_folders)

    def _run_check(self):
        new_hashes = scan_folder(self.folder_path, self.ignored_folders)
        changed_files, deleted_files, new_files = compare_file_states(self.current_hashes, new_hashes)

        if not changed_files and not deleted_files and not new_files:
            return

        print("\n--- REAL-TIME ALERT ---")

        alert_messages = []

        if changed_files:
            print("\n[CHANGED FILES]")
            for file in changed_files:
                print(f" - {file['path']} ({file['extension']}) -> {file['change_type']}")
                logging.warning(
                    f"Changed file detected: {file['path']} | "
                    f"type: {file['extension']} | "
                    f"change: {file['change_type']}"
                )

        if deleted_files:
            print("\n[DELETED FILES]")
            for file in deleted_files:
                print(f" - {file['path']} ({file['extension']})")
                logging.warning(
                    f"Deleted file detected: {file['path']} | type: {file['extension']}"
                )

        if new_files:
            print("\n[NEW FILES]")
            for file in new_files:
                print(f" - {file['path']} ({file['extension']})")

                if file.get("suspicious"):
                    print(f"   [ALERT] Suspicious file detected: {', '.join(file['suspicious_reasons'])}")
                    logging.warning(
                        f"Suspicious new file detected: {file['path']} | "
                        f"type: {file['extension']} | "
                        f"reasons: {', '.join(file['suspicious_reasons'])}"
                    )
                else:
                    logging.warning(
                        f"New file detected: {file['path']} | type: {file['extension']}"
                    )

        alert_text = " | ".join(alert_messages)
        send_desktop_alert("Integrity Alert", alert_text)

        save_hashes(new_hashes)
        self.current_hashes = new_hashes

    def on_modified(self, event):
        if not event.is_directory and not self._is_ignored(event.src_path):
            self._run_check()

    def on_created(self, event):
        if not event.is_directory and not self._is_ignored(event.src_path):
            self._run_check()

    def on_deleted(self, event):
        if not event.is_directory and not self._is_ignored(event.src_path):
            self._run_check()

    def on_moved(self, event):
        if not event.is_directory and not self._is_ignored(event.src_path):
            self._run_check()


def get_file_category(extension):
    categories = {
        "document": [".txt", ".pdf", ".doc", ".docx"],
        "image": [".jpg", ".jpeg", ".png", ".gif"],
        "code": [".py", ".js", ".java", ".cpp", ".c"],
        "archive": [".zip", ".rar", ".7z"],
        "executable": [".exe", ".msi", ".bat"]
    }

    for category, extensions in categories.items():
        if extension in extensions:
            return category

    return "other"

def setup_logging():
    """
    Configures logging so that events are stored
    in a file with timestamps.
    """
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def calculate_file_hash(file_path):
    """
    Calculates the SHA-256 hash of a file.
    Reads the file in chunks so it also works with large files.
    """
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Could not read file: {file_path}")
        print(f"Details: {e}")
        return None


def scheduled_monitoring(folder_path, interval_minutes, ignored_folders=None):
    """
    Performs automatic integrity checks every X minutes
    and records the results in a log file.
    """
    if ignored_folders is None:
        ignored_folders = []

    old_hashes = load_hashes()

    if not old_hashes:
        print("[WARNING] No baseline found. Create it first.")
        logging.warning("Monitoring aborted: baseline file not found.")
        return

    interval_seconds = interval_minutes * 60

    print(f"\n[INFO] Monitoring started for folder: {folder_path}")
    print(f"[INFO] Check interval: every {interval_minutes} minute(s).")
    print("[INFO] Press Ctrl+C to stop.\n")

    logging.info(f"Monitoring started for folder: {folder_path}")
    logging.info(f"Check interval set to {interval_minutes} minute(s)")

    try:
        while True:
            print("[INFO] Running new integrity check...")
            logging.info("New integrity check started")

            new_hashes = scan_folder(folder_path, ignored_folders)
            changed_files, deleted_files, new_files = compare_file_states(old_hashes, new_hashes)

            print("\n--- CHECK RESULTS ---")

            if not changed_files and not deleted_files and not new_files:
                print("[OK] No changes detected.")
                logging.info("No changes detected")
            else:
                if changed_files:
                    print("\n[CHANGED FILES]")
                    for file in changed_files:
                        print(f" - {file['path']} ({file['extension']}) -> {file['change_type']}")
                        logging.warning(
                            f"Changed file detected: {file['path']} | "
                            f"type: {file['extension']} | "
                            f"change: {file['change_type']}"
                        )

                if deleted_files:
                    print("\n[DELETED FILES]")
                    for file in deleted_files:
                        print(f" - {file['path']} ({file['extension']})")
                        logging.warning(
                            f"Deleted file detected: {file['path']} | type: {file['extension']}"
                        )

                if new_files:
                    print("\n[NEW FILES]")
                    for file in new_files:
                        print(f" - {file['path']} ({file['extension']})")

                        if file.get("suspicious"):
                            print(f"   [ALERT] Suspicious file detected: {', '.join(file['suspicious_reasons'])}")
                            logging.warning(
                                f"Suspicious new file detected: {file['path']} | "
                                f"type: {file['extension']} | "
                                f"reasons: {', '.join(file['suspicious_reasons'])}"
                            )
                        else:
                            logging.warning(
                                f"New file detected: {file['path']} | type: {file['extension']}"
                            )

                save_hashes(new_hashes)
                old_hashes = new_hashes
                logging.info("Baseline updated after detected changes")

            print(f"\n[INFO] Waiting {interval_minutes} minute(s) for the next check...\n")
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")
        logging.info("Monitoring stopped by user")


def scan_folder(folder_path, ignored_folders=None):
    """
    Recursively scans all files in a folder,
    ignoring those located in specific subfolders.
    """
    if ignored_folders is None:
        ignored_folders = []

    folder = Path(folder_path)
    file_hashes = {}

    if not folder.exists() or not folder.is_dir():
        print(f"[ERROR] Folder does not exist: {folder_path}")
        return file_hashes

    for file_path in folder.rglob("*"):
        if file_path.is_file():
            if any(ignored in file_path.parts for ignored in ignored_folders):
                continue

            if file_path.name == HASH_FILE:
                continue

            relative_path = str(file_path.relative_to(folder))
            file_hash = calculate_file_hash(file_path)

            if file_hash is not None:
                file_hashes[relative_path] = {
                    "hash": file_hash,
                    "size": file_path.stat().st_size,
                    "extension": file_path.suffix.lower() if file_path.suffix else "[no extension]"
                }

    return file_hashes

def get_ignored_folders():
    """
    Asks the user which folders should be ignored.
    """
    answer = input("Do you want to ignore specific subfolders? (y/n): ").lower()

    if answer != "y":
        return []

    folders = input("Enter folder names separated by commas: ")
    ignored = [f.strip() for f in folders.split(",") if f.strip()]

    print(f"[INFO] Ignored folders: {ignored}")
    return ignored


def real_time_monitoring(folder_path, ignored_folders=None):
    """
    Monitors the folder and its subfolders in real time.
    """
    if ignored_folders is None:
        ignored_folders = []

    current_hashes = scan_folder(folder_path, ignored_folders)
    save_hashes(current_hashes)

    event_handler = IntegrityEventHandler(folder_path, ignored_folders)
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=True)

    print(f"\n[INFO] Real-time monitoring started for folder: {folder_path}")
    print("[INFO] Press Ctrl+C to stop.\n")

    logging.info(f"Real-time monitoring started for folder: {folder_path}")

    observer.start()

    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")
        observer.stop()
        logging.info("Real-time monitoring stopped by user")

    observer.join()


def save_hashes(hashes, hash_file=HASH_FILE):
    """
    Saves hashes to a JSON file.
    """
    try:
        with open(hash_file, "w", encoding="utf-8") as f:
            json.dump(hashes, f, indent=4, ensure_ascii=False)
        print(f"[OK] Hashes were saved to '{hash_file}'")
    except Exception as e:
        print(f"[ERROR] Failed to save hashes: {e}")


def load_hashes(hash_file=HASH_FILE):
    """
    Loads hashes from a JSON file.
    """
    if not os.path.exists(hash_file):
        print(f"[WARNING] File '{hash_file}' was not found")
        return {}

    try:
        with open(hash_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load hashes: {e}")
        return {}


def compare_file_states(old_data, new_data):
    """
    Compares old and new file states and returns detailed results.
    """
    changed_files = []
    deleted_files = []
    new_files = []

    old_files = set(old_data.keys())
    new_files_set = set(new_data.keys())

    for file_path in old_files - new_files_set:
        deleted_files.append({
            "path": file_path,
            "extension": old_data[file_path]["extension"]
        })

    for file_path in new_files_set - old_files:
        file_info = new_hashes[file_path]
        suspicious_reasons = detect_suspicious_file(file_path, file_info)

        new_files.append({
            "path": file_path,
            "extension": file_info["extension"],
            "size": file_info["size"],
            "suspicious": len(suspicious_reasons) > 0,
            "suspicious_reasons": suspicious_reasons
        })

    for file_path in old_files & new_files_set:
        old_entry = old_data[file_path]
        new_entry = new_data[file_path]

        if old_entry["hash"] != new_entry["hash"]:
            change_type = "content modified"

            if old_entry["size"] != new_entry["size"]:
                change_type = "content and size modified"

            changed_files.append({
                "path": file_path,
                "extension": new_entry["extension"],
                "change_type": change_type,
                "old_size": old_entry["size"],
                "new_size": new_entry["size"]
            })

    return changed_files, deleted_files, new_files


def create_baseline(folder_path):
    """
    Creates the initial hash baseline.
    """
    print(f"\n[INFO] Creating baseline for folder: {folder_path}")
    hashes = scan_folder(folder_path)
    save_hashes(hashes)
    print(f"[OK] Baseline created for {len(hashes)} file(s).\n")


def check_integrity(folder_path):
    """
    Checks file integrity by comparing
    the current state with the baseline.
    """
    print(f"\n[INFO] Checking integrity for folder: {folder_path}")

    old_hashes = load_hashes()
    if not old_hashes:
        print("[WARNING] No baseline found. Create it first.")
        return

    new_hashes = scan_folder(folder_path)
    changed_files, deleted_files, new_files = compare_file_states(old_hashes, new_hashes)

    print("\n--- CHECK RESULTS ---")

    if not changed_files and not deleted_files and not new_files:
        print("[OK] No changes detected.")
        return

    if changed_files:
        print("\n[CHANGED FILES]")
        for file in changed_files:
            print(f" - {file['path']} ({file['extension']}) -> {file['change_type']}")

    if deleted_files:
        print("\n[DELETED FILES]")
        for file in deleted_files:
            print(f" - {file['path']} ({file['extension']})")

    if new_files:
        print("\n[NEW FILES]")
        for file in new_files:
            print(f" - {file['path']} ({file['extension']})")

    print()


def send_desktop_alert(title, message):
    """
    Displays a desktop notification.
    """
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="File Integrity Monitor",
            timeout=5
        )
    except Exception as e:
        logging.error(f"Desktop notification failed: {e}")


def main():
    setup_logging()

    print("=== File Integrity Checker ===")
    folder_path = input("Enter the folder path to monitor: ").strip()

    if not folder_path:
        print("[ERROR] No folder path was provided.")
        return

    print("\nSelect an option:")
    print("1. Create baseline")
    print("2. Check integrity")
    print("3. Automatic monitoring every X minutes")
    print("4. Real-time monitoring")

    choice = input("Choice (1/2/3/4): ").strip()

    if choice == "1":
        ignored_folders = get_ignored_folders()
        hashes = scan_folder(folder_path, ignored_folders)
        save_hashes(hashes)
        print(f"[OK] Baseline created for {len(hashes)} file(s).")

    elif choice == "2":
        check_integrity(folder_path)

    elif choice == "3":
        interval_input = input("How many minutes between checks? ").strip()
        try:
            interval_minutes = float(interval_input)
            if interval_minutes <= 0:
                print("[ERROR] Minutes must be greater than 0.")
                return

            ignored_folders = get_ignored_folders()
            scheduled_monitoring(folder_path, interval_minutes, ignored_folders)

        except ValueError:
            print("[ERROR] Enter a valid number of minutes.")

    elif choice == "4":
        ignored_folders = get_ignored_folders()
        real_time_monitoring(folder_path, ignored_folders)

    else:
        print("[ERROR] Invalid choice.")


if __name__ == "__main__":
    main()