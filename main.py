
from collections import Counter

LOG_FILE = "sample_logs.txt"
FAILED_LOGIN_THRESHOLD = 3


def analyze_logs():
    failed_attempts = Counter()
    successful_attempts = 0
    total_events = 0

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                parts = line.strip().split()

                if len(parts) != 4:
                    continue

                status = parts[2]
                ip_address = parts[3]

                total_events += 1

                if status == "FAILED":
                    failed_attempts[ip_address] += 1
                elif status == "SUCCESS":
                    successful_attempts += 1

        print("\n===== SECURITY LOG REPORT =====")
        print("Total events:", total_events)
        print("Successful logins:", successful_attempts)
        print("Failed login attempts:", sum(failed_attempts.values()))

        print("\nFailed login attempts by IP address:")

        for ip, attempts in failed_attempts.items():
            print(f"{ip}: {attempts} failed attempts")

        print("\nSuspicious activity:")

        found = False

        for ip, attempts in failed_attempts.items():
            if attempts >= FAILED_LOGIN_THRESHOLD:
                print(f"ALERT: {ip} has {attempts} failed login attempts!")
                found = True

        if not found:
            print("No suspicious activity detected.")

    except FileNotFoundError:
        print("Error: Security log file not found.")


if __name__ == "__main__":
    analyze_logs()
