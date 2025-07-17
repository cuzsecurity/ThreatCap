import os
import csv
import argparse
from datetime import datetime

# Argument Parser for custom tags
parser = argparse.ArgumentParser(description="Generate labeled dataset for PCAP files.")
parser.add_argument("--tag", type=str, help="Optional label tag for the output files (e.g., v1.0, test1).")
args = parser.parse_args()

# Paths
BASE_DIR = os.path.dirname(__file__)
PCAP_DIR = os.path.abspath(os.path.join(BASE_DIR, "../samples/training_pcaps"))

# Generate versioned filenames
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
suffix = f"_{args.tag}" if args.tag else ""
label_filename = f"labels_{timestamp}{suffix}.csv"
log_filename = f"unmatched_{timestamp}{suffix}.log"

OUTPUT_FILE = os.path.join(BASE_DIR, label_filename)
UNMATCHED_LOG = os.path.join(BASE_DIR, log_filename)

# Category mapping keywords
family_category_map = {
    "Emotet": "Loader",
    "Trickbot": "Loader",
    "IcedID": "Loader",
    "Qakbot": "Loader",
    "Gootkit": "Loader",
    "AZORult": "Infostealer",
    "Redline": "Infostealer",
    "Vidar": "Infostealer",
    "spambot": "Botnet",
    "Zeus": "Banking",
    "Panda": "Banking",
    "LockBit": "Ransomware",
    "REvil": "Ransomware",
    "Conti": "Ransomware",
    "BlackCat": "Ransomware",
    "log4j": "Exploitation",
    "scan": "Reconnaissance",
    "probe": "Reconnaissance",
    "webserver": "Reconnaissance",
    "ransom": "Ransomware",
    "EK": "ExploitKit",
    "exploitkit": "ExploitKit",
    "rigek": "ExploitKit",
    "nuclear": "ExploitKit",
    "angler": "ExploitKit",
    "neutrino": "ExploitKit",
    "Bazar": "Loader",
    "Hancitor": "Loader",
    "MetaStealer": "Infostealer",
    "NetSupport": "RAT",
    "GootLoader": "Loader",
    "Lumma": "Infostealer",
    "Koi": "Loader",
    "AsyncRAT": "RAT",
    "Remcos": "RAT",
    "Astaroth": "Infostealer",
    "Bumblebee": "Loader",
    "Zbot": "Banking",
    "Netwire": "RAT",
    "Dridex": "Banking",
    "Hawkeye": "Infostealer",
    "Lokibot": "Infostealer",
    "Dreambot": "Loader",
    "Ursnif": "Banking",
    "Quasar": "RAT",
    "Redaman": "Banking",
    "XMRig": "Cryptominer",
    "Formbook": "Infostealer",
    "AgentTesla": "Infostealer",
    "Agent-Tesla": "Infostealer",
    "Pikabot": "Loader",
    "SSLoad": "Loader",
    "XLoader": "Infostealer",
    # Phishing indicators (family will be blank)
    "phish": "Phishing",
    "phishing": "Phishing",
    "web-phish": "Phishing",
    "paypal": "Phishing",
    "office365": "Phishing",
    "login-page": "Phishing",
    "fake-login": "Phishing"
}

def infer_labels(filename):
    lower_name = filename.lower()
    for keyword, category in family_category_map.items():
        if keyword.lower() in lower_name:
            category = category.title()
            if category == "Phishing":
                return "", category
            else:
                return keyword.title(), category
    return "", "Malware"

if __name__ == "__main__":
    matched, unmatched = 0, []

    with open(OUTPUT_FILE, "w", newline="") as out_csv:
        writer = csv.writer(out_csv)
        writer.writerow(["filename", "family", "category"])

        for file in sorted(os.listdir(PCAP_DIR)):
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                family, category = infer_labels(file)
                writer.writerow([file, family, category])
                if category and category != "Malware":
                    matched += 1
                else:
                    unmatched.append(file)

    # 🎯 Output Summary
    print(f"✅ Labeling complete.")
    print(f"✔️  {matched} files matched with a specific category (not just 'Malware').")

    if unmatched:
        print(f"⚠️  {len(unmatched)} files had no specific match. Logged to: {log_filename}")
        with open(UNMATCHED_LOG, "w") as log_file:
            for u in unmatched:
                log_file.write(f"{u}\n")
                print(f"   - {u}")

    print(f"\n📁 Output saved to: {OUTPUT_FILE}")
