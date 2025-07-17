import os
import csv

# 🗂️ Paths
BASE_DIR = os.path.dirname(__file__)
PCAP_DIR = os.path.abspath(os.path.join(BASE_DIR, "../samples/training_pcaps"))
OUTPUT_FILE = os.path.join(BASE_DIR, "labels_test.csv")

# ⚙️ Category mapping keywords (malware behavior or stage)
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
    "neutrino": "ExploitKit"
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
            # For phishing, omit family on purpose
            if category == "Phishing":
                return "", category
            else:
                return keyword, category

    # If no keyword is matched, fallback to generic malware:
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
                if category:
                    matched += 1
                else:
                    unmatched.append(file)

    # 🎯 Output Summary
    print(f"✅ Labeling complete.")
    print(f"✔️  {matched} files matched with a category.")
    if unmatched:
        print(f"⚠️  {len(unmatched)} files had no match:")
        for u in unmatched:
            print(f"   - {u}")
    print(f"\n📁 Output saved to: {OUTPUT_FILE}")
