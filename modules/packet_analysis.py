import re

# ================= ADVANCED PACKET ANALYSIS =================

def analyze_packet(data):
    data = str(data)
    lower = data.lower()

    results = []

    # ---------------- ATTACK DETECTION ----------------
    if "select" in lower or "or 1=1" in lower:
        results.append("⚠ SQL Injection Detected")

    if "<script>" in lower:
        results.append("⚠ XSS Attack Detected")

    if "cmd=" in lower or "exec" in lower:
        results.append("⚠ Command Injection Detected")

    if "../" in lower:
        results.append("⚠ Directory Traversal Detected")

    # ---------------- SUSPICIOUS PATTERNS ----------------
    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", data):
        results.append("🌐 IP Address Found in Packet")

    if "base64" in lower:
        results.append("⚠ Encoded Payload Detected")

    if "password" in lower:
        results.append("🔐 Sensitive Data Detected")

    # ---------------- PACKET STRUCTURE ----------------
    results.append("📦 Packet Length: " + str(len(data)))
    results.append("📡 Protocol Guess: HTTP/TCP")

    # ---------------- DEFAULT ----------------
    if len(results) == 2:  # only structure lines
        results.append("✅ No Major Threat Found")

    return results


# ================= FILE ANALYSIS =================

def analyze_packet_file(path):
    try:
        with open(path, "rb") as f:
            content = f.read()

        try:
            data = content.decode(errors="ignore")
        except:
            data = str(content)

        return analyze_packet(data)

    except Exception as e:
        return [f"❌ Error reading file: {str(e)}"]