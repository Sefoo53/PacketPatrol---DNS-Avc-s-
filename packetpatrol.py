from scapy.all import *
import time
import threading

# Dinleme yapılacak ağ arayüzü (örnek: "wlan0", "eth0")
IFACE = "wlan0"

# Şüpheli domain listesi (örnek)
SUSPICIOUS_DOMAINS = [
    "login-facebook.com",
    "paypal-security-check.com",
    "update-microsoft.net",
    "free-nitro-discord.net",
    "example-phishing-site.org"
]

# DNS sorgu ve cevapları sayacı
dns_stats = {
    "queries": 0,
    "responses": 0,
    "suspicious_queries": 0
}

# Log dosyası istersen aktif et
LOG_TO_FILE = True
LOG_FILE = "dns_traffic_log.txt"

def log_message(msg):
    print(msg)
    if LOG_TO_FILE:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")

def check_suspicious_domain(domain):
    domain_lower = domain.lower()
    for bad_domain in SUSPICIOUS_DOMAINS:
        if bad_domain in domain_lower:
            return True
    return False

def process_packet(pkt):
    # DNS sorgusu (Query)
    if pkt.haslayer(DNSQR):
        dns_stats["queries"] += 1
        queried_domain = pkt[DNSQR].qname.decode()
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown IP"
        log_message(f"[DNS Sorgusu] {src_ip} → {queried_domain}")

        if check_suspicious_domain(queried_domain):
            dns_stats["suspicious_queries"] += 1
            log_message(f"[! UYARI] Şüpheli domain sorgusu tespit edildi: {queried_domain} (Kaynak: {src_ip})")

    # DNS cevabı (Response)
    elif pkt.haslayer(DNSRR):
        dns_stats["responses"] += 1
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown IP"
        answers = []
        dns_resp = pkt[DNS]
        # DNS içinde birden çok cevap olabilir
        for i in range(dns_resp.ancount):
            rr = dns_resp.an[i]
            answers.append(rr.rdata if hasattr(rr, 'rdata') else str(rr))
        log_message(f"[DNS Cevabı] {src_ip} → {', '.join(map(str, answers))}")

def print_stats_periodically(interval=30):
    while True:
        time.sleep(interval)
        print("\n=== DNS Trafik İstatistikleri ===")
        print(f"Toplam sorgu sayısı: {dns_stats['queries']}")
        print(f"Toplam cevap sayısı: {dns_stats['responses']}")
        print(f"Şüpheli sorgu sayısı: {dns_stats['suspicious_queries']}")
        print("==================================\n")

def start_sniffing():
    log_message(f"[*] {IFACE} arayüzünde DNS trafiği izleniyor...")
    sniff(
        iface=IFACE,
        filter="udp port 53",
        prn=process_packet,
        store=0
    )

if __name__ == "__main__":
    try:
        if LOG_TO_FILE:
            with open(LOG_FILE, "w") as f:
                f.write(f"PacketPatrol DNS Hunter Log Başlangıcı - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # İstatistikleri ayrı thread'te periyodik yazdır
        stats_thread = threading.Thread(target=print_stats_periodically, daemon=True)
        stats_thread.start()

        # Paketi dinle
        start_sniffing()

    except KeyboardInterrupt:
        log_message("\n[!] İzleme kullanıcı tarafından durduruldu.")
    except Exception as e:
        log_message(f"[!] Hata oluştu: {e}")
