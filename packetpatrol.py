from scapy.all import *
import time

iface = "wlan0"  # Dinleme yapılacak ağ arayüzü

suspicious_domains = [
    "login-facebook.com",
    "paypal-security-check.com",
    "update-microsoft.net",
    "free-nitro-discord.net",
]

seen_queries = {}

def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):  # DNS Query Request
        queried_domain = pkt[DNSQR].qname.decode()
        src_ip = pkt[IP].src

        if queried_domain not in seen_queries:
            seen_queries[queried_domain] = time.time()
            print(f"[+] {src_ip} → DNS sorgusu: {queried_domain}")

            for suspicious in suspicious_domains:
                if suspicious in queried_domain:
                    print(f"[!] ⚠️ Şüpheli domain sorgusu tespit edildi: {queried_domain}")
                    break

def start_sniff():
    print("[*] DNS trafiği izleniyor, CTRL+C ile çıkabilirsiniz...\n")
    sniff(filter="udp port 53", prn=dns_monitor, iface=iface, store=0)

if __name__ == "__main__":
    try:
        start_sniff()
    except KeyboardInterrupt:
        print("\n[!] İzleme sonlandırıldı.")
    except Exception as e:
        print(f"[!] Hata oluştu: {e}")
