from scapy.all import *
import subprocess
import os
import sys

# Генерация test.pcap в текущей директории
packets = [
    IP(src="192.168.1.100", dst="11.0.0.5") / TCP(sport=12345, dport=7070) / "Test packet 1",
    IP(src="192.168.1.101", dst="11.0.0.10") / TCP(sport=12346, dport=80) / "Test packet 2",
    IP(src="192.168.1.102", dst="12.0.0.15") / UDP(sport=12347, dport=8080) / "Data with x inside",
    IP(src="192.168.1.103", dst="12.0.0.20") / TCP(sport=12348, dport=8080) / "No x here",
    IP(src="192.168.1.104", dst="10.0.0.1") / TCP(sport=12349, dport=443) / "TCP test packet",
    IP(src="192.168.1.105", dst="172.16.0.1") / UDP(sport=54321, dport=54321) / "UDP matching ports",
    IP(src="192.168.1.106", dst="172.16.0.2") / UDP(sport=12350, dport=9999) / "Regular packet"
]
pcap_path = os.path.join(os.getcwd(), "test.pcap")
wrpcap(pcap_path, packets)
print("Файл test.pcap создан в:", pcap_path)

python_path = sys.executable

script_dir = os.path.dirname(os.path.abspath(__file__))
script_path = os.path.join(script_dir, "infotech_RD.py")

if not os.path.exists(python_path):
    print(f"Ошибка: интерпретатор Python {python_path} не найден.")
    sys.exit(1)
if not os.path.exists(script_path):
    print(f"Ошибка: скрипт {script_path} не найден.")
    sys.exit(1)
if not os.path.exists(pcap_path):
    print(f"Ошибка: файл {pcap_path} не найден.")
    sys.exit(1)

# Запуск основной программы
try:
    subprocess.run([python_path, script_path, "-i", pcap_path], check=True)
except subprocess.CalledProcessError as e:
    print(f"Ошибка при запуске infotech_RD.py: {e}")
except FileNotFoundError as e:
    print(f"Не удалось выполнить команду: {e}")