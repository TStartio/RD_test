import argparse
from scapy.all import *
from queue import Queue
import threading
import time


class Processor(threading.Thread):
    def __init__(self, number, queue, output_file):
        super().__init__()
        self.queue = queue
        self.output_file = output_file
        self.number = number
        self.writer = PcapWriter(self.output_file, append=False)
        self.packet_counter = 0  # Счётчик записанных пакетов

    def run(self):
        while True:
            packet_info = self.queue.get()
            if packet_info is None:
                self.writer.close()
                self.queue.task_done()
                break
            packet = packet_info
            if self.number == 1:
                self.processor1(packet)
            elif self.number == 2:
                self.processor2(packet)
            elif self.number == 3:
                self.processor3(packet)
            self.queue.task_done()

    def processor1(self, packet):
        if UDP in packet or TCP in packet:
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if dport == 7070:
                # Выводим предполагаемый номер пакета в случае игнорирования
                print(f"Обработчик 1: пакет под номером {self.packet_counter + 1} игнорируется")
                return
        self.writer.write(packet)
        self.packet_counter += 1

    def processor2(self, packet):
        if Raw in packet:
            load = packet[Raw].load
            x_pos = load.find(b'x')
            if x_pos != -1:
                modified_load = load[:x_pos + 1]
                new_packet = packet.copy()
                new_packet[Raw].load = modified_load
                # Пересобираем пакет для пересчёта контрольных сумм
                new_packet = IP(new_packet.build())
                self.writer.write(new_packet)
                return
        self.writer.write(packet)

    def processor3(self, packet):
        if TCP in packet:
            time.sleep(2)
            current_time = int(time.time())
            if current_time % 2 == 0:
                self.writer.write(packet)
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if sport == dport:
                print(f"Обработчик 3: Найдено совпадение port = {sport}")
                self.writer.write(packet)


def ip_in_range(ip, start, end):
    ip = list(map(int, ip.split('.')))
    start = list(map(int, start.split('.')))
    end = list(map(int, end.split('.')))
    return start <= ip <= end


def distribute_packets(pcap_file, queues):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Ошибка при чтении файла {pcap_file}: {str(e)}")
        return

    for packet in packets:
        if IP in packet:
            dst_ip = packet[IP].dst
            if ip_in_range(dst_ip, '11.0.0.3', '11.0.0.200'):
                queues[0].put(packet)
            elif ip_in_range(dst_ip, '12.0.0.3', '12.0.0.200'):
                if (TCP in packet and packet[TCP].dport == 8080) or (UDP in packet and packet[UDP].dport == 8080):
                    queues[1].put(packet)
                else:
                    queues[2].put(packet)
            else:
                queues[2].put(packet)
        else:
            queues[2].put(packet)

    for q in queues:
        q.put(None)


def main():
    parser = argparse.ArgumentParser(description='Data Distributor')
    parser.add_argument('-i', '--input', required=True, help='Input .pcap file')
    args = parser.parse_args()

    queues = [Queue() for _ in range(3)]
    processors = []

    for i in range(3):
        p = Processor(i + 1, queues[i], f'result_{i + 1}.pcap')
        p.start()
        processors.append(p)

    distribute_packets(args.input, queues)

    for q in queues:
        q.join()

    for p in processors:
        p.join()


if __name__ == '__main__':
    main()