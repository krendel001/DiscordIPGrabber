from scapy.all import sniff, TCP, IP
import psutil

def get_process_by_port(port):
    """Получение имени процесса по порту."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['pid'] is None or proc.info['name'] is None:
                continue  # Пропускаем процессы без PID или имени
            
            connections = proc.net_connections()
            for conn in connections:
                if conn.laddr.port == port:
                    return proc.info['name']
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass  # Игнорируем ошибки доступа или несуществующих процессов
    return None

def packet_callback(packet):
    """Обработчик пакетов."""
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        src_process_name = get_process_by_port(src_port)
        dst_process_name = get_process_by_port(dst_port)
        
        if src_process_name and "discord" in src_process_name.lower():
            print(f"Discord Traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Process: {src_process_name}")
        elif dst_process_name and "discord" in dst_process_name.lower():
            print(f"Discord Traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Process: {dst_process_name}")

def get_network_interfaces():
    """Получение списка сетевых интерфейсов."""
    interfaces = {}
    for name, info in psutil.net_if_addrs().items():
        interfaces[name] = name  # Используйте только имя интерфейса, если нужно
    return interfaces

def sniff_discord_traffic(interface=None, filter_expression="tcp"):
    """Захват трафика Discord на указанном интерфейсе."""
    if not interface:
        interfaces = get_network_interfaces()
        print("Выберите интерфейс для захвата:")
        for i, iface in enumerate(interfaces.values(), start=1):
            print(f"{i}. {iface}")
        choice = int(input("Введите номер интерфейса: ")) - 1
        interface = list(interfaces.keys())[choice]
    
    print(f"Начинаем захват пакетов на интерфейсе {interface}...")
    sniff(iface=interface, prn=packet_callback, filter=filter_expression)

if __name__ == "__main__":
    sniff_discord_traffic(filter_expression="tcp")