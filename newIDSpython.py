import sqlite3
from datetime import datetime
import scapy.all as scapy
from scapy.all import sniff, IP, TCP, ICMP, ARP, Raw
from collections import defaultdict
import time
import re
from urllib.parse import unquote
import socket

# Conectar a la base de datos (si no existe, se crea)
conn = sqlite3.connect('results.db')
c = conn.cursor()

# Crear una tabla con un campo timestamp si no existe
c.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, log_text TEXT, timestamp TEXT)''')

# Función para guardar los logs y el timestamp
def save_log(log):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO logs (log_text, timestamp) VALUES (?, ?)", (log, timestamp))
    conn.commit()

# Obtener IP del PC
def get_local_ip():
    # Obtiene el nombre del host
    hostname = socket.gethostname()
    # Obtiene la dirección IP asociada al nombre del host
    local_ip = socket.gethostbyname(hostname)
    return local_ip

my_ip = get_local_ip()

# Puertos comunes a monitorear
common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 445}

# Almacena los tiempos de los paquetes de escaneo de puertos
port_scan_records = defaultdict(set)
scan_threshold = 10  # Número de intentos de conexión para considerar como escaneo

# Detectar posible escaneo de puertos
def detect_port_scan(src_ip, dst_port):
    if dst_port in common_ports:
        port_scan_records[src_ip].add(dst_port)

        if len(port_scan_records[src_ip]) > scan_threshold:
            log_msg = f"Posible barrido de puertos detectado desde {src_ip} a puertos comunes: {list(port_scan_records[src_ip])} \n"
            print(log_msg)
            save_log(log_msg)  # Guardar log en la base de datos
            
#Detectar SSH
# Diccionario para almacenar la cantidad de paquetes SSH por IP
ssh_attempts = defaultdict(int)
# Parámetros de detección
MAX_PACKETS = 500  # Número máximo de paquetes antes de considerar un ataque
TIME_WINDOW = 30  # Tiempo en segundos (por ejemplo, 1 minuto)

def detect_ssh_connection(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Detectar si es el puerto SSH (22)
        if packet[TCP].dport == 22 or packet[TCP].sport == 22:

            # Si el paquete tiene el flag SYN, la conexión se está iniciando
            if packet[TCP].flags & 0x02:  # Flag SYN
                log_msg = f"Conexión SSH iniciada desde {src_ip} hacia {dst_ip}"
                print(log_msg)
                save_log(log_msg)


            # Si el paquete tiene los flags FIN o RST, la conexión está finalizando
            if packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04:  # Flag FIN or RST
                log_msg = f"Conexión SSH finalizada desde {src_ip} hacia {dst_ip}"
                print(log_msg)
                save_log(log_msg)


def detect_ssh_bruteforce(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Filtrar por puerto 22 (SSH)
        if packet[TCP].dport == 22:
            src_ip = packet[IP].src
            
            # Aumentar el contador de intentos SSH
            ssh_attempts[src_ip] += 1
            
            # Obtener el tiempo actual
            current_time = time.time()
            
            # Limpiar el diccionario de intentos de IPs que están fuera de la ventana de tiempo
            # Esto mantiene solo los conteos recientes
            for ip in list(ssh_attempts.keys()):
                # Si el IP ha estado inactivo por más de TIME_WINDOW segundos, eliminarlo
                if current_time - packet.time > TIME_WINDOW:
                    del ssh_attempts[ip]

            # Si supera el límite de paquetes, considerarlo ataque
            if ssh_attempts[src_ip] >= MAX_PACKETS:
                log_msg = f"Ataque de fuerza bruta detectado desde {src_ip}: {ssh_attempts[src_ip]} intentos de conexión SSH."
                print(log_msg)
                save_log(log_msg)
                
                # Limpiar intentos para esa IP después de detectar el ataque
                del ssh_attempts[src_ip]


# Detectar ICMP ping
def detect_icmp_ping(packet):
    if packet.haslayer(ICMP) and packet[IP].dst == my_ip:
        if packet[ICMP].type == 8:  # Tipo 8 es una solicitud de eco (ping request)
            log_msg = f"Posible ping detectado desde {packet[IP].src}: {packet.summary()}"
            print(log_msg)
            save_log(log_msg)

# Detectar ARP ping
def detect_arp_ping(packet):
    if packet.haslayer(ARP) and packet[ARP].pdst == my_ip and packet[ARP].op == 1:  # ARP Request
        log_msg = f"Posible ARP ping detectado desde {packet[ARP].psrc}: {packet.summary()}"
        print(log_msg)
        save_log(log_msg)


#Detectar ARP Spoofing attack
ip_mac_mapping = {}

def detect_ARP_spoofing(packet):
    if packet.haslayer(ARP):
        ip_origen = packet[ARP].psrc
        mac_origen = packet[scapy.Ether].src

        if ip_origen in ip_mac_mapping:
            if ip_mac_mapping[ip_origen] != mac_origen:
               log_msg = f"Posible ataque de MAC Spoofing detectado. IP: {ip_origen} cambió de MAC: de {ip_mac_mapping[ip_origen]} a {mac_origen}"
               print(log_msg)
               save_log(log_msg)
               
            else:
                ip_mac_mapping[ip_origen] = mac_origen
                print(f"Registro inicial - IP: {ip_origen}, MAC: {mac_origen}")


#Detectar Injeccion SQL
# patrones comunes de inyecciones SQL
sql_injection_patterns = [
    r"'.*?'",               # Apóstrofe abierto
    r"OR 1=1",              # OR 1=1 lógica booleana
    r"OR '1'='1'",          # OR '1'='1' lógica booleana con comillas
    r"SELECT .* FROM",      # Intento de extracción de datos
    r"UNION SELECT",        # Intento de unión de consultas
    r"INSERT INTO .* VALUES", # Intento de inserción de datos
    r"DROP TABLE",          # Intento de borrar tablas
    r"UPDATE .* SET",       # Intento de actualización de datos
    r"DELETE FROM",         # Intento de borrar datos
    r"AND 1=1",             # Lógica booleana AND
    r"AND '1'='1'",         # Lógica booleana con comillas
    r"EXEC\(.*\)",          # Intento de ejecutar un procedimiento almacenado (paréntesis escapados)
    r"INFORMATION_SCHEMA",  # Intento de acceder al esquema de información
    r"CHAR\([0-9]+\)",      # Codificación de caracteres para inyección
    r"--",                  # Comentario SQL
    r"#[^\r\n]*",           # Comentario SQL en MySQL
    r";--",                 # Fin de consulta seguido de comentario
    r"' OR 'x'='x",         # Inyección simple con OR
    r"ORDER BY \d+",        # Ordenar por columnas, usado en ataques UNION
    r"GROUP BY .* HAVING",  # Intento de agrupar y filtrar datos
    r"' or 'a'='a",         # Comparación lógica falsa
    r"' or 1=1 --",         # Intento de evadir autenticación
    r"\" or 1=1 --",        # Variación con comillas dobles
    r"'\) or '1'='1'--",    # Finalizar consulta e inyectar código SQL (paréntesis escapados)
    r"waitfor delay '0:0:", # Ataque de denegación de servicio (DoS) con SQL
    r"SLEEP\([0-9]+\)",     # Intento de usar función de retardo (paréntesis escapados)
    r"BENCHMARK\([0-9]+,",  # Intento de medir tiempo de ejecución (paréntesis escapados)
    r"NULL",                # Uso de NULL en ataques UNION
    r"CAST\(.* AS",         # Intento de convertir tipos de datos (paréntesis escapados)
    r"CONCAT\(",            # Intento de concatenar columnas para UNION (paréntesis escapados)
]

# Función para detectar patrones comunes de inyección SQL
def detect_sql_injection(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):  # Solo para paquetes TCP con datos
        payload = packet[Raw].load.decode(errors='ignore')  # Decodificar carga útil
        src_ip = packet[IP].src
        
        # Solo analizar si es una solicitud HTTP (puerto 80, en este caso)
        if packet[TCP].dport == 80 or packet[TCP].dport == 5000 or packet[TCP].sport == 80 :
            # Decodificar el contenido para obtener la URL si es GET
            if payload.startswith("GET") or payload.startswith("POST"):
                # Patrón para detectar inyección SQL
                
                # Buscar inyección SQL en la URL o el cuerpo de la petición
                for pattern in sql_injection_patterns:
                    if re.search(pattern, unquote(payload)):  # Descodificar URL para analizar
                        log_msg = f"Posible inyección SQL detectada: {pattern} desde: {src_ip} en {payload}"
                        print(log_msg)
                        save_log(log_msg)
                        break  # Rompe si detecta inyección para no seguir buscando


#Detectar Fuzzing de directorios en URL
# Lista de patrones comunes para reconocer ataques de reconocimiento de directorios
dir_traversal_patterns = [
    r"\.\./\.\./",            # Directory traversal básico
    r"/etc/passwd",           # Intento de acceder al archivo de contraseñas en sistemas Unix
    r"/admin",                # Intento de acceder a áreas administrativas
    r"/wp-admin",             # WordPress admin
    r"/robots.txt",           # Intento de leer robots.txt (para encontrar URLs interesantes)
    r"/.git",                 # Intento de acceder a directorios de repositorios
    r"/config.php",           # Intento de acceder a archivos de configuración de PHP
    r"shell\.php",            # Intento de subir un shell PHP
    r"\.env",                 # Intento de acceder a archivos de entorno
    r"cgi-bin",               # Intento de atacar scripts cgi-bin
]

# Función para detectar patrones de reconocimiento de directorios
def detect_dir_traversal(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):  # Solo para paquetes TCP con datos
        try:
            payload = packet[Raw].load.decode(errors='ignore')  # Decodificar carga útil
        except UnicodeDecodeError:
            return  # Si no se puede decodificar, saltar el paquete

        # Solo analizar si es una solicitud HTTP (puerto 80, 5000 o tráfico HTTPS en 443)
        if packet[TCP].dport in [80, 5000] or packet[TCP].sport == 80:
            # Decodificar el contenido para obtener la URL si es GET
            if payload.startswith("GET"):
                decoded_payload = unquote(payload)  # Decodificar la URL para analizar

                # Buscar patrones de reconocimiento de directorios
                for pattern in dir_traversal_patterns:
                    if re.search(pattern, decoded_payload):
                        src_ip = packet[IP].src
                        log_msg = f"Posible reconocimiento de directorios detectado desde {src_ip} en la URL: {decoded_payload}"
                        print(log_msg)
                        save_log(log_msg)
                        break  # Rompe si detecta el patrón para no seguir buscando

            # Buscar en solicitudes POST (los datos están en el cuerpo de la solicitud)
            elif payload.startswith("POST"):
                # El cuerpo del POST generalmente está después de los encabezados HTTP
                post_body = payload.split("\r\n\r\n", 1)[-1]  # Extraer el cuerpo del POST
                for pattern in dir_traversal_patterns:
                    if re.search(pattern, post_body):
                        src_ip = packet[IP].src
                        log_msg = f"Intento de subida de archivos maliciosos mediante metodo POST desde {src_ip} con datos: {post_body}"
                        print(log_msg)
                        save_log(log_msg)
                        break  # Detener búsqueda si se detecta un patrón

#Detectar fuerza bruta en panel de autenticacion:
# Función para leer la URL de un archivo de texto
def read_login_url_from_file(filename):
    try:
        with open(filename, 'r') as file:
            return file.readline().strip()  # Leer la primera línea y eliminar espacios
    except FileNotFoundError:
        print(f"Error: El archivo {filename} no fue encontrado.")
        return None

# Leer el valor de login_url desde el archivo config.txt
login_url = read_login_url_from_file('Auth_Panel_Config.txt')

# Configuración
brute_force_threshold = 10  # Número de intentos fallidos para considerarlo un ataque
brute_force_time_window = 60  # Ventana de tiempo en segundos

# Almacena los tiempos de los intentos de inicio de sesión
login_attempts = defaultdict(list)

# Función para detectar ataques de fuerza bruta
def detect_brute_force(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore')
        except UnicodeDecodeError:
            return  # Si no se puede decodificar, saltar el paquete

        # Solo analizar si es una solicitud HTTP (puerto 80)
        if packet[TCP].dport == 80 or packet[TCP].sport == 80 or packet[TCP].dport == 5000:
            # Procesar solo solicitudes POST a la URL de inicio de sesión
            if payload.startswith("POST") and login_url in payload:
                src_ip = packet[IP].src
                current_time = time.time()

                # Registrar el intento de inicio de sesión
                login_attempts[src_ip].append(current_time)

                # Limpiar los registros de intentos antiguos
                login_attempts[src_ip] = [t for t in login_attempts[src_ip] if current_time - t < brute_force_time_window]

                # Verificar si el número de intentos excede el umbral
                if len(login_attempts[src_ip]) > brute_force_threshold:
                    log_msg = f"Posible ataque de fuerza bruta en panel de autenticacion path: {login_url} detectado desde {src_ip}. Intentos: {len(login_attempts[src_ip])}"
                    print(log_msg)
                    save_log(log_msg)

# Callback para manejar los paquetes capturados
def packet_callback(packet):
    if packet.haslayer(IP) and packet[IP].dst == my_ip:
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            detect_port_scan(packet[IP].src, dst_port)

        detect_icmp_ping(packet)
        detect_ssh_connection(packet)
        detect_ssh_bruteforce(packet)
        detect_sql_injection(packet)
        detect_dir_traversal(packet)
        detect_brute_force(packet)
    
    if packet.haslayer(ARP):
        detect_arp_ping(packet)
        detect_ARP_spoofing(packet)

# Iniciar la captura de paquetes
sniff(prn=packet_callback, filter="ip and tcp or icmp or arp", store=0)
# Cerrar la conexión a la base de datos
conn.close()
