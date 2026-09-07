import socket

# Bytes EXACTOS del log del hub (DEBUG paso1 hex=...)
hex_msg = "00006699000000000000000000030000002c8d2287d57d6b52293271e706150ace1fdb1a52c0f2a052da70186ea786a1456fb56b287be375755dac1222c300009966"
data = bytes.fromhex(hex_msg)

THERMOSTAT_IP = "192.168.1.137"  # ajusta si cambió otra vez
THERMOSTAT_PORT = 6668

print(f"Conectando a {THERMOSTAT_IP}:{THERMOSTAT_PORT} ...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect((THERMOSTAT_IP, THERMOSTAT_PORT))
print("Conectado. Enviando los bytes exactos del hub...")

sock.sendall(data)
print(f"Enviados {len(data)} bytes. Esperando respuesta...")

try:
    resp = sock.recv(2048)
    if resp:
        print(f"¡RESPUESTA RECIBIDA! ({len(resp)} bytes)")
        print(resp.hex())
    else:
        print("Conexión cerrada sin datos (igual que el hub)")
except socket.timeout:
    print("Timeout esperando respuesta (nada llegó)")
except Exception as e:
    print(f"Error: {e}")

sock.close()
