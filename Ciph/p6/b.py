

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)
print("hecho paso 1")

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# (A realizar por el alumno/a...)


# Recibe el mensaje
cifrado = socket.recibir()
cifrado_mac = socket.recibir()
cifrado_nonce = socket.recibir()

# Descifro los datos con AES GCM
datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KBT, cifrado_nonce, cifrado, cifrado_mac)

# Decodifica el contenido: K1, K2, Nb
json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
print("T->B (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)

# Extraigo el contenido
K1, K2, t_nb = msg_ET
t_nh = bytearray.fromhex(t_nb)

if(t_n_origen.hex() == t_nb):
    print("El nonce coincide con el enviado.")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 
print("hecho paso 2")

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)

socketserver = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socketserver.escuchar()

jStr = socketserver.recibir()
nonce_16_ini = socketserver.recibir()
mac = socketserver.recibir()


# Descifro el mensaje
aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_16_ini)

BLOCK_SIZE = 16
jStr = funciones_aes.descifrarAES_CTR(aes_descifrado, jStr)
jStr = unpad(jStr, BLOCK_SIZE).decode("utf-8", "ignore")
mensaje = json.loads(jStr) # Recuperamos un Array Python de un string
msg, nonce_cadenaHEX = mensaje
nonce_cadena = bytearray.fromhex(nonce_cadenaHEX) # De Hexadecimal a Bytes 
print("Mensaje: ", msg)
if(nonce_cadena == nonce_16_ini):
    print("Los nonce son iguales")
else: 
    print("Los nonce NO son iguales")

# Verifico el mac

if (mac == HMAC.new(K2, bytes(jStr, encoding='utf8'), SHA256).digest()):
    print("mac is valid.")
else:
    print("mac is invalid.")

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)

