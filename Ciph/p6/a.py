
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad

# Paso 0: Inicializacion
# Lee clave KAT
KAT = open("KAT.bin", "rb").read()
########################

# (A realizar por el alumno/a...)

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# (A realizar por el alumno/a...)
# Crear el socket de conexion con T (5552)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Alice")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("A -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

# (A realizar por el alumno/a...)


# Recibe el mensaje
cifrado = socket.recibir()
cifrado_mac = socket.recibir()
cifrado_nonce = socket.recibir()

# Descifro los datos con AES GCM
datos_descifrado_ET = funciones_aes.descifrarAES_GCM(KAT, cifrado_nonce, cifrado, cifrado_mac)

# Decodifica el contenido: K1, K2, Nb
json_ET = datos_descifrado_ET.decode("utf-8" ,"ignore")
print("T->A (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)

# Extraigo el contenido
K1, K2, t_nb = msg_ET

print("1st k1")
print(K1.encode("utf-8"))
print("2nd k1")
print("K1 ", K1)
#t_nh = bytearray.fromhex(t_nb)

if(t_n_origen.hex() == t_nb):
    print("El nonce coincide con el enviado.")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)

socketclient = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socketclient.conectar()

aes_cifrado, nonce_16_ini = funciones_aes.iniciarAES_CTR_cifrado(K1)

mensaje = [] # Array vacio
mensaje.append("Nombre") 
mensaje.append(nonce_16_ini.hex()) # Conversion de Bytes a Hexadecimal
jStr = json.dumps(mensaje) # Convertimos un Array Python a string
print(jStr)
BLOCK_SIZE = 16

# Cifro el json con K1
datos_cifrado = funciones_aes.cifrarAES_CTR(aes_cifrado, pad(bytes(jStr, encoding='utf8'), BLOCK_SIZE))

# Aplico HMAC
hmac_obj = HMAC.new(K2, bytes(jStr, encoding='utf8'), SHA256)
mac = hmac_obj.digest()

# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC
socketclient.enviar(datos_cifrado)
socketclient.enviar(nonce_16_ini)
socketclient.enviar(mac)


# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
