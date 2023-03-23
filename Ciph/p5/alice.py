import funciones_rsa
import funciones_aes
from socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import json
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import HMAC, SHA256

# Cargo la clave pública de Bob y la clave privada de Alice
Pub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")
Pri_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem", "alice")

# Genero las dos claves
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()


# Cifro K1 y K2 con Pub_B
K1_cif = funciones_rsa.cifrarRSA_OAEP_BIN(K1, Pub_B)
K2_cif = funciones_rsa.cifrarRSA_OAEP_BIN(K2, Pub_B)

# Firmo la concatenación de K1 y K2 con Pri_A
K1K2_fir = funciones_rsa.firmarRSA_PSS(K1 + K2, Pri_A)

# Conectamos con el servidor y enviamos a Bob a través del socket
socketclient = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketclient.conectar()

socketclient.enviar(bytes("prueba",'UTF-8'))
socketclient.enviar(K1_cif)
socketclient.enviar(K2_cif)
socketclient.enviar(K1K2_fir)



#####################
#####################

# Genero el json con el nombre de Alice y un nonce nA

aes_cifrado, nonce_16_ini = funciones_aes.iniciarAES_CTR_cifrado(K1)

mensaje = [] # Array vacio
mensaje.append("Alice lpmqtp") 
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


#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC
jStr = socketclient.recibir()
nonce_16_ini = socketclient.recibir()
mac = socketclient.recibir()

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

# Visualizo la identidad del remitente y compruebo si los campos enviados son los mismo que los recibidos

#####################
#####################

# Intercambio de información NUMERO 1. Al utilizar K1, reutilizo el canal de comunicaciones aes_cifrado

# Aplico HMAC


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC


# Intercambio de información NUMERO 2. Al utilizar K1, reutilizo el canal de comunicaciones aes_cifrado


# Aplico HMAC


# Envío el json cifrado junto con el nonce del AES CTR, y el mac del HMAC


# Cierro el socket
socketclient.cerrar()
