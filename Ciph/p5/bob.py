import funciones_rsa
import funciones_aes
from socket_class import SOCKET_SIMPLE_TCP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import json
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import HMAC, SHA256

# Cargo la clave pública de Alice y la clave privada de Bob
Pub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Pri_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem", "bob")

# Creamos el servidor para Bob y recibimos las claves y la firma
socketserver = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socketserver.escuchar()

prueba = socketserver.recibir()
K1_cif = socketserver.recibir()
K2_cif = socketserver.recibir()
K1K2_fir = socketserver.recibir()

print(prueba)

# Descifro las claves K1 y K2 con Pri_B
K1 = funciones_rsa.descifrarRSA_OAEP_BIN(K1_cif, Pri_B)
K2 = funciones_rsa.descifrarRSA_OAEP_BIN(K2_cif, Pri_B)

# Compruebo la validez de la firma con Pub_A
if funciones_rsa.comprobarRSA_PSS(K1+K2,K1K2_fir,Pub_A):
    print("Firma de K1||K2 válida")
else:
    print("Firma de K1||K2 NO válida")

#####################
#####################

# Recibo el mensaje, junto con el nonce del AES CTR, y el mac del HMAC
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


# Visualizo la identidad del remitente

#####################
#####################

# Genero el json con el nombre de Bob, el de Alice y el nonce nA

aes_cifrado, nonce_16_ini = funciones_aes.iniciarAES_CTR_cifrado(K1)

mensaje = [] # Array vacio
mensaje.append("Alice, soy Bob, lpmqtrmp") 
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
socketserver.enviar(datos_cifrado)
socketserver.enviar(nonce_16_ini)
socketserver.enviar(mac)

#####################
#####################

# Recibo el primer mensaje de Alice

# Descifro el mensaje


# Verifico el mac

# Muestro el mensaje


# Recibo el segundo mensaje de Alice

# Descifro el mensaje


# Verifico el mac

# Muestro el mensaje


# Cierro el socket
socketserver.cerrar()
