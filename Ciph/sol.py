

# Paso 1) A->T: Alice,KDC
#######################################

# Crear el socket de escucha de Alice (5551)
print("Esperando a Alice...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Alice.escuchar()

# Recibe el mensaje
json_M1 = socket_Alice.recibir()
id_Alice,id_Bob = json.loads(json_M1)

# 1 -----------------------

socket_KDC = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_KDC.conectar()

msg_1 = []
msg_1.append("Alice")
msg_1.append("Bob")
json_msg_1 = json.dumps(msg_1)
socket_KDC.enviar(json_msg_1.encode("utf-8"))

# --------------------------


# 2 ------------------------

# Kerberos

# --------------------------

# Paso 2) T->A: KAT(Time, L, K_AB, Bob), mac_A, nonce_A, KBT(Time, L, K_AB, Alice), mac_B, nonce_B usando AES-GCM
##########################################

# Crea la clave de sessión K_AB
K_AB = get_random_bytes(16)

# Obtiene el tiempo
timestamp = time.time()

# Establece el tiempo de validez máximo en 100 segundos
l = 100

# Crea el mensaje con la clave para A
msg_2_A = []
msg_2_A.append(timestamp)
msg_2_A.append(l)
msg_2_A.append(K_AB.hex())
msg_2_A.append(id_Bob)
json_msg_2_A = json.dumps(msg_2_A)
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado_clave_a, mac_a, nonce_a = funciones_aes.cifrarAES_GCM(aes_engine,json_msg_2_A.encode("utf-8"))

# Crea el mensaje con la clave para B

# 3 ------------------------

msg_2_B = []
msg_2_B.append(timestamp)
msg_2_B.append(l)
msg_2_B.append(K_AB.hex())
msg_2_B.append(id_Alice)
json_msg_2_B = json.dumps(msg_2_B)
aes_engine = funciones_aes.iniciarAES_GCM(KBT)

cifrado_clave_b, mac_b, nonce_b = funciones_aes.cifrarAES_GCM(aes_engine,json_msg_2_B.encode("utf-8"))

# --------------------------

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_2 = []
msg_2.append(cifrado_clave_a.hex())
msg_2.append(mac_a.hex())
msg_2.append(nonce_a.hex())
msg_2.append(cifrado_clave_b.hex())
msg_2.append(mac_b.hex())
msg_2.append(nonce_b.hex())
json_msg_2 = json.dumps(msg_2)

# Envía el mensaje a Alice
socket_Alice.enviar(json_msg_2.encode("utf-8"))

# Cerramos el socket entre A y T, no lo utilizaremos mas
socket_Alice.cerrar() 

# 4 ------------------------

# Recibe el mensaje
json_M2 = socket_KDC.recibir()
c_a_hex, mac_a_hex, nonce_a_hex, c_b_hex, mac_b_hex, nonce_b_hex  = json.loads(json_M2)


# Separamos la parte que puede leer Alice
cifrado_clave_a = bytearray.fromhex(c_a_hex)
mac_a = bytearray.fromhex(mac_a_hex)
nonce_a = bytearray.fromhex(nonce_a_hex)

# Desciframos la parte que puede leer Alice
ticket_kerberos = funciones_aes.descifrarAES_GCM(KAT, nonce_a, cifrado_clave_a, mac_a)

timestamp,l,clave_ab,id_Bob=json.loads(ticket_kerberos)

# Comprobamos que el mensaje es reciente
if time.time() - timestamp <= l:
	# Si es reciente le enviamos a Bob su parte.
	msg_3 = []
	msg_3.append(cifrado_clave_b.hex())
	msg_3.append(mac_b.hex())
	msg_3.append(nonce_b.hex())
	json_msg_3 = json.dumps(msg_3)
	socket_Bob.enviar(json_msg_3.encode("utf-8"))
# --------------------------
