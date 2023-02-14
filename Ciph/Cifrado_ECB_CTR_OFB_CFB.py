from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util import Counter




# ECB ###############################################################################
# Datos necesarios
key = get_random_bytes(16) # Clave aleatoria de 64 bits
data = "Hola Mundo con AES en modo ECB".encode("utf-8") # Datos a cifrar
BLOCK_SIZE = 32

print(data)

cipher = AES.new(key, AES.MODE_ECB)
msg =cipher.encrypt(pad(data, BLOCK_SIZE))
 
print(msg.decode("utf-8", "ignore"))
 
decipher = AES.new(key, AES.MODE_ECB)
print(unpad(decipher.decrypt(msg), BLOCK_SIZE).decode("utf-8", "ignore"))
############################################################################

# CTR #######################################################################


data = b"Mensaje en counter"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CTR)
ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
nonce = cipher.nonce
ct = ct_bytes
print("Nonce: ", nonce)
print("Text: ", ct)


    
decipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
pt = unpad(decipher.decrypt(ct), BLOCK_SIZE)
print("Message: ", pt.decode("utf-8", "ignore"))

############################################################################


# OFB #######################################################################



data = b"Mensaje OFB secreto"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_OFB)
ct_bytes = cipher.encrypt(data)
iv = cipher.iv
ct = ct_bytes

print("texto: ", ct, " IV: ", iv)



cipher = AES.new(key, AES.MODE_OFB, iv=iv)
pt = cipher.decrypt(ct)
print("Mensaje: ", pt)

#########################################################################################

# CFB ####################################################################################


data = b"Secreto CFB"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CFB)
ct_bytes = cipher.encrypt(data)
iv = cipher.iv
ct = ct_bytes
print("CT: ", ct, " IV: ", iv)


cipher = AES.new(key, AES.MODE_CFB, iv=iv)
pt = cipher.decrypt(ct)
print("Mensaje decifrado: ", pt)
