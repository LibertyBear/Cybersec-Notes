def cifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if(cadena[i] == " "):
            ordenCifrado = ord(" ")
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        #para minusculas
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + 3) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def decifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if(cadena[i] == " "):
            ordenCifrado = ord(" ")
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) - 3) % 26) + 65
        #para minusculas
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) - 3) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESARMAY = 'VENI VIDI VINCI AURIA'
print(claroCESARMAY)
cifradoCESARMAY = cifradoCesarAlfabetoInglesMAY(claroCESARMAY) 
print(cifradoCESARMAY)
decifradoCESARMAY = decifradoCesarAlfabetoInglesMAY(cifradoCESARMAY) 
print(decifradoCESARMAY)

claroCESARMAY = 'veni vidi vinci auria'
print(claroCESARMAY)
cifradoCESARMAY = cifradoCesarAlfabetoInglesMAY(claroCESARMAY) 
print(cifradoCESARMAY)
decifradoCESARMAY = decifradoCesarAlfabetoInglesMAY(cifradoCESARMAY) 
print(decifradoCESARMAY)


def cifradoCesarAlfabetoInglesGen(cadena, secreto):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        val = ord(secreto[i%len(secreto)])
        if(cadena[i] == " "):
            ordenCifrado = ord(" ")
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + val - 65 + 1) % 26) + 65
        #para minusculas
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + val - 97 + 1) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def decifradoCesarAlfabetoInglesGen(cadena, secreto):
    """Devuelve un cifrado Cesar tradicional (+3)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        val = ord(secreto[i%len(secreto)])
        ordenCifrado = 0
        if(cadena[i] == " "):
            ordenCifrado = ord(" ")
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) - val + 65 - 1) % 26) + 65
        #para minusculas
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) - val + 97 - 1) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado


claroCESARMAY = 'VENI VIDI VIncI AURIA'
print(claroCESARMAY)
cifradoCESARMAY = cifradoCesarAlfabetoInglesGen(claroCESARMAY, "pupa" ) 
print(cifradoCESARMAY)
decifradoCESARMAY = decifradoCesarAlfabetoInglesGen(cifradoCESARMAY, "pupa") 
print(decifradoCESARMAY)
