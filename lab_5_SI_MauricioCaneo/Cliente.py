#Mauricio Caneo Catalan
#Universidad Finis Terrae
#Asignatura: Seguridad Informatica
#Profesor: Manuel Alba
#Laboratorio Evaluado N°5

#El cliente es Jonathan.
import socket
import random 
import sys
from Crypto.Cipher import DES
from secrets import token_bytes

cl_socket = socket.socket()
cl_socket.connect(('localhost',8000))

while True:
    #Crea Llave diffie hellman (Kb).
    #Escribimos el mensaje al servidor.
    mensaje = input("Escribe un numero primo : ")
    K = input("Escribe un numero menor al anterior : ")
    #Guardamos K y P.
    P = int(mensaje)
    print("P = ",P)
    Num_K = int(K)
    print("K = ",K)
    #Genera un numero random menor a P.
    b = random.randint(1, P-1)
    #Generamos la llave para Jonathan.
    B = ((pow(int(K), b)) % P)
    print("B = ",B)
    #Enviamos mensaje que seria P.
    cl_socket.send(mensaje.encode())
    #Enviamos mensaje que seria K.
    cl_socket.send(K.encode())
    #Recibo A.
    A = cl_socket.recv(1024).decode()
    #Calculo clave secreta
    Kb = ((pow(int(A), b)) % P)
    print("CLave Secreta de Jonathan  = ",Kb)
    #Envio B desde el cliente.
    num_B = str(B)
    cl_socket.send(num_B.encode())

    #Lee el texto con el mensaje.
    #Abrir el archivo de texto.
    MensajeEntrada = open("mensajeentrada.txt","r+",encoding="utf-8")
    msg = MensajeEntrada.read()
    #Cierra el archivo de texto.
    MensajeEntrada.close

    #Enviar clave secreta del cliente al servidor.
    Clave_cliente = str(Kb) 
    cl_socket.send(Clave_cliente.encode())
    print("enviando clave Df/Hellman al servidor...")

    #Cifrado DES.
    key = token_bytes(8)

    def CifradoDES(msg):
        cifrado = DES.new(key, DES.MODE_EAX)
        nonce = cifrado.nonce
        ciphertext, tag = cifrado.encrypt_and_digest(msg.encode('ascii'))
        return nonce, ciphertext, tag
    
    #Cifrado del mensaje leido.
    nonce, ciphertext, tag = CifradoDES(msg)
    print(f'\nTexto Cifrado con DES : {ciphertext}')

    #Enviar mensaje cifrado del texto leido hacia el servidor junto con la clave de diffie hellman obtenida.
    cl_socket.send(ciphertext)
    print("Texto cifrado enviado al servidor...")

    #Enviar variables para el decifrado.
    cl_socket.send(nonce)
    print(f'\nnonce : {nonce}')
    cl_socket.send(tag)
    print(f'\ntag : {tag}')
    cl_socket.send(key)
    print(f'\nkey : {key}')

    print("\nvariables enviadas..")

    #Descifrado DES.
    def descifradoDES(nonce, ciphertext, tag):
        cifrado = DES.new(key, DES.MODE_EAX, nonce=nonce)
        plaintext = cifrado.decrypt(ciphertext)

        try:
            cifrado.verify(tag)
            return plaintext.decode('ascii')
        except:
            return False
    
    textoDescifrado = descifradoDES(nonce, ciphertext, tag)
    print(f'Texto descifrado : {textoDescifrado}')

    #Funcion para Crear el archivo de texto con el mensaje cifrado dentro.
    def ArchivoCifrado(textoDescifrado):
        mensajeSalida = open("mensajerecibido.txt","w+",encoding="utf-8")
        mensajeSalida.write(textoDescifrado)
        mensajeSalida.close()

    #Crear archivo.
    ArchivoCifrado(textoDescifrado)

    #Cerramos el socket del cliente.
    print("\nCerrando Socket...")
    cl_socket.close()
    sys.exit()
