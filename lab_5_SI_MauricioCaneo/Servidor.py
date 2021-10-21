#Mauricio Caneo Catalan
#Universidad Finis Terrae
#Asignatura: Seguridad Informatica
#Profesor: Manuel Alba
#Laboratorio Evaluado N°5

#El servidor es Mauricio.
import socket
import random
import sys
from Crypto import Cipher 
from Crypto.Cipher import DES
from secrets import token_bytes


sv_socket = socket.socket()
sv_socket.bind(('localhost',8000))
sv_socket.listen()

while True:
    #Se establece la conexion.
    conexion, direccion = sv_socket.accept()
    print("Conectado con el cliente", direccion)

    #Recibimos el numero P del cliente.
    MensajeR = conexion.recv(1024).decode()
    #Guardamos el numero recibido en la variable P.
    P = int(MensajeR)
    print("P = ",P)
    #Recibimos el numero K del cliente.
    MensajeK = conexion.recv(1024).decode() 
    #Guardamos el numero recibido en la variable K.
    K = int(MensajeK)
    print("K = ",K)
    #Genera un numero random menor a P.
    a = random.randint(1, P-1)
    #Generamos la llave para Mauricio.
    A = ((pow(K, a)) % P) 
    #Envio A.
    print("A = ", A)
    num_A = str(A)
    conexion.send(num_A.encode())
    #Recibo B desde del cliente.
    B = conexion.recv(1024).decode()
    #Calculo clave secreta.
    Ka = ((pow(int(B), a)) % P)
    print("CLave Secreta de Mauricio  = ",Ka)

    print("Leyendo clave secreta del cliente...")
    #Leer clave secreta del cliente.
    ciphertext = conexion.recv(1024).decode()
    print("Clave secreta Cliente : ", ciphertext)
    print("Clave secreta Servidor : ", Ka)

    #Comparamos las claves para verificar si son iguales.
    if (ciphertext == str(Ka)):
        print("Claves diffie hellman correctas...")
        #Leer mensaje recibido desde el cliente.
        Texto_CifradoDES = conexion.recv(1024)
        print("\nTexto recibido Cifrado con DES : ",Texto_CifradoDES)

        #Leer variables del cliente.
        nonce = conexion.recv(16)
        print(f'\nnonce : {nonce}')
        tag = conexion.recv(8)
        print(f'\ntag : {tag}')
        key = conexion.recv(8)
        print(f'\nkey : {key}')

        print("\nvariables recibidas..")


    else:
        print("saliendo del progrma...")
        sys.exit()
    print("\nDesconectado el cliente", direccion)
    #Cerramos conexion.
    conexion.close()

    
