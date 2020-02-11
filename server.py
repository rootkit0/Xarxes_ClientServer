"""
USAGE
    server.py [-c <config_file>] [-u <auth_file>] [-d debug mode]
AUTHOR
    Xavier Berga Puig <xbp1@alumnes.udl.cat>
LICENSE
    This software is published under the GNU Public License GPLv3
    https://www.github.com/rootkit0/Practica_Xarxes
"""
#!/usr/bin/python

import sys
import getopt
import socket
import random
import struct
import threading
import time

# Fase registre
REGISTER_REQ = 0x00
REGISTER_ACK = 0x01
REGISTER_NACK = 0x02
REGISTER_REJ = 0x03
ERROR = 0x09

# Fase alive
ALIVE_INF = 0x10
ALIVE_ACK = 0x11
ALIVE_NACK = 0x12
ALIVE_REJ = 0x13

# Paquets send
SEND_FILE = 0x20
SEND_ACK = 0x21
SEND_NACK = 0x22
SEND_REJ = 0x23
SEND_DATA = 0x24
SEND_END = 0x25

# Paquets get
GET_FILE = 0x30
GET_ACK = 0x31
GET_NACK = 0x32
GET_REJ = 0x33
GET_DATA = 0x34
GET_END = 0x35

class clients:
    def __init__(self):
        self.nom = []
        self.mac = []
        self.ip_client = []
        self.num_aleatori = []
        self.estat = []

class pdu:
    def __init__(self):
        self.tipus_paquet = 0x00
        self.nom = []
        self.mac = []
        self.num_aleatori = []
        self.dades = []

def datasending_udp(sockfd, address, tipus_paq, nom, mac, num_aleatori, dades):
    paquet = struct.pack('B7s13s7s50s', tipus_paq, nom, mac, num_aleatori, dades)
    sockfd.sendto(paquet, address)

def datasending_tcp(connection, tipus_paq, nom, mac, num_aleatori, dades):
    paquet = struct.pack('B7s13s7s150s', tipus_paq, nom, mac, num_aleatori, dades)
    connection.sendall(paquet)

def dataparsing_udp(data):
    dades = struct.unpack('B7s13s7s50s', data)
    trama = []
    for element in dades:
        trama.append(str(element).split('\x00')[0])
    parsed = pdu()
    parsed.tipus_paquet = hex(int(trama[0]))
    parsed.nom = trama[1]
    parsed.mac = trama[2]
    parsed.num_aleatori = trama[3]
    parsed.dades = trama[4]
    return parsed

def dataparsing_tcp(data):
    dades = struct.unpack('B7s13s7s150s', data)
    trama = []
    for element in dades:
        trama.append(str(element).split('\x00')[0])
    parsed = pdu()
    parsed.tipus_paquet = hex(int(trama[0]))
    parsed.nom = trama[1]
    parsed.mac = trama[2]
    parsed.num_aleatori = trama[3]
    parsed.dades = trama[4]
    return parsed

def llegir_comandes():
    while(True):
        line = raw_input()
        #Comanda list
        if(line == "list"):
            print("Nom"+"\t""MAC"+"\t""IP"+"\t""Nombre aleatori"+"\t"+"Estat").expandtabs(18)
            for i in range(0, len(info_clients.nom)):
                print(info_clients.nom[i]+"\t"+info_clients.mac[i]+"\t"+info_clients.ip_client[i]+"\t"+info_clients.num_aleatori[i]+"\t"+info_clients.estat[i]).expandtabs(18)
        #Comanda quit
        elif(line == "quit"):
            #Tanco els sockets
            socket_tcp.close()
            socket_udp.close()
            #Tanco els threads
            for i in range(0, len(threads)):
                threads[i].join()
            #Tanco el servidor
            sys.exit(1)
        else:
            print("Comanda no reconeguda")

def peticions_tcp(id_client):
    while(True):
        connection, address = socket_tcp.accept()
        data = connection.recv(1024)
        data = dataparsing_tcp(data)
        #SEND_CONF
        if(data.tipus_paquet == "0x20"):
            if(data.nom == info_clients.nom[id_client] and data.mac == info_clients.mac[id_client] and info_clients.estat[id_client] == "ALIVE"):
                if(data.num_aleatori == info_clients.num_aleatori[id_client]):
                    arxiu_nom = data.nom + ".cfg"
                    datasending_tcp(connection, SEND_ACK, data.nom, data.mac, data.num_aleatori, arxiu_nom)
                    print(time.strftime("%H:%M:%S: MSG.  => Acceptada peticio SEND de l'arxiu configuracio per l'equip " + arxiu_nom))
                    f = open(arxiu_nom, "w")
                    data = connection.recv(178)
                    data = dataparsing_tcp(data)
                    #Guardo les dades rebudes a l0arxiu de configuracio
                    while(data.tipus_paquet != "0x25"):
                        f.write(data.dades)
                        data = connection.recv(178)
                        data = dataparsing_tcp(data)
                        if(debug):
                            print(time.strftime("%H:%M:%S: DEBUG.  => Dades del paquet GET_DATA rebudes: " + data.dades))
                    f.close()
                    print(time.strftime("%H:%M:%S: MSG.  => Arxiu de configuracio per l'equip " + arxiu_nom + " rebut"))
                else:
                    datasending_tcp(connection, SEND_NACK, "", "000000000000", "000000", "Nombre aleatori incorrecte, paquet SEND_NACK")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet SEND_NACK a l'equip " + data.nom + " amb mac " + data.mac))
            else:
                datasending_tcp(connection, SEND_REJ, "", "000000000000", "000000", "Equip no autoritzat, paquet SEND_REJ")
                if(debug):
                    print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet SEND_REJ a l'equip " + data.nom + " amb mac " + data.mac))              
        #GET_CONF
        if(data.tipus_paquet == "0x30"):
            if(data.nom == info_clients.nom[id_client] and data.mac == info_clients.mac[id_client] and info_clients.estat[id_client] == "ALIVE"):
                if(data.num_aleatori == info_clients.num_aleatori[id_client]):
                    arxiu_nom = data.nom + ".cfg"
                    datasending_tcp(connection, GET_ACK, data.nom, data.mac, data.num_aleatori, arxiu_nom)
                    print(time.strftime("%H:%M:%S: MSG.  => Acceptada peticio GET de l'arxiu de configuracio per l'equip"))
                    f = open(arxiu_nom, "r")
                    #Envio l'arxiu de configuracio linia per linia
                    for line in f:
                        datasending_tcp(connection, GET_DATA, data.nom, data.mac, data.num_aleatori, line)
                        if(debug):
                            print(time.strftime("%H:%M:%S: DEBUG.  => Dades de l'arxiu de configuracio enviades: " + data.dades))
                    datasending_tcp(connection, GET_END, data.nom, data.mac, data.num_aleatori, "")
                    print(time.strftime("%H:%M:%S: MSG.  => Finalitzat enviament de l'arxiu de configuracio per l'equip"))
                else:
                    datasending_tcp(connection, GET_NACK, "", "000000000000", "000000", "Nombre aleatori incorrecte, paquet SEND_NACK")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet SEND_NACK a l'equip " + data.nom + " amb mac " + data.mac))
            else:
                datasending_tcp(connection, GET_REJ, "", "000000000000", "000000", "Equip no autoritzat, paquet SEND_REJ")
                if(debug):
                    print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet SEND_REJ a l'equip " + data.nom + " amb mac " + data.mac))   

def tractar_paquet(data, address):
    #ID_CLIENT
    id_client = info_clients.mac.index(data.mac)
    #Paquet REGISTER_REQ
    if(data.tipus_paquet == "0x0"):
        if(data.nom == info_clients.nom[id_client] and data.mac == info_clients.mac[id_client]):
            if(debug):
                print(time.strftime("%H:%M:%S: DEBUG.  => Rebut REGISTER_REQ de l'equip " + data.nom + " amb mac " + data.mac))
            if(info_clients.estat[id_client] == "DISCONNECTED"):
                if(data.num_aleatori == "000000"):
                    info_clients.num_aleatori[id_client] = str(random.randint(100000, 999999))
                    datasending_udp(socket_udp, address, REGISTER_ACK, data.nom, data.mac, info_clients.num_aleatori[id_client], str(tcp_port))
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat REGISTER_ACK a l'equip " + data.nom + " amb mac " + data.mac))
                    info_clients.estat[id_client] = "REGISTERED"
                    info_clients.ip_client[id_client] = "127.0.0.1"
                    print(time.strftime("%H:%M:%S: MSG.  => Equip " + info_clients.nom[id_client] + " passa a estat: " + info_clients.estat[id_client]))
                else:
                    datasending_udp(socket_udp, address, REGISTER_NACK, "000000", "000000000000", "000000", "Nombre aleatori incorrecte, enviant paquet REGISTER_NACK")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet REGISTER_NACK a l'equip " + data.nom + " amb mac " + data.mac))
            elif(info_clients.estat[id_client] == "REGISTERED" or info_clients.estat[id_client] == "ALIVE"):
                if(data.num_aleatori == info_clients.num_aleatori[id_client]):
                    datasending_udp(socket_udp, address, REGISTER_ACK, data.nom, data.mac, info_clients.num_aleatori[id_client], str(tcp_port))
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet REGISTER_ACK a l'equip " + data.nom + " amb mac " + data.mac))
                    info_clients.estat[id_client] = "REGISTERED"
                    print(time.strftime("%H:%M:%S: MSG.  => Equip " + info_clients.nom[id_client] + " passa a estat: " + info_clients.estat[id_client]))
                else:
                    datasending_udp(socket_udp, address, REGISTER_NACK, "000000", "000000000000", "000000", "Nombre aleatori incorrecte, enviant paquet REGISTER_NACK")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet REGISTER_NACK a l'equip " + data.nom + " amb mac " + data.mac))
        else:
            datasending_udp(socket_udp, address, REGISTER_REJ, "000000", "000000000000", "000000", "Equip no autoritzat, paquet REGISTER_REJ")
            if(debug):
                print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet REGISTER_REJ a l'equip " + data.nom + " amb mac " + data.mac))
    #Paquet ALIVE_INF
    if(data.tipus_paquet == "0x10"):
        if(data.nom == info_clients.nom[id_client] and data.mac == info_clients.mac[id_client]):
            if(debug):
                print(time.strftime("%H:%M:%S: DEBUG.  => Rebut ALIVE_INF de l'equip " + data.nom + " amb mac " + data.mac))
            if(data.num_aleatori == info_clients.num_aleatori[id_client]):
                if(info_clients.estat[id_client] == "REGISTERED"):
                    info_clients.estat[id_client] = "ALIVE"
                    print(time.strftime("%H:%M:%S: MSG.  => Equip " + data.nom + " passa a estat: " + info_clients.estat[id_client]))
                    datasending_udp(socket_udp, address, ALIVE_ACK, data.nom, data.mac, info_clients.num_aleatori[id_client], "")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat ALIVE_ACK a l'equip " + data.nom + " amb mac " + data.mac))
                    t = threading.Thread(target=peticions_tcp, args=(id_client,))
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Creat thread per a gestionar les peticions TCP"))
                    t.start()
                    threads.append(t)
                elif(info_clients.estat[id_client] == "ALIVE"):
                    datasending_udp(socket_udp, address, ALIVE_ACK, data.nom, data.mac, info_clients.num_aleatori[id_client], "")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat ALIVE_ACK a l'equip " + data.nom + " amb mac " + data.mac))
                else:
                    datasending_udp(socket_udp, address, ALIVE_REJ, "000000", "000000000000", "000000", "Equip no registrat, paquet ALIVE_REJ")
                    if(debug):
                        print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet ALIVE_REJ a l'equip " + data.nom + " amb mac " + data.mac))
            else:
                datasending_udp(socket_udp, address, ALIVE_NACK, "000000", "000000000000", "000000", "Nombre aleatori incorrecte, paquet ALIVE_NACK")
                if(debug):
                    print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet ALIVE_NACK a l'equip " + data.nom + " amb mac " + data.mac))
        else:
            datasending_udp(socket_udp, address, ALIVE_REJ, "000000", "000000000000", "000000", "Equip no autoritzat, paquet ALIVE_REJ")
            if(debug):
                print(time.strftime("%H:%M:%S: DEBUG.  => Enviat paquet ALIVE_REJ a l'equip " + data.nom + " amb mac " + data.mac))

def main(argv):
    #Llegeixo els parametres
    cfg_file = 'server.cfg'
    auth_file = 'equips.dat'
    global debug
    debug = False
    opts, args = getopt.getopt(argv, "d:c:u:")
    for opt, arg in opts:
        if opt == '-d':
            debug = True
        elif opt == '-c':
            cfg_file = arg
        elif opt == '-u':
            auth_file = arg
    if(debug):
        print(time.strftime("%H:%M:%S: DEBUG.  => Llegits parametres linia de comandes"))
    #Obro l'arxiu de configuracio
    server_cfg = open(cfg_file, "r")
    word = server_cfg.readline().split()
    global nom_server
    nom_server = word[1]
    word = server_cfg.readline().split()
    global mac_server
    mac_server = word[1]
    word = server_cfg.readline().split()
    global udp_port
    udp_port = int(word[1])
    word = server_cfg.readline().split()
    global tcp_port
    tcp_port = int(word[1])
    if(debug):
        print(time.strftime("%H:%M:%S: DEBUG.  => Llegits parametres arxiu de configuracio"))
    #Obro l'arxiu d'equips autoritzats
    auth_macs = open(auth_file, "r")
    global info_clients
    info_clients = clients()
    for line in auth_macs:
        word = line.split()
        info_clients.nom.append(word[0])
        info_clients.mac.append(word[1])
        info_clients.ip_client.append("")
        info_clients.num_aleatori.append("")
        info_clients.estat.append("DISCONNECTED")
    if(debug):
        print(time.strftime("%H:%M:%S: DEBUG.  => Llegits equips autoritzats en el sistema"))
    #Defineixo la IP on escoltara el servidor
    localip = "localhost"
    #Obro el socket UDP
    global socket_udp
    socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_udp.bind((localip, udp_port))
    if(debug):
        print(time.strftime("%H:%M:%S: DEBUG.  => Socket UDP actiu"))
    #Obro el socket TCP
    global socket_tcp
    socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_tcp.bind((localip, tcp_port))
    socket_tcp.listen(1)
    if(debug):
        print(time.strftime("%H:%M:%S: DEBUG.  => Socket TCP actiu"))
    #Estructura on emmagatzemare els threads
    global threads
    threads = []
    #Creo un thread per a tractar les comandes del servidor
    threading.Thread(target=llegir_comandes).start()
    #Llegeixo els paquets que arriben pel socket_udp
    while(True):
        data, address = socket_udp.recvfrom(1024)
        data = dataparsing_udp(data)
        #Obro un thread per a tractar cada paquet
        t = threading.Thread(target=tractar_paquet, args=(data, address))
        if(debug):
            print(time.strftime("%H:%M:%S: DEBUG.  => Creat thread per a gestionar el paquet"))
        t.start()
        #Emmagatzemo el thread creat
        threads.append(t)

if __name__ == "__main__":
    main(sys.argv[1:])