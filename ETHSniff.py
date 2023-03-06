import os
import socket #Création de connexions
from struct import * #Manipulation de types de variable en détail
from termcolor import colored

prompt = "/ ETHSniff \ >>> "
taille_paquet_ethernet = 14 #Taille d'un paquet

#Retourne la chaîne contenant l'adresse MAC
def mac(adresse):
	#%.2 : Deux premiers (x: bits/hexadécimal)
	string = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (adresse[0], adresse[1], adresse[2], adresse[3], adresse[4], adresse[5])
	return string

def main():
	os.system("clear")
	print(colored(banner,"cyan"))
	print(colored(title, "yellow"))
	print(colored("[!!] Fonctionne uniquement sous linux !\n","red",attrs=['bold']))

	try:
		#Manipulation de paquet au niveau des protocoles
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	except:
		print(colored("[ERREUR] La socket n'a pas pu être crée.","red"))
		exit(1)

	nb_paquets = 1
	while True:
		#Récupération de paquet du port 65535
		paquet = s.recvfrom(65535)
		paquet = paquet[0] #<-- Taille du paquet

		header = paquet[:taille_paquet_ethernet]

		#Découpe en paquets de 6 bits
		ethernet = unpack('!6s6sH',header)
		protocole = socket.ntohs(ethernet[2])

		print(colored(prompt+"["+str(nb_paquets)+"] ~ @MAC " + mac(paquet[6:12]) + " --> " + mac(paquet[0:6]) + " [PROTOCOLE: "+str(protocole)+"]", "green"))
		nb_paquets += 1

banner=("  _____ _____ _   _ ____        _  __  __\n"+
" | ____|_   _| | | / ___| _ __ (_)/ _|/ _|\n"+
" |  _|   | | | |_| \___ \| '_ \| | |_| |_\n"+
" | |___  | | |  _  |___) | | | | |  _|  _|\n"+
" |_____| |_| |_| |_|____/|_| |_|_|_| |_|\n")
title="Ethernet packets sniffer by b64-Sm9yZGFuIExBSVJFUw\n\n"
main()

