# network_analyser

options :

-i <interface> : interface for live analysis
-o <file> : input file for offline analysis
-f <filter> : GMP filter (optional)
-v <1..3> : level of verbosity (1=very concise; 2=concise; 3=complete)
-l <number> : number of packet, set to 1000 by default

supported protocols :

ethernet,
 IP,
 UDP,
 TCP,
 
 
 

# analyseur réseau

options :

-i <interface> : interface pour l’analyse live
-o <fichier> : fichier d’entrée pour l’analyse offline
-f <filtre> : filtre BPF (optionnel)
-v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)
-l <nombre> : nombre de paquet, positionné à 1000 par défaut

protocols supportés :

ethernet,
 IP,
 UDP,
 TCP,
 


à faire :

 ARP,
applications comme : BOOTP et DHCP, DNS, HTTP, FTP, SMTP, etc.
