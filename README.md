# network_analyser

options :

-i <interface> : interface for live analysis
-o <file> : input file for offline analysis
-f <filter> : GMP filter (optional)
-v <1..4> : level of verbosity (1=very concise; 2=concise; 3=complete 4=full_frame)
-l <number> : number of packet to analyse, by default the analyse stops when there's no more packet


supported protocols :

 ethernet,
 ARP,
 IP,
 UDP,
 TCP,
 BOOTP
 DNS, 
 HTTP, 
 FTP, 
 SMTP,
 IMAP,
 POP,
 
 
 

# analyseur réseau

options :

-i <interface> : interface pour l’analyse live
-o <fichier> : fichier d’entrée pour l’analyse offline
-f <filtre> : filtre BPF (optionnel)
-v <1..4> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet 4=trames complètes)
-l <nombre> : nombre de paquet à analyser, par défaut, l'analyse se poursuit tant qu'il y a des paquets.


protocols supportés :

 ethernet,
 ARP,
 IP,
 UDP,
 TCP,
 BOOTP
 DNS, 
 HTTP, 
 FTP, 
 SMTP,
 IMAP,
 POP,

