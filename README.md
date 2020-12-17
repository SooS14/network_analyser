# network_analyser


-> open the "network_analyser" directory and use make to compile.
-> the generated binary file is created in the bin folder
-> "frames" directory contains ethernet frames for the tests

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
 
For BOOTP vendors specific and requested parameters list, only the most interesting options have been analysed. The same goes for the commands of SMTP, POP, IMAP ,...



# analyseur réseau


-> ouvrir le répertoire "network_analyser" et utiliser "make" pour compiler.
-> le fichier binaire généré est dans le dossier bin
-> le dossier "frames" contient des captures wireshark pour les tests

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

Concernant la partie vendors specific et parameters request list de BOOTP, seules les options les plus intéressantes ont été traitées. Il en va de même pour SMTP, POP, IMAP...
