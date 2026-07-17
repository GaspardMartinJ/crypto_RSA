• Décrire la structure du padding PKCS#1 v1.5 et la faille exploitée  
• Expliquer la construction mathématique de la forge  
• Proposer la correction : vérification stricte du padding, passage à PSS  
• Analyser quelles implémentations réelles ont été touchées (OpenSSL, NSS…)  

Pour signer un message avec PKCS#1 v1.5, il faut construire un bloc avec une structure spécifique:  
Deux premiers octets: 00 01, préfixe requis pour un bloc PKCS#1 v1.5  
Ensuite: Padding constitué d'octets FF. Le bloc doit faire la même taille que le modulo RSA (n). Le standard est 2048 bit (256 octets), donc la plupart du bloc est constitué de ce padding. Un octet 00 termine le padding.  
Ensuite: le DigestInfo ASN.1(H) est le préfixe désignant l'algorithme de hash utilisé (SHA256 ici)  
Enfin: le hash du message (32 octets)

On signe avec RSA: 
$$s = EM^d \pmod n$$
avec s la signature, EM le bloc décrit au dessus, d l'exposant privé RSA et n le modulo RSA public.

Pour vérifier la signature, on fait l'opération inverse:
$$
EM' = s^e \pmod n
$$
avec (e) l'exposant public (3 ici)

puis on vérifie que le bloc respecte bien la structure demandée.  
La vulnérabilité exploitée par Bleichenbacher est à cette étape. Certains vérificateurs vérifiaient seulement la présence des deux premiers octets, le début du padding, l'octet 00 de terminaison du padding, puis la présence du DigestInfo et du hash, mais sans vérifier leurs positions exactes ni le nombre d'octets de padding.

Ce qu'on peut faire pour exploiter cette vérification, c'est construire le bloc minimal qui passe cette vérification (00 01 FF 00 ASN.1(H) H) puis remplir la fin de 00. Ça donne le plus petit entier qui passe la vérification. Cependant, on veut une signature, pas un bloc EM. On prends la racine cubique de ce bloc (et on prends l'entier supérieur le plus proche si on ne tombe pas sur une racine parfaite).

La différence entre une signature correcte et la notre vient de cet arrondi au supérieur. Techniquement, si le bloc est déja un cube parfait, on pourrait obtenir une signature valide juste en faisant la racine, et la signature passerait même un check strict complet (mais ça a très peu de chance d'arriver).

On pourrait imaginer faire la même chose (racine puis ceil) avec le bloc qui passe une vérification stricte (le bon nombre de padding FF), mais quand on cube notre signature forgée, l'erreur d'arrondi supérieur change les derniers bits du bloc EM (qui correspondent à des bits du hash du message) et la vérification échoue.

Au lieu de ça, dans notre cas l'erreur d'arrondi va se trouver seulement sur des bits non vérifiés parce que la fonction de vérification aura déja trouvé tous les octets qu'elle cherchait.

Dans le cas d'une clé RSA 2048 bits, on a à peu près 200 octets de marge non vérifiés (ça dépends de l'implémentation fautive), donc la signature forgée est accéptée à tous les coups.

Il y a aussi la partie $\pmod n$ de la formule qui pourrait ruiner la structure de notre bloc EM si $s^3 > n$. Cependant, RSA garantit que $2^{2047}<n<2^{2048}$ pour une clé de 2048 bits, et on sait que EM commence par 0001, donc $EM<2^{2045}<n$. Même si $s^3$ est un peu plus grand que EM, il ne peut pas être plus grand que n.

Cette attaque fonctionne seulement pour des (e) très petit. Déja à partir de e=5, l'erreur d'arrondi après l'étape $EM' = s^e \pmod n$ est supérieure au nombre d'octets non vérifiés, donc l'attaque échoue.

Pour les corrections possibles, j'ai mis une fonction de vérification qui vérifie la position exacte de chaque octet qui rejette bien la signature forgée. On peut aussi choisir un (e) plus grand que 3 (65537 est le standard aujourd'hui). De plus, à partir de PKCS#1 v2.1/v2.2, on utilise RSA-PSS (Probabilistic Signature Scheme). Avec ce système, le padding n'est plus fixe, on ajoute un salt donc la signature est différente à chaque fois, même avec le même message.

Il y a eu deux implémentations majeures touchées par cette attaque: OpenSSL et Mozilla's Network Security Services (NSS). Les deux implémentait des vérification trop permissives avec e=3. Pour OpenSSL:  
CVE-2006-4339:  
OpenSSL before 0.9.7, 0.9.7 before 0.9.7k, and 0.9.8 before 0.9.8c, when using an RSA key with exponent 3, removes PKCS-1 padding before generating a hash, which allows remote attackers to forge a PKCS #1 v1.5 signature that is signed by that RSA key and prevents OpenSSL from correctly verifying X.509 and other certificates that use PKCS #1.
impact: falsification de certificats X.509, acceptation de faux certificats SSL/TLS

Pour NSS:  
CVE-2006-4340:  
Mozilla Network Security Service (NSS) library before 3.11.3, as used in Mozilla Firefox before 1.5.0.7, Thunderbird before 1.5.0.7, and SeaMonkey before 1.0.5, when using an RSA key with exponent 3, does not properly handle extra data in a signature, which allows remote attackers to forge signatures for SSL/TLS and email certificates, a similar vulnerability to CVE-2006-4339. NOTE: on 20061107, Mozilla released an advisory stating that these versions were not completely patched by MFSA2006-60. The newer fixes for 1.5.0.7 are covered by CVE-2006-5462.

Plusieurs application étaient basée sur NSS, dont Firefox, SeaMonkey et Thunderbird.  
Un attaquant pouvait créer un faux certificat SSL accepté par le navigateur, et donc effectuer des attaques Man-in-the-Middle.
