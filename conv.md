> **Question**
> 
> 2.3 Sujet 3 : Forge de signature RSA par faute
>  2.3.1 Classification
> Difficulté : Très difficile
> Catégorie : Cryptographie / Mathématique
>  2.3.2 Contexte
> En 2006, Bleichenbacher a démontré qu'une vérification incorrecte du padding PKCS#1 v1.5 dans
> les signatures RSA (notamment dans certaines implémentations SSL/TLS) permettait de forger des
> signatures valides sans connaître la clé privée, en exploitant la malléabilité de RSA.
> 
> Explique en détail le principe de cette attaque 


L'attaque de Bleichenbacher (présentée en 2006) vise certaines implémentations défectueuses de la vérification des signatures RSA utilisant le format PKCS#1 v1.5. Elle ne casse pas RSA lui-même, mais exploite une validation trop permissive du bloc signé.

## 1. Rappel : signature RSA PKCS#1 v1.5

Pour signer un message (M) :

1. On calcule son condensat :
$$
   h = H(M)
$$

2. On construit un bloc encodé (EM) de taille égale au module RSA :

$$
EM = 00 ; || ; 01 ; || ; FF \ldots FF ; || ; 00 ; || ; ASN.1(H) ; || ; h
$$

où :

* `00 01` indique une signature PKCS#1 v1.5.
* une longue suite de `FF` remplit le bloc.
* `ASN.1(H)` identifie l'algorithme de hachage.
* `h` est le hash du message.

3. La signature est :

$$
s = EM^d \pmod n
$$

La vérification consiste à calculer :

$$
EM' = s^e \pmod n
$$

et à vérifier que tout le bloc respecte exactement le format PKCS#1.

---

## 2. L'erreur d'implémentation

Certaines bibliothèques anciennes effectuaient une vérification incomplète :

Elles vérifiaient seulement :

* présence de `00 01`
* quelques octets `FF`
* séparateur `00`
* présence d'un ASN.1 correct
* hash correct

mais **sans vérifier que le reste du bloc était exactement conforme**.

Exemple :

```
00 01 FF FF 00 ASN1 HASH GARBAGE GARBAGE GARBAGE
```

était accepté alors qu'il devrait être rejeté.

Cette faiblesse est la clé de l'attaque.

---

## 3. Pourquoi l'exposant public e = 3 est important

À l'époque, beaucoup de certificats utilisaient :

$$
e = 3
$$

La vérification calcule alors :

$$
s^3 \pmod n
$$

L'attaquant cherche une valeur (s) telle que $s^3$ commence par un bloc ressemblant à un encodage PKCS#1 valide.

Si le vérificateur ne contrôle pas la totalité du bloc, cela suffit.

---

## 4. Idée fondamentale

Supposons un module RSA de 1024 bits.

Un bloc PKCS#1 correct ressemble à :

```
00 01 FF FF FF FF FF FF 00 ASN1 HASH ....
```

L'attaquant construit artificiellement un entier :

$$
B
$$

dont les bits de poids fort contiennent exactement cette structure :

```
00 01 FF FF 00 ASN1 HASH
```

et dont tous les bits restants sont libres.

Comme les bits de fin ne sont jamais vérifiés par l'implémentation vulnérable, ils peuvent contenir n'importe quoi.

---

## 5. Recherche d'une racine cubique

L'attaquant construit :

$$
B
$$

de façon à ce qu'il soit proche d'un cube parfait :

$$
B \approx x^3
$$

Puis il calcule :

$$
s = \lfloor \sqrt[3]{B} \rfloor
$$

Alors :

$$
s^3
$$

commence par :

```
00 01 FF FF 00 ASN1 HASH
```

mais la fin est incorrecte.

Une implémentation rigoureuse rejetterait :

```
00 01 FF FF 00 ASN1 HASH XXXXXXXX
```

Une implémentation vulnérable accepte parce qu'elle ne regarde que le début.

---

## 6. Exemple simplifié

Supposons qu'une vérification naïve accepte :

```
00 01 FF 00 HASH
```

sans vérifier le reste.

L'attaquant choisit :

```
00 01 FF 00 HASH AAAAAAAA...
```

et cherche un cube parfait proche :

$$
x^3
$$

Si :

$$
x^3 =
00 01 FF 00 HASH BBBBBBBB...
$$

alors la signature candidate est simplement :

$$
s=x
$$

La vérification calcule :

$$
s^3
$$

retrouve le préfixe attendu et accepte la signature.

Aucune clé privée n'a été utilisée.

---

## 7. Pourquoi cela fonctionne mathématiquement

Le bloc PKCS#1 occupe principalement les bits de poids fort.

Les bits de poids faible sont ignorés par la vérification vulnérable.

Or modifier légèrement les bits de poids faible change peu la racine cubique.

Ainsi on peut :

1. Fixer les bits de tête pour obtenir un format PKCS#1 crédible.
2. Laisser libres les bits de queue.
3. Trouver un entier dont le cube possède exactement ce préfixe.

L'attaque devient particulièrement facile avec :

$$
e = 3
$$

car la racine cubique est simple à manipuler.

Avec :

$$
e = 65537
$$

la même approche devient impraticable.

---

## 8. Conditions nécessaires

L'attaque nécessite simultanément :

### Exposant faible

Typiquement :

$$
e=3
$$

### Vérification laxiste

Par exemple :

* ne vérifie pas toute la chaîne ASN.1,
* n'impose pas la longueur exacte,
* ignore des octets après le hash,
* accepte un padding partiel.

### Signature PKCS#1 v1.5

Les schémas modernes comme RSA-PSS ne sont pas vulnérables à cette attaque.

---

## 9. Impact historique

Cette vulnérabilité a affecté plusieurs implémentations de :

* SSL/TLS,
* bibliothèques cryptographiques,
* produits embarqués,
* logiciels de validation de certificats X.509.

Une signature forgée pouvait permettre :

* l'usurpation d'identité numérique,
* l'acceptation de certificats frauduleux,
* le contournement de mécanismes d'authentification.

---

## 10. Contre-mesures

Les protections actuelles sont :

1. Vérification stricte de l'intégralité du bloc PKCS#1 v1.5.
2. Rejet du moindre octet inattendu.
3. Utilisation de :

   * RSA-PSS,
   * exposant public (e = 65537).
4. Comparaison constante et complète du format encodé.

En résumé, l'attaque de Bleichenbacher 2006 exploite une vérification incomplète du format PKCS#1 v1.5. Avec un exposant faible ((e=3)), l'attaquant construit un entier dont le cube commence par un encodage de signature apparemment valide. Si l'implémentation ne vérifie que ce préfixe et ignore le reste du bloc, elle accepte une signature forgée sans que l'attaquant ne possède la clé privée.

> **Question**
> 
> Explique plus en détail RSA PKCS pour une personne non experte en cryptographie. Comment la signature est crée ? Comment est elle vérifiée ?


Pour comprendre l'attaque, il faut d'abord comprendre précisément ce qu'est une signature RSA PKCS#1 v1.5.

---

# 1. Le but d'une signature numérique

Une signature numérique sert à répondre à deux questions :

1. **Qui a créé ce document ?**
2. **Le document a-t-il été modifié ?**

C'est l'équivalent numérique d'une signature manuscrite, mais vérifiable mathématiquement.

---

# 2. Les clés RSA

RSA utilise deux clés :

* une **clé privée** (secrète)
* une **clé publique** (connue de tous)

La clé privée sert à signer.

La clé publique sert à vérifier.

On note généralement :

* (n) : le module RSA
* (d) : l'exposant privé
* (e) : l'exposant public

---

# 3. Pourquoi on ne signe pas directement le message

Imaginons un document :

```text
Je promets de payer 1000 €
```

RSA travaille sur des nombres.

On commence donc par calculer une empreinte (hash) :

$$
h = SHA256(message)
$$

Par exemple :

```text
A3F7C8...
```

Cette empreinte possède deux propriétés :

* elle est beaucoup plus courte que le document ;
* la moindre modification du document change complètement l'empreinte.

Ainsi :

```text
Je promets de payer 1000 €
```

et

```text
Je promets de payer 10000 €
```

produisent des hashes totalement différents.

---

# 4. Pourquoi le hash seul ne suffit pas

Supposons :

```text
Hash = A3F7C8...
```

Si on signait simplement ce hash avec RSA, il existerait plusieurs problèmes mathématiques.

PKCS#1 v1.5 ajoute donc une structure stricte autour du hash.

---

# 5. Construction du bloc PKCS#1 v1.5

Supposons une clé RSA de 1024 bits.

Cela représente :

```text
1024 / 8 = 128 octets
```

Le bloc signé doit faire exactement 128 octets.

On construit alors :

```text
00 01 FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF
00 ASN1 HASH
```

---

## Le sens des octets

### 00 01

Début obligatoire :

```text
00 01
```

qui signifie :

```text
Ceci est une signature PKCS#1 v1.5
```

---

### FF FF FF ...

Une longue série :

```text
FF FF FF FF ...
```

qui sert de remplissage.

---

### 00

Séparateur :

```text
00
```

indiquant :

```text
Le remplissage est terminé.
```

---

### ASN.1

Petit identifiant précisant l'algorithme utilisé.

Par exemple :

```text
SHA-1
```

ou

```text
SHA-256
```

---

### HASH

Enfin :

```text
A3F7C8...
```

l'empreinte du document.

---

# 6. Exemple simplifié

Imaginons un mini RSA de jouet.

Le bloc pourrait ressembler à :

```text
00 01 FF FF FF 00 SHA256 ABCD
```

En réalité il est beaucoup plus long.

---

# 7. Transformation en nombre

L'ordinateur interprète ce bloc comme un entier géant.

Par exemple :

```text
0001FFFF00010203ABCD...
```

devient :

$$
m
$$

un très grand nombre.

---

# 8. Création de la signature

Le propriétaire applique sa clé privée :

$$
s = m^d \pmod n
$$

où :

* (m) = bloc PKCS#1
* (d) = clé privée

Le résultat :

$$
s
$$

est la signature.

---

Visuellement :

```text
Document
    ↓
Hash
    ↓
Bloc PKCS#1
    ↓
RSA avec clé privée
    ↓
Signature
```

---

# 9. Vérification

Le vérificateur possède :

* le document
* la signature
* la clé publique

Il calcule :

$$
m' = s^e \pmod n
$$

C'est l'opération inverse.

---

Il récupère alors quelque chose comme :

```text
00 01 FF FF FF FF FF
00 ASN1 HASH
```

---

# 10. Recalcul du hash

Le vérificateur recalcule :

$$
h = SHA256(document)
$$

à partir du document reçu.

---

# 11. Comparaison

Il vérifie que :

```text
HASH dans le bloc
=
HASH calculé
```

et que tout le format est correct.

Si oui :

```text
Signature valide
```

Sinon :

```text
Signature invalide
```

---

# 12. Analogie avec un tampon officiel

Imagine :

```text
[Début officiel]
[Remplissage officiel]
[Type de document]
[Empreinte]
```

La vérification doit contrôler **tout le tampon**.

Une implémentation correcte vérifie :

```text
[Début]
[Remplissage]
[Séparateur]
[Type]
[Hash]
[Fin exacte]
```

---

# 13. Là où l'erreur apparaît

Certaines implémentations anciennes faisaient seulement :

```text
Le document commence-t-il par :

00 01 FF ... 00 ASN1 HASH ?
```

Si oui :

```text
Accepté
```

Elles ignoraient le reste.

---

Par exemple :

```text
00 01 FF FF 00 ASN1 HASH
XXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXX
```

était accepté.

Alors qu'il aurait fallu vérifier que les `X` n'existent pas.

---

# 14. Pourquoi cela permet une forge

La sécurité RSA garantit essentiellement :

> Il est difficile de produire exactement un bloc PKCS#1 valide sans la clé privée.

Mais si le vérificateur accepte :

```text
00 01 FF FF 00 ASN1 HASH
n'importe quoi ensuite
```

alors l'attaquant n'a plus besoin de construire un bloc parfait.

Il lui suffit d'en fabriquer un qui **commence correctement**.

Comme beaucoup de bits deviennent libres, il peut chercher un nombre dont le cube (pour (e=3)) possède ce préfixe.

Cette liberté supplémentaire est précisément ce qui rend possible l'attaque de Bleichenbacher 2006.

> **Question**
> 
> Donne un exemple complet de l'utilisation de cette faille

Je peux donner un exemple **pédagogique et simplifié** montrant le mécanisme, mais pas un mode d'emploi permettant de forger réellement des signatures contre des systèmes vulnérables.

---

# Situation

Supposons un vérificateur RSA défectueux qui n'effectue que les contrôles suivants :

1. le bloc commence par `00 01`
2. il contient ensuite quelques `FF`
3. il trouve un séparateur `00`
4. il trouve un hash correct

Tout ce qui suit est ignoré.

---

# Message à signer

Le message est :

```text
Autoriser Alice
```

Le vérificateur calcule :

```text
HASH = 1234
```

(pour simplifier, on utilise un faux hash très court).

---

# Ce qu'une vraie signature devrait produire

Après l'opération RSA publique :

```text
signature^e mod n
```

on devrait obtenir :

```text
00 01 FF FF FF FF 00 HASH=1234
```

et rien d'autre.

---

# Vérification correcte

Une implémentation sérieuse compare tout le bloc :

```text
00 01 FF FF FF FF 00 HASH=1234
```

Si un seul octet diffère :

```text
00 01 FF FF FF FF 00 HASH=1235
```

la signature est rejetée.

---

# Vérification vulnérable

Supposons maintenant que le programme fasse seulement :

```pseudo
si bloc commence par
    00 01 FF
et contient
    00 HASH=1234
alors accepter
```

Le reste n'est jamais examiné.

---

# Ce que voit le programme

Le programme accepte :

```text
00 01 FF FF 00 HASH=1234 ZZZZZZZZZZZ
```

ou

```text
00 01 FF FF 00 HASH=1234 AAAAAAAAAAA
```

ou

```text
00 01 FF FF 00 HASH=1234 98765432109
```

alors que ces blocs sont invalides selon PKCS#1.

---

# Ce que fait l'attaquant

Il veut fabriquer une signature sans clé privée.

Il construit d'abord un bloc cible :

```text
00 01 FF FF 00 HASH=1234
XXXXXXXXXXXXXXX
```

Les X représentent une zone libre.

---

# Pourquoi cette zone libre aide

Dans RSA avec :

$$
e=3
$$

la vérification calcule :

$$
s^3 \pmod n
$$

L'attaquant cherche donc un entier (s) dont le cube ressemble à :

```text
00 01 FF FF 00 HASH=1234
XXXXXXXXXXXXXXX
```

Il n'a pas besoin que le bloc soit parfait.

Il a seulement besoin que le début soit correct.

---

# Analogie décimale

Imaginons que le vérificateur accepte tout nombre commençant par :

```text
12345
```

Il ignore les chiffres suivants.

Ces nombres sont donc tous acceptés :

```text
123450000000
123451111111
123459999999
123457654321
```

L'attaquant a énormément de liberté.

Il peut alors chercher un cube parfait proche :

```text
4979³ = 123406539739
```

ou

```text
4980³ = 123480792000
```

ou un autre cube commençant par la séquence désirée.

Le principe mathématique est identique : on ne cherche plus un bloc exact, seulement un préfixe.

---

# Vue d'ensemble de l'attaque

Normalement :

```text
Bloc PKCS#1 exact
        ↓
racine RSA privée
        ↓
Signature
```

Sans la clé privée, impossible.

---

Avec le bug :

```text
Préfixe PKCS#1 correct
+ beaucoup de bits libres
        ↓
chercher un cube proche
        ↓
obtenir une valeur s
        ↓
s³ commence correctement
        ↓
signature acceptée
```

---

# Pourquoi cela a été particulièrement grave

À l'époque, beaucoup d'implémentations :

* utilisaient PKCS#1 v1.5 ;
* utilisaient l'exposant public (e=3) ;
* validaient mal le padding.

Bleichenbacher a montré qu'un attaquant pouvait alors produire une signature qui passait la vérification sans connaître la clé privée, simplement parce que le logiciel ne vérifiait pas strictement tout le bloc PKCS#1.

L'idée essentielle n'est donc pas « casser RSA », mais **transformer un problème impossible (fabriquer exactement le bloc attendu) en un problème beaucoup plus facile (fabriquer seulement un bloc qui commence correctement)**.

> **Question**
> 
> m′=s^e(mod n)
> Explique cette étape plus en détail. Pourquoi est-ce l'opération inverse de la signature ? Pourquoi cela permet d'obtenir bloc PKCS à partir de la signature ? Comment e est il choisi ? Pourquoi le fait que e soit public n'est pas une vulnérabilité ? 


Ce sont les questions fondamentales pour comprendre RSA. Repartons du début.

# 1. Que représente réellement une signature RSA ?

Une signature RSA est simplement un nombre.

Lors de la signature, on commence par construire le bloc PKCS#1 :

```text
00 01 FF FF FF ... 00 ASN1 HASH
```

Ce bloc est interprété comme un très grand entier :

$$
m
$$

Par exemple (nombre fictif) :

$$
m = 123456789
$$

La signature est alors :

$$
s = m^d \pmod n
$$

où :

* (d) = exposant privé
* (n) = module RSA

Le résultat (s) est la signature.

---

# 2. Pourquoi la vérification utilise-t-elle (e) ?

La clé publique RSA contient :

$$
(n,e)
$$

Le vérificateur calcule :

$$
m' = s^e \pmod n
$$

L'objectif est de retrouver le bloc original (m).

---

# 3. Pourquoi cela fonctionne ?

Toute la magie de RSA repose sur une propriété mathématique.

Les exposants (d) et (e) sont choisis de sorte que :

$$
ed \equiv 1 \pmod{\varphi(n)}
$$

où ($\varphi(n)$) est la fonction d'Euler.

Autrement dit :

$$
ed = 1 + k\varphi(n)
$$

pour un certain entier (k).

---

Grâce au théorème d'Euler :

$$
m^{\varphi(n)} \equiv 1 \pmod n
$$

on obtient :

$$
\begin{aligned}
m^{ed}
&= m^{1+k\varphi(n)} \\
&= m\left(m^{\varphi(n)}\right)^k \\
&\equiv m \pmod n
\end{aligned}
$$

Donc :

$$
\begin{aligned}
(m^d)^e
&= m^{de} \\
&\equiv m \pmod n
\end{aligned}
$$

---

C'est exactement la raison pour laquelle :

$$
s^e \equiv m
$$

puisque

$$
s = m^d
$$

---

# 4. Petit exemple numérique

Les vrais nombres RSA font plusieurs centaines de chiffres.

Prenons un mini exemple.

Choisissons :

$$
n = 33
$$

Supposons :

$$
e=3
$$

et

$$
d=7
$$

(car ($3\times7=21\equiv1\pmod{20}$)).

---

Message :

$$
m=4
$$

Signature :

$$
s = 4^7 \pmod{33}
$$

Calcul :

$$
4^7=16384
$$

$$
16384 \bmod 33 = 16
$$

Donc :

$$
s=16
$$

---

Vérification :

$$
s^e=16^3
$$

$$
4096 \bmod 33 = 4
$$

On retrouve :

$$
m'=4
$$

exactement le message d'origine.

---

# 5. Pourquoi retrouve-t-on le bloc PKCS ?

Parce que le bloc PKCS est précisément le nombre (m).

Avant signature :

```text
00 01 FF FF ... 00 ASN1 HASH
```

↓

converti en entier :

$$
m
$$

↓

signé :

$$
s=m^d \pmod n
$$

---

À la vérification :

$$
s^e \pmod n
$$

redonne :

$$
m
$$

qui est ensuite réinterprété en octets :

```text
00 01 FF FF ... 00 ASN1 HASH
```

Le vérificateur peut alors contrôler le contenu.

---

# 6. Comment choisit-on (e) ?

Le générateur de clés RSA :

1. choisit deux grands nombres premiers (p) et (q)
2. calcule :

$$
n=pq
$$

3. calcule :

$$
\varphi(n)=(p-1)(q-1)
$$

4. choisit un exposant public (e)

5. calcule :

$$
d=e^{-1}\pmod{\varphi(n)}
$$

c'est-à-dire l'inverse modulaire de (e).

---

Aujourd'hui on utilise presque toujours :

$$
e = 65537
$$

car :

* suffisamment grand pour éviter certaines attaques ;
* suffisamment petit pour que les vérifications restent rapides.

---

# 7. Pourquoi utilisait-on parfois (e=3) ?

Historiquement :

$$
e=3
$$

était populaire parce que :

$$
s^3
$$

est très rapide à calculer.

À l'époque où les processeurs étaient beaucoup plus lents, cela était considéré comme un avantage.

---

Cependant :

$$
e=3
$$

facilite certaines attaques lorsque le protocole ou l'implémentation contient une erreur.

C'est précisément ce qui intervient dans l'attaque de Bleichenbacher.

---

# 8. Pourquoi (e) public n'est-il pas un problème ?

C'est souvent le point qui paraît contre-intuitif.

Tout le monde connaît :

$$
e
$$

et

$$
n
$$

mais personne ne connaît :

$$
d
$$

---

Pour fabriquer une signature valide, il faut calculer :

$$
m^d \pmod n
$$

Or (d) ne peut pas être retrouvé facilement à partir de (e) et (n).

---

Pour calculer (d), il faudrait connaître :

$$
\varphi(n)
$$

et donc factoriser :

$$
n=pq
$$

en retrouvant (p) et (q).

---

Avec un RSA moderne de 2048 bits :

```text
n = p × q
```

où chaque facteur possède environ 300 chiffres décimaux.

Aucun algorithme connu ne permet de factoriser efficacement un tel nombre sur des ordinateurs classiques.

---

# 9. Pourquoi l'attaque de Bleichenbacher ne casse-t-elle pas RSA ?

C'est un point très important.

L'attaquant ne cherche jamais à calculer :

$$
d
$$

Il ne casse pas :

$$
s = m^d \pmod n
$$

Il exploite simplement un vérificateur qui accepte des blocs mal formés.

En quelque sorte :

```text
RSA : toujours solide
↓
Implémentation du contrôle : défectueuse
↓
Signature forgée acceptée
```

La vulnérabilité est dans la validation du bloc PKCS#1, pas dans le mécanisme mathématique RSA lui-même.

---

Résumé :

* Le bloc PKCS#1 est transformé en un entier (m).
* La signature est $s=m^d \pmod n$.
* La vérification calcule $s^e \pmod n$.
* Grâce à la relation spéciale entre $(e)$ et $(d)$, on retrouve exactement $(m)$.
* Le bloc PKCS original réapparaît et peut être contrôlé.
* (e) est public par conception ; la sécurité repose sur le fait qu'il est extrêmement difficile de retrouver (d) sans factoriser (n).
* L'attaque de Bleichenbacher exploite une vérification PKCS#1 incorrecte, pas une faiblesse fondamentale de RSA.

> **Question**
> 
> Choisissons :
> n=33
> Supposons :
> e=3
> et
> d=7
> (car 3×7=21≡1(mod20)).
> 
> Pourquoi mod 20 ?


Excellente question.

Le modulo 20 vient de la fonction d'Euler $(\varphi(n))$.

Dans RSA, (d) n'est pas choisi arbitrairement. Il doit vérifier :

$$
e \times d \equiv 1 \pmod{\varphi(n)}
$$

où $(\varphi(n))$ dépend de la factorisation de (n).

---

## Étape 1 : factoriser (n)

Dans l'exemple :

$$
n = 33
$$

Or :

$$
33 = 3 \times 11
$$

Donc :

$$
p=3,\quad q=11
$$

---

## Étape 2 : calculer $(\varphi(n))$

Pour RSA :

$$
\varphi(n) = (p-1)(q-1)
$$

Donc :

$$
\varphi(33)=(3-1)(11-1)
$$

$$
=2\times10
$$

$$
=20
$$

C'est pour cela que le modulo est 20.

---

## Étape 3 : choisir (e)

On choisit :

$$
e=3
$$

Il faut que (e) soit premier avec $(\varphi(n))$ :

$$
\gcd(3,20)=1
$$

C'est le cas.

---

## Étape 4 : trouver (d)

On cherche un nombre (d) tel que :

$$
3d \equiv 1 \pmod{20}
$$

Autrement dit :

$$
3d = 1 + 20k
$$

pour un entier (k).

Essayons quelques valeurs :

* (d=1) → (3)
* (d=3) → (9)
* (d=5) → (15)
* (d=7) → (21)

et :

$$
21 = 1 + 20
$$

donc :

$$
21 \equiv 1 \pmod{20}
$$

Ainsi :

$$
d=7
$$

---

## Pourquoi a-t-on besoin de cette propriété ?

Parce que :

$$
ed = 21 = 1 + 20
$$

et comme :

$$
20=\varphi(33)
$$

on obtient :

$$
ed = 1 + \varphi(n)
$$

(ici (k=1)).

Lors de la vérification :

$$
\begin{aligned}
(m^d)^e &= m^{ed} \\
         &= m^{21} \\
         &= m^{1+20} \\
         &= m(m^{20})
\end{aligned}
$$

Or le théorème d'Euler dit que pour tout (m) premier avec 33 :

$$
m^{20}\equiv1\pmod{33}
$$

Donc :

$$
\begin{aligned}
m^{21}
&= m(m^{20}) \\
&\equiv m \cdot 1 \\
&\equiv m \pmod{33}
\end{aligned}
$$

On retrouve le message initial.

---

## Intuition

On peut voir (d) comme le « déverrouilleur » mathématique de (e).

Si (e) est l'opération :

$$
x \mapsto x^3 \pmod{33}
$$

alors (d) est choisi pour être l'opération inverse :

$$
x \mapsto x^7 \pmod{33}
$$

car :

$$
\begin{aligned}
(x^7)^3
&= x^{21} \\
&\equiv x \pmod{33}
\end{aligned}
$$

Grâce au choix de (d), l'exponentiation par (d) puis par (e) ramène au point de départ.

C'est exactement le mécanisme qui permet à la clé privée ((d)) de signer et à la clé publique ((e)) de vérifier.
