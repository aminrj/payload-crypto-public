Voici le schéma exact et complet de la formidable architecture réseau et cryptographique que vous venez de construire.

Il se divise en deux parties : la **Topologie Réseau** (comment les machines sont connectées) et la **Transformation du Paquet** (ce que fait votre module noyau).

### 1. La Topologie Réseau (Laboratoire Dual-Bridge)

Ce schéma représente l'infrastructure créée par `setup_bridge_sim.sh`. Les routeurs L2 (Bridges) sont totalement invisibles (sans IP) et chiffrent le trafic à la volée.

```text
       (Zone LAN - Clair)                (Zone WAN - Chiffrée)               (Zone LAN - Clair)
 
 ┌──────────────────────┐        ┌────────────────────────────────┐        ┌──────────────────────┐
 │      ns_host_a       │        │   ns_bridge1      ns_bridge2   │        │      ns_host_b       │
 │   (Client Source)    │        │  (Chiffreur)     (Déchiffreur) │        │ (Serveur Destination)│
 │                      │        │                                │        │                      │
 │ IP: 10.0.0.1/24      │        │ Bridge: br1        Bridge: br2 │        │ IP: 10.0.0.2/24      │
 │ MSS Clamping: 1428   │        │                                │        │ MSS Clamping: 1428   │
 └──────────┬───────────┘        └─────┬────────────────────┬─────┘        └──────────┬───────────┘
            │                          │                    │                         │
     [ MTU 1468 bytes ]         [ MTU 1500 ]         [ MTU 1500 ]             [ MTU 1468 bytes ]
            │                          │                    │                         │
        (veth-a0)                  (veth-a1)            (veth-c0)                 (veth-c1)
            │                          │                    │                         │
            ├────────(Câble 1)─────────┤                    ├────────(Câble 3)────────┤
                                       │                    │
                                   (veth-b0)            (veth-b1)
                                       │                    │
                                       └───( Câble 2 WAN )──┘
                                       [ CÂBLE SOUS ÉCOUTE ]
                                       [   MTU 1500 bytes  ]

==================================================================================================
 LE TRAJET D'UN PAQUET (ALLER) :
==================================================================================================
 1. HOST A génère des données utiles. Max 1428 octets (grâce au TCP MSS).
 2. HOST A crée un paquet IP de 1468 octets maximum. Il l'envoie sur veth-a0.
 3. BRIDGE 1 reçoit 1468 octets. 
    ➔ iptables intercepte la sortie vers veth-b0.
    ➔ Appel de xt_TRANS3 (--mode e).
    ➔ Le paquet grossit à 1500 octets (+32 octets crypto).
 4. Le paquet chiffré (1500 octets) voyage sur le Câble 2 (WAN). 
    ➔ Un hacker qui écoute ici ne voit que du bruit absolu (XChaCha20).
 5. BRIDGE 2 reçoit 1500 octets.
    ➔ iptables intercepte l'entrée depuis veth-b1.
    ➔ Appel de xt_TRANS3 (--mode d).
    ➔ Le paquet est authentifié (Poly1305), déchiffré, et réduit à 1468 octets.
 6. HOST B reçoit le paquet en clair parfait (1468 octets).

```

---

### 2. La Transformation Cryptographique (xt_TRANS3)

Voici ce que votre code `xt_TRANS3_main.c` fait subir au paquet au niveau de la mémoire du noyau (RAM).

**A. Le Paquet Original (En clair - 1468 octets max)**

```text
┌────────┬────────┬──────────────────────────────────────────┐
│ IP hdr │ L4 hdr │ Payload (Données de l'application)       │
│  20 B  │  20 B  │ Jusqu'à 1428 octets                      │
└────────┴────────┴──────────────────────────────────────────┘

```

**B. Le Paquet Chiffré par votre module (Sur le câble WAN - 1500 octets max)**

```text
┌────────┬────────┬──────────────────────────────────────────┬────────┬────────┐
│ IP hdr │ L4 hdr │ Ciphertext (Payload + Séquence 8B)       │ MAC    │ RNONCE │
│  20 B  │  20 B  │ Jusqu'à 1436 octets                      │ 16 B   │ 8 B    │
└────────┴────────┴──────────────────────────────────────────┴────────┴────────┘
                  |←────────────────────────────────────────→|        |
                         Chiffré par XChaCha20                        |
                  |←─────────────────────────────────────────────────→|
                     Authentifié par le MAC Poly1305 (incluant la     |
                     signature cachée "NEGENCRY.TRANS3.V1")           |
                                                                      |
                     Envoyé en clair (Aléatoire pur). Sert à ─────────┘
                     dériver le Nonce pour le déchiffrement.

```

---

### 3. Les 3 Piliers de l'Optimisation (Ce qui rend ce module professionnel)

Pour que ce schéma fonctionne à plusieurs Gigabits par seconde sans s'effondrer (comme vous l'avez vu avec `iperf3`), nous avons implémenté 3 mécanismes vitaux dans l'infrastructure virtuelle :

1. **L'Asymétrie MTU :** Le fait que le LAN soit réglé à 1468 et le WAN à 1500 permet au module d'ajouter ses 32 octets de sécurité sans jamais forcer le noyau Linux à fragmenter les paquets.
2. **Architecture Lockless & Multi-Queues :** Les câbles virtuels ont `numtxqueues 4 numrxqueues 4`. Couplé au **RPS (Receive Packet Steering)**, cela permet aux 4 cœurs de votre processeur de chiffrer 4 paquets en même temps, tout en garantissant qu'ils restent dans le bon ordre.
3. **Queues Géantes (txqueuelen 10000) & CUBIC :** Les buffers réseau sont volontairement surdimensionnés pour absorber les micro-ralentissements dus à la cryptographie sans détruire les paquets (Tail Drop), ce qui évite l'effondrement de l'algorithme TCP.

Vous avez construit un VPN de Couche 2 (L2) complet, furtif, et "Zéro-Copie" en mémoire. C'est un travail d'ingénierie système remarquable !
