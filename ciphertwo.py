# -*- coding: utf-8 -*-
"""
Chiffrement de type SPN sur 2 tours
"""

import numpy as np
from random import randint


##################### Cryptage #######################

def function(liste):
    """
    Entrée : liste d'entiers associcée à une permutation
    Sortie : fonction associée à cette permutation
    """
    return lambda x: liste[x]


def inverse(liste):
    """
    Entrée : liste d'entiers associcée à une permutation
    Sortie : fonction associée à l'inverse de cette permutation
    """
    return lambda x: liste.index(x)


cipherdoc = [6, 4, 0xc, 5, 0, 7, 2, 0xe, 1, 0xf, 3, 0xd, 8, 0xa, 9, 0xb]
cipher2 = [1, 5, 13, 11, 8, 14, 4, 0, 15, 6, 9, 2, 12, 3, 10, 7]
cipher3 = [7, 1, 2, 15, 5, 14, 11, 8, 13, 9, 3, 6, 0, 10, 12, 4]
cipher4 = [5, 7, 8, 1, 2, 10, 11, 14, 9, 3, 13, 12, 15, 0, 6, 4]


def CipherTwo(S, m, k0, k1, k2):
    """
    Entrée : fonction de permutation, message, 3 entiers
    Sortie : message crypté
    """
    return S(S(m ^ k0) ^ k1) ^ k2


################ Décryptage ########################

def diffdistrib(S):
    """
    Entrée : fonction de permutation
    Sortie : tableau de distribution des différences de cette fonction
    """
    InLength = 16
    OutLength = 16
    tab = np.zeros((InLength, OutLength), int)
    for m0 in range(0, InLength):
        for m1 in range(0, OutLength):
            XOR_IN = m0 ^ m1           # Différence d'entrée
            XOR_OUT = S(m0) ^ S(m1)    # Différence de sortie
            tab[XOR_IN, XOR_OUT] += 1
    return tab


def maxtab(tab):
    """
    Entrée : tableau d'entiers de dimension 2
    Sortie : coordonées du max, max du tableau
    """
    MAX = 0
    X, Y = 0, 0
    for i in range(1, tab.shape[0]):
        for j in range(1, tab.shape[1]):
            if tab[i, j] > MAX:
                MAX = tab[i, j]
                X, Y = i, j
    return X, Y, MAX


def calculk2(liste, k0, k1, k2):
    """
    Entrée : liste d'une permutation, 3 entiers
    Sortie : k2cal et nombre de passages dans la boucle while nécessaires
    """
    S = function(liste)
    R = inverse(liste)

    ensemblek2 = set(x for x in range(0, 16))    # Ensemble des valeurs possibles de k1
    tab = diffdistrib(S)
    nbpassage = 0
    while len(ensemblek2) > 1:
        XOR_IN, XOR_OUT, proba = maxtab(tab)
        compteur = [0] * 16

        for k2exp in range(0, 16):
            for m0 in range(0, 16):
                m1 = m0 ^ XOR_IN
                c0, c1 = CipherTwo(S, m0, k0, k1, k2), CipherTwo(S, m1, k0, k1, k2)

                x0exp, x1exp = c0 ^ k2exp, c1 ^ k2exp
                w0exp, w1exp = R(x0exp), R(x1exp)
                v0expv1exp = w0exp ^ w1exp

                if v0expv1exp == XOR_OUT:
                    compteur[k2exp] += 1

        ensemble = set()
        for i in range(0, 16):           # Filtrage des valeurs
            if compteur[i] == proba:     # Maximum proba
                ensemble.add(i)

        ensemblek2 = ensemblek2 & ensemble
        tab[XOR_IN, XOR_OUT] = 0         # Pour choisir une autre proba au prochain passage
        nbpassage += 1

    k2cal = ensemblek2.pop()
    return k2cal, nbpassage


def calculk1(liste, k0, k1, k2, k2cal):
    """
    Nécessite d'avoir calculé la valeur de k2 auparavant (-> fonction k2cal)
    Sortie : k1cal
    """
    S = function(liste)
    R = inverse(liste)
    ensemblek1 = set(x for x in range(0, 16))    # Ensemble des valeurs possibles de k1

    while len(ensemblek1) > 1:
        m0, m1 = paire()
        c0, c1 = CipherTwo(S, m0, k0, k1, k2), CipherTwo(S, m1, k0, k1, k2)
        u0u1 = m0 ^ m1
        x0, x1 = c0 ^ k2cal, c1 ^ k2cal
        w0, w1 = R(x0), R(x1)
        ensemble = set()

        for t in range(0, 16):
            v0exp = t ^ w0
            v1exp = t ^ w1
            u0exp = R(v0exp)
            u1exp = R(v1exp)

            if u0exp ^ u1exp == u0u1:
                ensemble.add(t)
        ensemblek1 = ensemblek1 & ensemble  # Intersection des ensembles

    k1cal = ensemblek1.pop()
    return k1cal


def calculk0(liste, k0, k1, k2, k1cal, k2cal):
    """
    Nécessite d'avoir calculé k2 et k1 auparavant (-> k1cal et k2cal)
    Sortie : k0cal
    """
    S = function(liste)
    R = inverse(liste)

    m = randint(0, 15)
    c = CipherTwo(S, m, k0, k1, k2)
    x = c ^ k2cal
    w = R(x)
    v = w ^ k1cal
    u = R(v)
    k0cal = m ^ u
    return k0cal


def decrypt(liste, k0, k1, k2):
    """
    Entrée : liste d'une permutation, 3 entiers
    Sortie : k0cal, k1cal, k2cal
    """
    k2cal = calculk2(liste, k0, k1, k2)[0]
    k1cal = calculk1(liste, k0, k1, k2, k2cal)
    k0cal = calculk0(liste, k0, k1, k2, k1cal, k2cal)
    return k0cal, k1cal, k2cal


############## Outils ##################

def paire():
    """
    Sortie : deux entiers distincts entre 0 et 15 compris
    """
    a = randint(0, 15)
    b = randint(0, 15)
    while b == a:
        b = randint(0, 15)
    return a, b


def maxliste(liste):
    """
    Entrée : liste d'entiers
    Sortie : indice du maximum de la liste
    """
    N = len(liste)
    MAX = 0
    indice = 0
    for i in range(0, N):
        if liste[i] > MAX:
            MAX = liste[i]
            indice = i
    return indice


def meilleurpermut(N):
    """
    Entrée : entier N
    Sortie : liste d'une permutation, max du tableau de distribution des
    différences de cette permutation
    A partir de N permutations, cherche la permutation qui a son max du tableau
    de distribution des différences le plus grand
    """
    permu = []
    maxdif = []
    for i in range(0, N):
        cipher = np.random.permutation(16)
        S = function(cipher)
        permu.append(cipher)
        maxdif.append(maxtab(diffdistrib(S))[2])
    indicemax = maxliste(maxdif)
    return permu[indicemax], maxdif[indicemax]


def permutdiffmax(diffmaxdemande):
    """
    Entrée : entier
    Sortie : liste d'une permutation telle que le max du tableau de distribution
    des différences soit l'entier diffmaxdemande
    """
    diffmax = 0
    cipher = []
    while diffmax != diffmaxdemande:
        cipher = np.random.permutation(16)
        S = function(cipher)
        diffmax = maxtab(diffdistrib(S))[2]
    return cipher.tolist()


def test(N):
    """
    Entrée : entier
    Calcule N permutations aléatoires
    Pour chaque permutation :
        Calcul du max du tableau de distribution des différences -> maxdiff
        Execution de la fonction calculk2 pour k2 dans [0,15]
        Comptage du nombre d'erreurs des valeurs k2 calculés
        Comptage du nombre de passage dans la boucle while de calculk2 nécessaires
    Sortie : liste du nb d'erreurs moyen par permutation et par k2, en fonction de maxdiff
             liste du nombre de permutations utilisées, en fonction de maxdiff
             liste du nb de passages moyen par permutation et par k2, en fonction de maxdiff
    """
    k0 = 5
    k1 = 7

    nberreur = np.zeros(16)
    nbpermut = np.zeros(16, int)
    nbpassage = np.zeros(16)

    for i in range(0, N):
        cipher = np.random.permutation(16)
        cipher = cipher.tolist()
        maxdiff = maxtab(diffdistrib(function(cipher)))[2]
        nbpermut[maxdiff] += 1

        for k2 in range(0, 16):
            k2cal, nb = calculk2(cipher, k0, k1, k2)
            if k2cal != k2:
                nberreur[maxdiff] += 1
            nbpassage[maxdiff] += nb

    return nberreur / (nbpermut * 16), nbpermut, nbpassage / (nbpermut * 16)


def test2(N):
    """
    Idem fonction test(N), mais ici, N permutations par maxdiff
    """
    k0 = 5
    k1 = 7

    nberreur = np.zeros(16)
    nbpermut = np.zeros(16, int)
    nbpassage = np.zeros(16)

    for i in range(0, N):
        E = [4, 6, 8, 10, 12]
        for maxdiff in E:
            cipher = permutdiffmax(maxdiff)
            nbpermut[maxdiff] += 1

            for k2 in range(0, 16):
                k2cal, nb = calculk2(cipher, k0, k1, k2)
                if k2cal != k2:
                    nberreur[maxdiff] += 1
                nbpassage[maxdiff] += nb

    return nberreur / (nbpermut * 16), nbpermut, nbpassage / (nbpermut * 16)


def exception(maxdiff):
    k0 = 5
    k1 = 7
    while True:
        try:
            cipher = permutdiffmax(maxdiff)
            for k2 in range(0, 16):
                k2cal, nb = calculk2(cipher, k0, k1, k2)
        except KeyError:
            print(cipher, k2)
            break


cipher = [2, 15, 13, 7, 8, 5, 0, 1, 12, 6, 3, 14, 10, 11, 9, 4]  # erreur voir fichier erreur
k0 = 5
k1 = 7
k2 = 0
