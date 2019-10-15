# coding: utf-8
"""
Chiffrement de type SPN sur 4 tours
"""

import numpy as np
import random
import time
import cProfile
import re
import functools  # Mémoïsation
import itertools
import pickle  # Binary protocols
import pandas as pd
import logging

import os
os.environ["PATH"] += r";C:\Program Files (x86)\Graphviz2.38\bin"

# from pycallgraph import PyCallGraph
# from pycallgraph.output import GraphvizOutput


def inverse(liste):
    """
    Input : 16-bit permutation
    Output : Inverse de la permutation
    """
    result = list()
    for i in range(16):
        result.append(liste.index(i))
    return result


def diffdistrib(Sbox):
    """
    Input : Sbox list
    Output : difference distribution table
    """
    InLength = 16
    OutLength = 16
    tab = np.zeros((InLength, OutLength), int)
    for m0 in range(0, InLength):
        for m1 in range(0, OutLength):
            XOR_IN = m0 ^ m1           # Différence d'entrée
            XOR_OUT = Sbox[m0] ^ Sbox[m1]    # Différence de sortie
            tab[XOR_IN, XOR_OUT] += 1
    return tab


def maxtab(tab):
    """
    Entrée : tableau d'entiers de dimension 2
    Sortie : coordonées du max et sa valeur
    """
    MAX = 0
    X, Y = 0, 0
    InLength = 16
    OutLength = 16
    for i in range(1, InLength):
        for j in range(1, OutLength):
            if tab[i, j] > MAX:
                MAX = tab[i, j]
                X, Y = i, j
    return X, Y, MAX


### Février ###


def SboxLayer(state, Sbox):
    """Sbox function (4 Sbox)
    Input:  16-bit integer, Sbox list
    Output: 16-bit integer
    """
    output = 0
    for i in range(4):  # 4 sboxes
        output += Sbox[(state >> (i * 4)) & 0xF] << (i * 4)
    return output


@functools.lru_cache(maxsize=None)  # Mémoïsation, taille du cache infinie
def PboxLayer(state, Pbox):
    """Pbox function (4 Pbox)
    Input: 16-bit integer, Pbox list
    Output: 16-bit integer
    """
    output = 0
    for i in range(16):
        output += ((state >> i) & 0x1) << Pbox[i]
    return output


def CipherFourKnudsen(message, K, Sbox, Pbox):
    """CipherFour function
    Input: 16-bit integer
            K = [k0, k1, k2, k3, k4, k5] (16-bit integer)
            Sbox list, Pbox list
    Output : 16-bit integer
    """
    state = message
    for i in range(4):
        state = state ^ K[i]
        state = SboxLayer(state, Sbox)
        state = PboxLayer(state, Pbox)
    state = state ^ K[4]
    state = SboxLayer(state, Sbox)
    state = state ^ K[5]
    return state


def CipherFourKnudsendec(message, K, Sbox, Pbox):
    """
    Algorithme inverse de CipherFour (décodage normal)
    """
    invSbox = inverse(Sbox)
    invPbox = inverse(Pbox)
    state = message
    state = state ^ K[5]
    state = SboxLayer(state, invSbox)
    for i in range(4):
        state = state ^ K[4 - i]
        state = PboxLayer(state, invPbox)
        state = SboxLayer(state, invSbox)
    state = state ^ K[0]
    return state




########################################
#####  Attack : A tutorial on .... #####
########################################


def Ciphertuto(message, K, Sbox, Pbox):
    """CipherFour function
    Input: 16-bit integer
           K = [k1, k2, k3, k4, k5] (16-bit integer)
           Sbox, Pbox
    Output : 16-bit integer
    """
    state = message
    for i in range(3):
        state = state ^ K[i]
        state = SboxLayer(state, Sbox)
        state = PboxLayer(state, Pbox)
    state = state ^ K[3]
    state = SboxLayer(state, Sbox)
    state = state ^ K[4]
    return state


# def decryptK5partialtuto(n):
#     """
#     Input: nombre de couples de messages à utiliser
#     Output : clé K5 partielle (tuto)
#     """
#     tabk5partial = [0]*256

#     for i in range(n):
#         X = random.randint(0, 65535)
#         Xprim = X ^ deltaP
#         Y = Ciphertuto(X, Ktuto, Sboxtuto, Pboxtuto)
#         Yprim = Ciphertuto(Xprim, Ktuto, Sboxtuto, Pboxtuto)

#         for k5partial in range(256):
#             k5_4 = k5partial & 0b00001111
#             k5_2 = (k5partial & 0b11110000) >> 4

#             V4_X_4 = (Y & 15) ^ k5_4
#             V4_X_2 = (Y >> 8) & 15 ^ k5_2
#             V4_Xprim_4 = (Yprim & 15) ^ k5_4
#             V4_Xprim_2 = (Yprim >> 8) & 15 ^ k5_2

#             U4_X_4 = invSboxtuto[V4_X_4]
#             U4_X_2 = invSboxtuto[V4_X_2]
#             U4_Xprim_4 = invSboxtuto[V4_Xprim_4]
#             U4_Xprim_2 = invSboxtuto[V4_Xprim_2]

#             U4_Xpartial = U4_X_4 + (U4_X_2 << 8)
#             U4_Xprimpartial = U4_Xprim_4 + (U4_Xprim_2 << 8)

#             deltaU4exp = U4_Xpartial ^ U4_Xprimpartial
#             if deltaU4 == deltaU4exp:
#                 tabk5partial[k5partial] += 1

#     return maxliste(tabk5partial)


def maxliste(liste):
    """
    Input: Int liste
    Output: Liste de/des indices de/des élements max de la liste
    """
    max = 0
    maxind = []
    for i in range(len(liste)):
        if liste[i] == max:
            maxind.append(i)
        if liste[i] > max:
            max = liste[i]
            maxind = [i]
    return maxind


### 25/02/19 ###


###############################
#####  Calcul des chemins #####
###############################


def nombreboiteactive(a):
    """
    Input : Différence (16-bit integer)
    Ouput : Nombre de boites activées par cette différence
    """
    resul = 0
    for i in range(0, 4):
        if ((a >> (i * 4)) & 0xF) > 0:
            resul += 1
    return resul


def visualiser(state, proba=1):
    """
    Input : différence (16-bit integer), proba
    """
    print("| ", end='')
    for i in range(0, 16):
        val = (state >> (15 - i)) & 1
        if val == 1:
            print("x ", end='')
        else:
            print("_ ", end='')
        if (i + 1) % 4 == 0:
            print("| ", end='')

    print("", round(proba, 5))

# Exemple
# visualiser(1542, 0.0263671875)


def visualiserliste(liste):
    """
    Input : liste de différences (16-bit integer), probas
    """
    for elem in liste:
        visualiser(elem[0], elem[1])
        print()


def visualiserchemin(chemin):
    """
    Input : chemin = liste de différences (16-bit integer),probas
    """
    n = len(chemin)
    print("════════════════════════════════════════════════════════")
    print()
    for i in range(0, n):
        visualiser(chemin[i][0], chemin[i][1])
        if i % 2 == 0 and i != n - 1:
            nb = nombreboiteactive(chemin[i][0])
            print("                ╔════════╗        ┌───┐     ")
            print("                ║ Sbox", (i // 2) + 1, "║        │", nb, "│")
            print("                ╚════════╝        └───┘     ")
        elif i != n - 1:
            print("                 ╔══════╗              ")
            print("                 ║ Pbox ║              ")
            print("                 ╚══════╝              ")
    nb = nombreboiteactive(chemin[-1][0])
    print("                                   ", nb)
    print("════════════════════════════════════════════════════════")
    print()


# Exemple
# chemintuto = [(2816, 1),
#               (512, 0.5),
#               (64, 0.5),
#               (96, 0.1875),
#               (544, 0.1875),
#               (1360, 0.0263671875),
#               (1542, 0.0263671875)]
# visualiserchemin(chemintuto)


def visualiserlistechemin(listechemin):
    """
    Input : liste de chemins
    """
    n = len(listechemin)
    for i in range(0, n):
        visualiserchemin(listechemin[i])


def visualiserlistefinchemin(liste):
    """
    Input : liste de chemin
    N'affiche que la dernière étape de chaque chemin
    """
    for elem in liste:
        visualiser(elem[-1][0], elem[-1][1])
        print()


def visualiserX(X, Xprim, K, Sbox, Pbox):
    """
    Affiche les différences au cour du cryptage entre les messages X et Xprim
    """
    state = X
    stateprim = Xprim
    chemin = []
    for i in range(3):
        chemin.append((state ^ stateprim, 1))

        state = state ^ K[i]
        stateprim = stateprim ^ K[i]
        state = SboxLayer(state, Sbox)
        stateprim = SboxLayer(stateprim, Sbox)
        chemin.append((state ^ stateprim, 1))

        state = PboxLayer(state, Pbox)
        stateprim = PboxLayer(stateprim, Pbox)

    chemin.append((state ^ stateprim, 1))
    state = state ^ K[3]
    stateprim = stateprim ^ K[3]
    state = SboxLayer(state, Sbox)
    stateprim = SboxLayer(stateprim, Sbox)
    chemin.append((state ^ stateprim, 1))
    state = state ^ K[4]
    stateprim = stateprim ^ K[4]

    # visualiserchemin(chemin)
    return chemin, state, stateprim

## 14/03/19 ##

# global ensemblesortie
# ensemblesortie = set()   # Comptage du nombre d'utilisation pour utilisé mémoisation
# global compteursortie
# compteursortie = 0


# @functools.lru_cache(maxsize=None)  ## Mémoisation  maxsize = infini
# def sortiepossible(deltaIN, difftabtuple):
#     """
#     Input : deltaIN (16 bit), difftabtuple : difference distribution table sous
#             forme de tuple (pour mémosiation hashable)
#     Output : liste des différences (deltaOUT) et de leur probabilité, en sortie
#             d'une couche de Sboxs (correspondant au difftab) avec une
#             différence d'entrée deltaIN SUR UNE ETAPE
#     """
#     # global compteursortie
#     # global ensemblesortie
#     # if deltaIN in ensemblesortie:
#     #     compteursortie += 1
#     # else:
#     #     ensemblesortie.add(deltaIN)

#     deltaINlist = []    # Division de deltaIN en 4 entiers de 4 bits
#     for i in range(0, 4):
#         deltaINlist.append(deltaIN >> ((3-i)*4) & 0xF)

#     def OUTprobable(IN):
#         """
#         Input : différence d'entrée (entier de 4bit)
#         Output : liste des différences possibles (4bit) et de leur probabilité,
#                 en sortie de la Sbox (correspondant au difftab) avec une
#                 différence d'entrée IN et tel que la probabilité soit
#                 >= nbMIN/16
#         """
#         nbMIN = 2
#         resul = []
#         for OUT in range(0, 16):
#             proba = difftabtuple[IN][OUT]
#             if proba >= nbMIN:
#                 resul.append((OUT, proba))
#         return resul

#     OUTresul = []   # Liste de la liste des différences de sorties (4bit)
#                     # et proba pour chaque Sbox
#     for i in range(0, 4):
#         OUTresul.append(OUTprobable(deltaINlist[i]))

#     # def fusionV0(OUTresul):
#     #     """
#     #     Input : Liste de la liste des différences de sorties (4bit) et
#     #             proba pour chaque Sbox
#     #     Output : Liste des différences de sortie (16bit) (toutes les
#     #             combinaisons des sorties 4bits) et probas calculées
#     #     """
#     #     resul = []
#     #     for OUT1 in OUTresul[0]:
#     #         for OUT2 in OUTresul[1]:
#     #             for OUT3 in OUTresul[2]:
#     #                 for OUT4 in OUTresul[3]:
#     #                     OUTlist = [OUT1, OUT2, OUT3, OUT4]
#     #                     OUT16 = 0
#     #                     proba = 1
#     #                     for j in range(0, 4):
#     #                         OUT16 += OUTlist[j][0] << ((3-j)*4)
#     #                         proba *= (OUTlist[j][1])/16
#     #                     resul.append((OUT16, proba))
#     #     return resul

#     # def fusionV1(OUTresul):  ## 14/03/19 ## Suppression append
#     #     """
#     #     Input : Liste de la liste des différences de sorties (4bit) et
#     #             proba pour chaque Sbox
#     #     Output : Liste des différences de sortie (16bit) (toutes les
#     #             combinaisons des sorties 4bits) et probas calculées
#     #     """
#     #     resul = []
#     #     for OUT1 in OUTresul[0]:
#     #         for OUT2 in OUTresul[1]:
#     #             for OUT3 in OUTresul[2]:
#     #                 for OUT4 in OUTresul[3]:
#     #                     OUT16 = (OUT1[0] << 12) + (OUT2[0] << 8) + (OUT3[0] << 4) + OUT4[0]
#     #                     proba = OUT1[1] * OUT2[1] * OUT3[1] * OUT4[1]
#     #                     proba = proba / (16**4)

#     #                     resul.append((OUT16, proba))
#     #     return resul

#     def fusion(OUTresul):  ## 14/03/19 ## Suppression 4 boucles
#         """
#         Input : Liste de la liste des différences de sorties (4bit) et
#                 proba pour chaque Sbox
#         Output : Liste des différences de sortie (16bit) (toutes les
#                 combinaisons des sorties 4bits) et probas calculées
#         """
#         resul = []
#         for OUT1, OUT2, OUT3, OUT4 in itertools.product(OUTresul[0], OUTresul[1], OUTresul[2], OUTresul[3]):
#             OUT16 = (OUT1[0] << 12) + (OUT2[0] << 8) + (OUT3[0] << 4) + OUT4[0]
#             proba = OUT1[1] * OUT2[1] * OUT3[1] * OUT4[1]
#             proba = proba / (16**4)

#             resul.append((OUT16, proba))
#         return resul

#     return fusion(OUTresul)


@functools.lru_cache(maxsize=None)  # Mémoisation, taille du cache infini
def sortiepossible(deltaIN, difftabtuple):
    """
    Input : deltaIN (16 bit), difftabtuple : difference distribution table sous forme de tuple (pour mémosiation hashable)
    Output : liste des différences (deltaOUT) et de leur probabilité, en sortie d'une couche de Sboxs (correspondant au difftab) avec une différence d'entrée deltaIN SUR UNE ETAPE
    """
    deltaINlist = []    # Division de deltaIN en 4 entiers de 4 bits
    for i in range(0, 4):
        deltaINlist.append(deltaIN >> ((3 - i) * 4) & 0xF)

    def OUTprobable(IN):
        """
        Input : différence d'entrée (entier de 4bit)
        Output : liste des différences possibles (4bit) et de leur probabilité, en sortie de la Sbox (correspondant au difftab) avec une différence d'entrée IN et tel que la probabilité soit >= nbMIN/16
        """
        nbMIN = 2
        resul = []
        for OUT in range(0, 16):
            proba = difftabtuple[IN][OUT]
            if proba >= nbMIN:
                resul.append((OUT, proba))
        return resul

    OUTresul = []   # Liste de la liste des différences de sorties (4bit)
                    # et proba pour chaque Sbox
    for i in range(0, 4):
        OUTresul.append(OUTprobable(deltaINlist[i]))

    def fusion(OUTresul):
        """
        Input : Liste de la liste des différences de sorties (4bit) et proba pour chaque Sbox
        Output : Liste des différences de sortie (16bit) (toutes les combinaisons des sorties 4bits) et probas
        """
        resul = []
        for OUT1, OUT2, OUT3, OUT4 in itertools.product(OUTresul[0], OUTresul[1], OUTresul[2], OUTresul[3]):
            OUT16 = (OUT1[0] << 12) + (OUT2[0] << 8) + (OUT3[0] << 4) + OUT4[0]
            proba = OUT1[1] * OUT2[1] * OUT3[1] * OUT4[1]
            proba = proba / (16**4)
            resul.append((OUT16, proba))
        return resul

    return fusion(OUTresul)

# Exemple page 24 "A tutorial on..."
#
# >>> sortiepossible(0b0000101100000000,difftabtuto)
# [(512, 0.5), (1280, 0.125), (1792, 0.125), (3328, 0.125), (3840, 0.125)]

# sortiepossible = memoize(sortiepossiblebefore)


def filtreP(a, b, probaMIN, nbboiteMAX):
    """  Filtrage en sortie de la couche de Pbox
    Input : différence (16bit), proba (float), float, int
    Output : boolean
    """
    if b <= probaMIN:
        return False
    if nombreboiteactive(a) > nbboiteMAX:
        return False
    return True


###  08/03/19  ###
def boiteactive(a):
    """
    Input : Différence (16-bit integer)
    Ouput : Liste des boites activées par cette différence
    """
    resul = [False, False, False, False]
    for i in range(0, 4):
        if ((a >> (i * 4)) & 0xF) > 0:
            resul[3 - i] = True
    return resul


###  08/03/19  ###
def filtreboiteactive(a, listeboitesactives):
    """  Filtrage sur les boites actives
    Input : différence (16bit), Bool list
    Output : True si les boites actives demandées sont actives dans la différence
    """
    wanted = listeboitesactives
    current = boiteactive(a)
    for i in range(0, 4):
        if wanted[i] is True:
            if current[i] is False:
                return False
    return True


# def chemin(difftabtuple, Pbox, U1, probaMIN, nbboiteMAX, listeboitesactives):
#     """
#     Input : difference distribution table de la Sbox, Pbox
#             différence d'entrée (16bit)
#             Probabilité minimum du chemin à la dernière étape
#             Nombre de boites S activées maximale en dernière étape
#             Liste des boites S qui doivent être au moins activées en dernière
#                 étape
#     Output : liste des chemins possibles ayant en dernière étape une proba
#              >= probaMIN, un nombre de boites S activée <= nbboiteMAX, et tel
#              que toutes les boites S demandées (listeboitesactives) soient
#              activées.
#     """
#     resul = []

#     cheminencours = [0, 0, 0, 0, 0, 0, 0]

#     cheminencours[0] = (U1, 1)    # 1ère étape
#     S1 = sortiepossible(U1, difftabtuple)    # Ensemble des sorties possibles après
#                                         # la premiere couche de boites S
#     for V1 in S1:
#         cheminencours[1] = (V1[0], V1[1]*cheminencours[0][1])
#         U2 = PboxLayer(V1[0], Pbox), cheminencours[1][1]
#         if filtreP(U2[0], U2[1], probaMIN, 4):   # Filtrage en sortie des Pbox
#             cheminencours[2] = (U2[0], U2[1])
#             S2 = sortiepossible(U2[0], difftabtuple)
#             for V2 in S2:
#                 cheminencours[3] = ((V2[0], V2[1]*cheminencours[2][1]))
#                 U3 = PboxLayer(V2[0], Pbox), cheminencours[3][1]
#                 if filtreP(U3[0], U3[1], probaMIN, 4):
#                     cheminencours[4] = (U3[0], U3[1])
#                     S3 = sortiepossible(U3[0], difftabtuple)
#                     for V3 in S3:
#                         cheminencours[5] = (V3[0], V3[1]*cheminencours[4][1])
#                         U4 = PboxLayer(V3[0], Pbox), cheminencours[5][1]
#                         if filtreP(U4[0], U4[1], probaMIN, nbboiteMAX) and \
#                                 filtreboiteactive(U4[0], listeboitesactives):  ### 08/03/19  ###
#                             cheminencours[6] = (U4[0], U4[1])
#                             resul.append(cheminencours.copy())  #/!\ Référence /!\
#     return resul


# Exemple page 24 "A tutorial on..."
#
# >>> chemin(difftabtuto, Pboxtuto, 0b0000101100000000, 0.02, 2, [False, True, False, True])
# [[(2816, 1), (512, 0.5), (64, 0.5), (96, 0.1875), (544, 0.1875), (1360, 0.0263671875), (1542, 0.0263671875)]]


# def maxprobachemin(listechemin):
#     """
#     Input : liste de chemins
#     Ouput : chemin ayant la probabilité maximale
#     """
#     max = 0
#     resul = 0
#     for i in range(0, len(listechemin)):
#         proba = listechemin[i][-1][1]
#         if proba > max:
#             max = proba
#             resul = listechemin[i]
#     return resul


# def trichemin(listechemin):   ###  08/03/19  ###
#     """
#     Input : liste de chemins
#     Output : chemin trié EN PLACE par probabilité finale décroissante
#     """
#     listechemin.sort(key=lambda x: x[-1][1], reverse=True)


def listeU1(n):
    """
    Input : entier entre 1 et 4
    Ouput : liste de tous les différences (16-bits int) telle que le nombre de boites S activées soit inférieure ou égale à n (0 non inclus)
    """
    resul = []
    for i in range(1, 2**16):
        if nombreboiteactive(i) <= n:
            resul.append(i)
    return resul


# def recherchechemin(difftabtuple, Pbox, listeIN, probaMIN, nbboiteMAX, listeboitesactives):
#     """
#     Input : listeIN: liste des U1
#     Output : chemin ayant "la" probabilité maximale
#     """
#     resul = []
#     for U1 in listeIN:
#         a = maxprobachemin(chemin(difftabtuple, Pbox, U1, probaMIN, nbboiteMAX, listeboitesactives))
#         if a != 0:
#             resul.append(a)
#     trichemin(resul)
#     return maxprobachemin(resul), resul


### 08/03/19 ###
# Autre méthode dans la fonction chemin, à chaque fois chemin, rechercher
# chemin dont la proba est plus élevée que celle du précédent


def cheminV2(difftabtuple, Pbox, U1, probaMIN, nbboiteMAX, listeboitesactives):
    """
    Input : difference distribution table de la Sbox, Pbox
    Différence d'entrée (16-bits)
    Probabilité minimum du chemin à la dernière étape, pour le premier chemin calculé
    Nombre de boites S activées maximale en dernière étape
    Liste des boites S qui doivent être au moins activées en dernière étape
    Output : Chemin commencant par U1, ayant en dernière étape une probabilité maximale, un nombre de boites S activée <= nbboiteMAX, et tel que toutes les boites S demandées (listeboitesactives) soient activées
    """
    resul = 0
    cheminencours = [0, 0, 0, 0, 0, 0, 0]
    cheminencours[0] = (U1, 1)    # 1ère étape
    S1 = sortiepossible(U1, difftabtuple)    # Ensemble des sorties possibles après la premiere couche de boites S

    for V1 in S1:
        cheminencours[1] = (V1[0], V1[1] * cheminencours[0][1])
        U2 = PboxLayer(V1[0], Pbox), cheminencours[1][1]
        if filtreP(U2[0], U2[1], probaMIN, 4):   # Filtrage en sortie des Pbox
            cheminencours[2] = (U2[0], U2[1])
            S2 = sortiepossible(U2[0], difftabtuple)
            for V2 in S2:
                cheminencours[3] = ((V2[0], V2[1] * cheminencours[2][1]))
                U3 = PboxLayer(V2[0], Pbox), cheminencours[3][1]
                if filtreP(U3[0], U3[1], probaMIN, 4):
                    cheminencours[4] = (U3[0], U3[1])
                    S3 = sortiepossible(U3[0], difftabtuple)
                    for V3 in S3:
                        cheminencours[5] = (V3[0], V3[1] * cheminencours[4][1])
                        U4 = PboxLayer(V3[0], Pbox), cheminencours[5][1]
                        if filtreP(U4[0], U4[1], probaMIN, nbboiteMAX) and \
                                filtreboiteactive(U4[0], listeboitesactives):
                            cheminencours[6] = (U4[0], U4[1])
                            resul = cheminencours.copy()  # /!\ Référence /!\
                            probaMIN = U4[1]  # Mise à jour de probaMIN
    return resul


class RechercheCheminTropLong(Exception):
    pass


def recherchecheminV2(difftabtuple, Pbox, listeIN, probaMINdébut, nbboiteMAX, listeboitesactives, tempsmaxrecherchechemin):
    """
    Input : listeIN: liste des U1
    Output : chemin ayant "la" probabilité maximale
    """
    probaMIN = probaMINdébut

    debut = time.time()

    resul = 0
    for U1 in listeIN:
        if time.time() - debut > tempsmaxrecherchechemin:
            raise RechercheCheminTropLong()
        a = cheminV2(difftabtuple, Pbox, U1, probaMIN, nbboiteMAX, listeboitesactives)  # Plus besoin de maxProba
        if a != 0:
            resul = a.copy()  # /!\
            probaMIN = resul[-1][1]  # On met à jour probaMIN
    return resul


# def nombreboiteactivefinliste(liste, nb):
#     """
#     Input : liste de chemins
#     Output : nombre et liste des chemins ayant un nombre de boite S activée
#             égal à n à la dernière étape
#     """
#     resul = []
#     compteur = 0
#     n = len(liste)
#     for i in range(0, n):
#         if nombreboiteactive(liste[i][-1][0]) == nb:
#             compteur += 1
#             resul.append(liste[i])
#     return compteur, resul


# nombreboiteactivefinliste(a, 2)
# b = (9, [[(2816, 1), (512, 0.5), (64, 0.5), (48, 0.0625), (34, 0.0625), (85, 0.0087890625), (771, 0.0087890625)], [(2816, 1), (512, 0.5), (64, 0.5), (96, 0.1875), (544, 0.1875), (816, 0.0029296875), (102, 0.0029296875)], [(2816, 1), (512, 0.5), (64, 0.5), (96, 0.1875), (544, 0.1875), (1360, 0.0263671875), (1542, 0.0263671875)], [(2816, 1), (512, 0.5), (64, 0.5), (96, 0.1875), (544, 0.1875), (1632, 0.0029296875), (1632, 0.0029296875)], [(2816, 1), (512, 0.5), (64, 0.5), (96, 0.1875), (544, 0.1875), (2448, 0.0029296875), (24582, 0.0029296875)], [(2816, 1), (512, 0.5), (64, 0.5), (144, 0.0625), (8194, 0.0625), (20485, 0.0087890625), (2313, 0.0087890625)], [(2816, 1), (512, 0.5), (64, 0.5), (176, 0.125), (8226, 0.125), (20565, 0.006591796875), (2827, 0.006591796875)], [(2816, 1), (512, 0.5), (64, 0.5), (192, 0.0625), (8704, 0.0625), (21760, 0.0087890625), (3084, 0.0087890625)], [(2816, 1), (1280, 0.125), (1028, 0.125), (1542, 0.017578125), (1360, 0.017578125), (2720, 0.0010986328125), (24672, 0.0010986328125)]])


# nbcouples = 20
listeIN = listeU1(1)


class RechercheCoupleImpossible(Exception):
    pass


def decryptK5(Sbox, Pbox, K, nbcouples, tempsmaxrecherchechemin):
    """ Décryptage en utilisant seulement des chemins avec une seule boite activée à la fin
    Input: Sbox list, Pbox list, K = [k1, k2, k3, k4, k5]
    Output : clé K5 (tuto), compteurMAXLISTE
    """
    difftab = diffdistrib(Sbox)
    difftabtuple = tuple(map(tuple, difftab))
    invSbox = inverse(Sbox)
    probaMIN = 1 / (2 ** 16)
    listresul = [-1, -1, -1, -1]
    resul = 0
    compteurMAXLISTE = 0  # Nombre de fois ou la fonction Maxliste à renvoyer plus qu'une valeur
    tabproba = [0, 0, 0, 0]

    for partial in range(0, 4):   # Portion de la clé K5 à décrypter
        listeboitesactives = [False, False, False, False]
        listeboitesactives[partial] = True
        chemin = recherchecheminV2(difftabtuple, Pbox, listeIN, probaMIN, 1, listeboitesactives, tempsmaxrecherchechemin)
        tabk5partial = [0] * 16

        tabproba[partial] = chemin[-1][1]

        deltaP = chemin[0][0]  # U1
        deltaU4 = chemin[-1][0]

        ensemblefiltreCouple = set()
        sorties = sortiepossible(deltaU4, difftabtuple)
        for k in sorties:
            ensemblefiltreCouple.add(k[0])

        for i in range(nbcouples):
            X = random.randint(0, 65535)
            Xprim = X ^ deltaP
            Y = Ciphertuto(X, K, Sbox, Pbox)
            Yprim = Ciphertuto(Xprim, K, Sbox, Pbox)
            iteration = 0
            while Y ^ Yprim not in ensemblefiltreCouple:
                if iteration > 65535:
                    raise RechercheCoupleImpossible
                X = random.randint(0, 65535)
                Xprim = X ^ deltaP
                Y = Ciphertuto(X, K, Sbox, Pbox)
                Yprim = Ciphertuto(Xprim, K, Sbox, Pbox)
                iteration += 1

            for k5partial in range(16):  # 2**4
                V4_X_partial = (Y >> (3 - partial) * 4) & 15 ^ k5partial
                V4_Xprim_partial = (Yprim >> (3 - partial) * 4) & 15 ^ k5partial
                U4_X_partial = invSbox[V4_X_partial]
                U4_Xprim_partial = invSbox[V4_Xprim_partial]
                U4_Xpartial = U4_X_partial << (3 - partial) * 4
                U4_Xprimpartial = U4_Xprim_partial << (3 - partial) * 4
                deltaU4exp = U4_Xpartial ^ U4_Xprimpartial
                if deltaU4 == deltaU4exp:
                    tabk5partial[k5partial] += 1

        maxi = maxliste(tabk5partial)
        if len(maxi) != 1:
            compteurMAXLISTE += 1
        listresul[partial] = maxi[0]
        resul += listresul[partial] << (3 - partial) * 4

    return resul, compteurMAXLISTE, tabproba

# Pour filtrage des couples (page 30, la cryptanalyse diff et ses généralisations)
# 1ère méthode de filtrage, ici on est assuré d'avoir 10 chemins compatibles)

### Fin 08/03/19  ###

### 09/03/19  ###

# def decryptK5V2(Sbox, Pbox, K, nbcouples, tempsmaxrecherchechemin):   # Autre version du filtre des couples compatibles
#     """ Décryptage en utilisant seulement des chemins avec une seule boite
#         activée à la fin
#     Input: Sbox list, Pbox list, K = [k1, k2, k3, k4, k5]
#     Output : clé K5 (tuto)
#     """
#     difftab = diffdistrib(Sbox)
#     difftabtuple = tuple(map(tuple, difftab))
#     invSbox = inverse(Sbox)
#     probaMIN = 1/(2**16)

#     listresul = [-1, -1, -1, -1]
#     resul = 0

#     compteurMAXLISTE = 0  # Nombre de fois ou la fonction Maxliste à renvoyer plus qu'une valeur
#     tabproba = [0,0,0,0]

#     for partial in range(0, 4):   # Portion de la clé K5 à décrypter
#         listeboitesactives = [False, False, False, False]
#         listeboitesactives[partial] = True
#         chemin = recherchecheminV2(difftabtuple, Pbox, listeIN, probaMIN, 1, listeboitesactives, tempsmaxrecherchechemin)
#         # print(chemin)
#         tabk5partial = [0]*16

#         proba = chemin[-1][1]
#         n = int(nbcouples/proba)+1

#         tabproba[partial] = proba

#         deltaP = chemin[0][0]  # U1
#         deltaU4 = chemin[-1][0]

#         ensemblefiltreCouple = set()
#         sorties = sortiepossible(deltaU4, difftabtuple)      # Pour filtrage des couples (page 30, la cryptanalyse diff et ses généralisations)
#         for k in sorties:
#             ensemblefiltreCouple.add(k[0])

#         for i in range(n):                             # n est calculé pour avoir probablement 10 chemins compatibles
#             X = random.randint(0, 65535)
#             Xprim = X ^ deltaP
#             Y = Ciphertuto(X, K, Sbox, Pbox)
#             Yprim = Ciphertuto(Xprim, K, Sbox, Pbox)
#             if Y ^ Yprim in ensemblefiltreCouple:
#                 # print(X, Xprim, Y, Yprim)
#                 for k5partial in range(16):  # 2**4

#                     V4_X_partial = (Y >> (3-partial)*4) & 15 ^ k5partial
#                     V4_Xprim_partial = (Yprim >> (3-partial)*4) & 15 ^ k5partial

#                     U4_X_partial = invSbox[V4_X_partial]
#                     U4_Xprim_partial = invSbox[V4_Xprim_partial]

#                     U4_Xpartial = U4_X_partial << (3-partial)*4
#                     U4_Xprimpartial = U4_Xprim_partial << (3-partial)*4

#                     deltaU4exp = U4_Xpartial ^ U4_Xprimpartial
#                     if deltaU4 == deltaU4exp:
#                         tabk5partial[k5partial] += 1

#         # print(tabk5partial)
#         grgr = maxliste(tabk5partial)
#         if len(grgr) != 1:
#             compteurMAXLISTE += 1
#         listresul[partial] = grgr[0]
#         # print(listresul[partial], bin(listresul[partial]))
#         resul += listresul[partial] << (3-partial)*4

#     return resul, compteurMAXLISTE, tabproba


### Test des 2 méthodes de filtrage sur  un exemple ###
# K = [1045, 345, 23, 894, 0b1000010111110011]
# deltaP = 0b0000000000010000

# def x():
#     compteur3 = 0
#     for i in range(2024):
#         X = random.randint(0, 65535)
#         Xprim = X ^ deltaP
#         Y = Ciphertuto(X, K, Sboxtuto, Pboxtuto)
#         Yprim = Ciphertuto(Xprim, K, Sboxtuto, Pboxtuto)
#         if Y ^ Yprim in {4096, 20480, 40960, 49152, 24576, 61440}:
#             compteur3 += 1;
#     return compteur3

# def y():
#     compteur = 0
#     for i in range(10):
#         X = random.randint(0, 65535)
#         Xprim = X ^ deltaP
#         Y = Ciphertuto(X, K, Sboxtuto, Pboxtuto)
#         Yprim = Ciphertuto(Xprim, K, Sboxtuto, Pboxtuto)
#         while Y ^ Yprim not in {4096, 20480, 40960, 49152, 24576, 61440}:                    # A étudier, problème pour trouver couple, rare --> proba...
#             X = random.randint(0, 65535)
#             Xprim = X ^ deltaP
#             Y = Ciphertuto(X, K, Sboxtuto, Pboxtuto)
#             Yprim = Ciphertuto(Xprim, K, Sboxtuto, Pboxtuto)
#         compteur += 1
#     return compteur

# def z(n):
#     a = time.time()
#     for i in range(0, n):
#         x()
#     print(time.time() - a)

#     b = time.time()
#     for i in range(0, n):
#         y()
#     print(time.time() - b)

# Les deux méthodes se valent dans cet exemple, et au hasard, on retrouve à peu près 10 valeurs
# à vérifier dans l'algo --> test1


Sbox4 = [[8, 7, 0, 12, 13, 5, 2, 4, 14, 15, 3, 6, 11, 1, 9, 10],
         [10, 11, 7, 9, 12, 13, 5, 3, 14, 1, 2, 8, 0, 15, 6, 4],
         [0, 12, 14, 2, 7, 15, 5, 3, 10, 9, 8, 1, 4, 6, 13, 11],
         [0, 6, 14, 9, 7, 13, 1, 3, 12, 8, 4, 11, 15, 5, 10, 2],
         [0, 5, 6, 13, 8, 7, 9, 4, 12, 14, 11, 10, 3, 2, 15, 1],
         # [9, 14, 7, 0, 6, 2, 12, 3, 4, 10, 11, 1, 5, 15, 8, 13],  trop long test1
         [7, 10, 6, 2, 0, 12, 1, 9, 13, 14, 8, 3, 15, 4, 5, 11],
         [2, 6, 0, 15, 8, 11, 14, 4, 1, 3, 13, 9, 5, 7, 12, 10],
         [10, 14, 11, 9, 7, 12, 2, 8, 6, 3, 4, 5, 13, 1, 0, 15],
         [6, 14, 13, 10, 2, 12, 15, 3, 0, 9, 7, 5, 8, 1, 11, 4],
         [1, 11, 8, 15, 13, 10, 3, 0, 7, 6, 4, 9, 14, 5, 12, 2]]

Sbox6 = [[11, 1, 14, 2, 6, 12, 15, 8, 3, 4, 7, 10, 13, 0, 5, 9], [9, 1, 6, 5, 2, 12, 8, 14, 13, 7, 10, 0, 4, 11, 3, 15], [15, 14, 3, 6, 12, 1, 2, 8, 11, 0, 5, 7, 13, 10, 4, 9], [4, 11, 1, 3, 8, 15, 2, 12, 13, 0, 9, 10, 14, 5, 7, 6], [6, 5, 2, 3, 7, 12, 14, 0, 11, 4, 9, 13, 10, 1, 8, 15], [9, 2, 3, 7, 0, 14, 11, 4, 10, 13, 8, 15, 6, 1, 12, 5], [0, 6, 13, 12, 5, 9, 1, 11, 7, 4, 3, 10, 8, 2, 14, 15], [12, 11, 8, 5, 15, 14, 6, 13, 4, 10, 2, 1, 9, 7, 0, 3], [8, 12, 6, 7, 2, 0, 9, 1, 14, 13, 5, 4, 11, 15, 10, 3], [9, 10, 1, 3, 11, 15, 4, 6, 2, 13, 8, 14, 12, 7, 5, 0]]
Sbox8 = [[15, 5, 3, 1, 6, 13, 0, 4, 12, 9, 11, 2, 10, 7, 14, 8], [11, 10, 3, 5, 8, 2, 15, 9, 14, 4, 1, 13, 6, 7, 0, 12], [3, 2, 5, 8, 1, 13, 7, 11, 0, 9, 10, 15, 6, 4, 14, 12], [13, 9, 12, 10, 14, 8, 1, 2, 0, 4, 7, 15, 5, 11, 3, 6], [11, 15, 7, 4, 14, 13, 2, 5, 6, 8, 3, 9, 10, 1, 12, 0], [7, 8, 0, 15, 11, 9, 1, 13, 2, 3, 14, 6, 12, 10, 4, 5], [5, 0, 9, 12, 8, 10, 13, 11, 2, 14, 1, 4, 15, 7, 3, 6], [2, 3, 9, 8, 15, 11, 7, 1, 5, 12, 13, 6, 14, 10, 0, 4], [5, 6, 8, 3, 13, 2, 1, 9, 0, 4, 12, 15, 10, 14, 7, 11], [15, 8, 7, 6, 0, 4, 5, 12, 10, 14, 2, 11, 9, 3, 13, 1]]
Sbox10 = [[3, 1, 5, 0, 7, 15, 11, 2, 6, 12, 8, 4, 9, 14, 10, 13], [3, 14, 8, 1, 2, 12, 5, 6, 4, 10, 15, 13, 0, 11, 9, 7], [12, 11, 2, 1, 4, 3, 10, 9, 5, 7, 6, 8, 0, 13, 14, 15], [0, 14, 5, 9, 3, 1, 15, 12, 2, 13, 10, 7, 8, 11, 4, 6], [12, 7, 11, 2, 3, 9, 6, 13, 15, 5, 1, 0, 10, 8, 4, 14], [10, 5, 6, 11, 2, 13, 12, 3, 0, 7, 14, 9, 4, 8, 1, 15], [9, 5, 12, 14, 1, 3, 11, 13, 2, 15, 8, 4, 10, 6, 0, 7], [13, 3, 2, 12, 14, 6, 1, 9, 5, 11, 10, 8, 15, 0, 4, 7], [10, 5, 13, 12, 2, 14, 11, 15, 9, 6, 3, 7, 1, 0, 8, 4], [15, 1, 7, 3, 6, 10, 0, 5, 9, 8, 4, 2, 11, 14, 13, 12]]

Sbox12 = [[10, 14, 2, 6, 7, 3, 15, 5, 0, 13, 1, 12, 9, 4, 8, 11],
          # [15, 0, 2, 14, 1, 9, 12, 7, 4, 3, 10, 13, 11, 6, 5, 8],  trop long test1
          [0, 15, 7, 3, 4, 11, 8, 10, 2, 14, 1, 13, 5, 9, 6, 12],
          [12, 4, 10, 1, 7, 6, 0, 11, 2, 3, 15, 9, 13, 8, 5, 14],
          [9, 10, 7, 11, 4, 3, 5, 13, 2, 14, 15, 6, 0, 12, 8, 1],
          [12, 13, 14, 15, 6, 7, 4, 8, 2, 3, 1, 11, 5, 9, 0, 10],
          [7, 8, 12, 13, 15, 9, 10, 11, 1, 0, 4, 2, 5, 6, 14, 3],
          [15, 2, 4, 13, 12, 3, 0, 5, 11, 8, 14, 7, 6, 9, 10, 1],
          [7, 14, 5, 6, 15, 11, 9, 13, 12, 10, 1, 8, 2, 3, 4, 0],
          [12, 6, 1, 15, 5, 7, 4, 13, 2, 3, 0, 14, 8, 10, 9, 11],
          [2, 5, 1, 0, 6, 3, 7, 4, 14, 10, 11, 9, 8, 13, 15, 12]]

listSboxtest = [Sbox4, Sbox6, Sbox8, Sbox10, Sbox12]


def test1():  # Comparaison méthode filtrage
    K = [1045, 345, 23, 894, 0b1000010111110011]
    nbcouples = 20
    tempsmaxrecherchechemin = 20
    a = time.time()
    for i in range(5):
        for n in range(10):
            b = time.time()
            K5 = K[4]
            K5cal, compteurMAXLISTE, tabproba = decryptK5(listSboxtest[i][n], Pboxtuto, K, nbcouples, tempsmaxrecherchechemin)
            if K5 == K5cal:
                print(i, n, "K5 =", K5, "K5cal =", K5cal, "ok", "Durée :", time.time() - b, "compteurMAXLISTE :", compteurMAXLISTE)
            else:
                print(i, n, "K5 =", K5, "K5cal =", K5cal, "erreur", "Durée :", time.time() - b, "compteurMAXLISTE :", compteurMAXLISTE)
        c = time.time() - a
    print("Durée totale v1: ", c)
    print("Durée moyenne v1: ", (c / 50))

    a = time.time()
    for i in range(5):
        for n in range(10):
            b = time.time()
            K5 = K[4]
            K5cal, compteurMAXLISTE, tabproba = decryptK5V2(listSboxtest[i][n], Pboxtuto, K, nbcouples, tempsmaxrecherchechemin)
            if K5 == K5cal:
                print(i, n, "K5 =", K5, "K5cal =", K5cal, "ok", "Durée :", time.time() - b, "compteurMAXLISTE :", compteurMAXLISTE)
            else:
                print(i, n, "K5 =", K5, "K5cal =", K5cal, "erreur", "Durée :", time.time() - b, "compteurMAXLISTE :", compteurMAXLISTE)
        c = time.time() - a
    print("Durée totale v2: ", c)
    print("Durée moyenne v2: ", (c / 50))

## Résultats :
# moins d'erreur avec nbcouples = 20
# les deux méthodes se terminent avec le même temps
# On utilisera maintenant que la méthode 1


# def test2(n):     # Dépendance K5
#     nbcouples = 20
#     tempsmaxrecherchechemin = 20
#     a = time.time()
#     for i in range(0, n):
#         K5 = random.randint(0, 65535)
#         b = time.time()
#         K5cal, compteurMAXLISTE, tabproba = decryptK5(Sboxtest, Pboxtest, [1045, 345, 23, 894, K5], nbcouples, tempsmaxrecherchechemin)
#         if K5 == K5cal:
#             print("K5 =", K5, "K5cal =", K5cal, "ok", "Durée :", time.time()-b, "compteurMAXLISTE :", compteurMAXLISTE)
#         else:
#             print("K5 =", K5, "K5cal =", K5cal, "erreur", "Durée :", time.time()-b, "compteurMAXLISTE :", compteurMAXLISTE)
#     c = time.time()-a
#     print("Durée totale: ", c)
#     print("Durée moyenne: ", (c/n))

## Résultats :
# K5 n'est pas influent


# def test3(n):    # Dépendance K (liste des ki)
#      nbcouples = 20
#      tempsmaxrecherchechemin = 20
#     a = time.time()
#     for i in range(0, n):
#         K = []
#         for j in range(0, 5):
#             K.append(random.randint(0, 65535))
#         K5 = K[4]
#         b = time.time()
#         K5cal, compteurMAXLISTE, tabproba = decryptK5(Sboxtest, Pboxtest, [1045, 345, 23, 894, K5], nbcouples, tempsmaxrecherchechemin)
#         if K5 == K5cal:
#             print("K5 =", K5, "K5cal =", K5cal, "ok", "Durée :", time.time()-b, "compteurMAXLISTE :", compteurMAXLISTE)
#         else:
#             print("K5 =", K5, "K5cal =", K5cal, "erreur", "Durée :", time.time()-b, "compteurMAXLISTE :", compteurMAXLISTE)
#     c = time.time()-a
#     print("Durée totale: ", c)
#     print("Durée moyenne: ", (c/n))

## Résultats :
# K n'est pas influent


## 14/03/19 ##

## Optimisation ##

# def main():
#     decryptK5(listSboxtest[0][5], Pboxtuto, Ktuto)
#     #decryptK5(listSboxtest[1][8], Pboxtuto, Ktuto)
#     for i in range(0,5):
#         decryptK5(listSboxtest[i][0], Pboxtuto, Ktuto)

# cProfile.run('main()')

# with PyCallGraph(output=GraphvizOutput()):
#     main()


## Pour mémoisation : n'utiliser que des tuples pour les difftab et les Pbox

## 15/03/19 ##

# def listSbox(diffmaxdemande, nbdemande):
#     """
#     Entrée : uniformité différentielle, nombre de Sbox à trouver
#     Sortie : liste de Sbox distinctes ayant une certaine uniformité différentielle
#     """
#     if diffmaxdemande not in {4,6,8,10,12,16}:
#         return []
#     diffmax = 0
#     ensemble = set()
#     while len(ensemble) != nbdemande:
#         Sbox = np.random.permutation(16)
#         diffmax = maxtab(diffdistrib(Sbox))[2]
#         if diffmax == diffmaxdemande:
#             # if tuple(Sbox) in ensemble:
#             #     print("doublon")
#             ensemble.add(tuple(Sbox))

#     return list(ensemble)


# def createfichierSbox(nb,nom):
#     with open(nom, 'wb') as f:
#         pickle.dump([listSbox(i, nb) for i in range(0,12+1)], f)


# def test(nb, name, nbc, temps):
#     """
#     Input : nb : nombre de Sbox par uniffdiff (au total : nb*5 Sbox)
#             name : pour identifier les fichiers
#             nbc : nombre de couples pour DECRYPT
#             temps : tempsmaxrecherchechemin
#     """
#     K = Ktuto
#     K5 = K[4]
#     Pbox = Pboxtuto
#     nbcouples = nbc
#     tempsmaxrecherchechemin = temps

#     #LISTSBOX = [listSbox(i, nb) for i in range(0,12+1)]
#     with open("LISTSBOX", 'rb') as f:
#         LISTSBOX = pickle.load(f)

#     columns = ['name','Unindif','Sboxnumber', 'Resultat', 'Time', 'CompteurMaxListe', 'RechercheCheminTropLong','RechercheCoupleImpossible','Proba1','Proba2','Proba3','Proba4','ResultatAVG','TimeAVG']
#     index = range(-1, (nb*5))  # Premiere ligne : données
#     data = [[None,None,None,0,0,0,0,0,None,None,None,None,0,0]]

#     fichierlog = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'log.txt'
#     fichierresul = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'resultat.xlsx'
#     fichierLISTSBOX = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'LISTSBOX'
#     fichierdata = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'data'

#     with open(fichierlog,'w'):      # clear log
#         pass

#     logging.basicConfig(filename=fichierlog,level=logging.INFO, format='%(asctime)s - %(message)s')
#     logging.info('nb = '+str(nb))
#     logging.info('name = '+name)
#     logging.info('nbcouples = '+str(nbcouples))
#     logging.info('tempsmaxrecherchechemin = '+str(tempsmaxrecherchechemin))
#     with open(fichierlog,'r'):
#         pass  #pour voir en temps réeel

#     nblog = 25    # Intervalle log
#     compteur = 0
#     temps = time.time()

#     for Sboxnumber in range(0, nb):
#         for unifdiff in [4, 6, 8, 10, 12]:

#             if compteur % nblog == 0:   # LOG
#                 if compteur == 0:
#                     logging.info('count '+str(compteur))
#                 else:
#                     logging.info('count '+str(compteur)+'  timeavg '+str((time.time()-temps)/compteur))
#                 with open(fichierlog,'r'):
#                     pass  #pour voir en temps réeel

#             sortiepossible.cache_clear()   # Vider cache pour ne pas favorier la suite
#             PboxLayer.cache_clear()
#             boolCheminTropLong = False
#             boolCoupleImpossible = False
#             a = time.time()

#             try:
#                 K5cal, compteurMAXLISTE, tabproba = decryptK5(LISTSBOX[unifdiff][Sboxnumber], Pbox, K, nbcouples, tempsmaxrecherchechemin)
#                 proba1, proba2, proba3, proba4 = tabproba[0], tabproba[1], tabproba[2], tabproba[3]
#             except RechercheCheminTropLong:
#                 boolCheminTropLong = True
#                 K5cal = None
#                 compteurMAXLISTE = 0
#                 proba1, proba2, proba3, proba4 = None, None, None, None
#             except RechercheCoupleImpossible:
#                 boolCoupleImpossible = True
#                 K5cal = None
#                 compteurMAXLISTE = 0
#                 proba1, proba2, proba3, proba4 = None, None, None, None

#             Temps = time.time() - a
#             Resul = (K5cal == K5)
#             data.append([name, unifdiff, Sboxnumber, Resul, Temps, compteurMAXLISTE, boolCheminTropLong, boolCoupleImpossible, proba1, proba2, proba3, proba4])
#             compteur += 1

#     logging.info('Fin calculs')

#     for i in range(1, len(data)):
#         if data[i][3]:          # Resultat
#             data[0][3] += 1
#         data[0][4] += data[i][4] # Temps
#         if data[i][5] > 0:       # CompteurMaxListe
#             data[0][5] += 1
#         if data[i][6]:           # Recherchechemintroplong
#             data[0][6] += 1
#         if data[i][7]:           # Recherchecoupleimpossible
#             data[0][7] += 1

#     ResultatAVG = (data[0][3] / (len(data)-1))*100
#     data[0][12] = ResultatAVG
#     logging.info('ResultatAVG = '+str(ResultatAVG))

#     TIMEAVG = data[0][4] / (len(data) -1)
#     data[0][13] = TIMEAVG
#     logging.info('TIMEAVG = '+str(TIMEAVG))

#     df = pd.DataFrame(data, index=index, columns=columns)
#     df.to_excel(fichierresul)
#     with open(fichierLISTSBOX, 'wb') as f:
#         pickle.dump(LISTSBOX, f)
#     with open(fichierdata, 'wb') as g:
#         pickle.dump(data, g)
#     logging.info('Fin exportation')
#     with open(fichierlog,'r'): pass


## 18/03/19 ##

# compteur = 17 * [0]

# for i in range(10**5):
#     Sbox = np.random.permutation(16)
#     #print(maxtab(diffdistrib(Sbox))[2])
#     compteur[maxtab(diffdistrib(Sbox))[2]] += 1
# for i in range(0, 17):
#     compteur[i] = compteur[i] / 10**3

# print(compteur)

def permutdiffmax(diffmaxdemande):
    """
    Entrée : entier
    Sortie : liste d'une permutation telle que le max du tableau de distribution des différences soit l'entier diffmaxdemande, et tableau
    """
    diffmax = 0
    while diffmax != diffmaxdemande:
        Sbox = np.random.permutation(16)
        difftab = diffdistrib(Sbox)
        diffmax = maxtab(difftab)[2]
    compteurtab = 9 * [0]
    for ligne in range(1, 16):
        for colonne in range(1, 16):
            compteurtab[difftab[ligne][colonne] // 2] += 1
    return tuple(Sbox), diffmax, compteurtab


Pbox0 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0)             # n0
Pbox1 = (0, 1, 4, 5, 2, 3, 8, 9, 6, 7, 12, 13, 10, 11, 14, 15)             # n1
Pbox2 = (0, 1, 4, 8, 2, 3, 5, 9, 6, 10, 12, 13, 7, 11, 14, 15)             # n2
Pbox3 = (0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15)             # n3
Pbox4 = (12, 13, 14, 15, 4, 5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3)
Pbox5 = (12, 13, 14, 15, 9, 10, 11, 4, 5, 6, 7, 8, 0, 1, 2, 3)             # n4
Pbox6 = (4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11)
Pbox7 = (15, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0)
Pbox8 = (4, 5, 6, 7, 0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15)
Pbox9 = (1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14)
Pbox10 = (0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15)
Pbox11 = (0, 1, 2, 3, 4, 5, 8, 9, 6, 7, 10, 11, 12, 13, 14, 15)             # n5
Pbox12 = (0, 1, 2, 3, 4, 5, 6, 8, 7, 9, 10, 11, 12, 13, 14, 15)
Pbox13 = (4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 2, 3, 8, 9, 10, 11)
Pbox14 = (12, 13, 14, 15, 4, 5, 6, 8, 7, 9, 10, 11, 0, 1, 2, 3)             # n6
Pbox15 = (6, 4, 0xc, 5, 0, 7, 2, 0xe, 1, 0xf, 3, 0xd, 8, 0xa, 9, 0xb)       # n7
Pbox16 = (12, 7, 13, 15, 0, 1, 4, 9, 11, 5, 8, 2, 6, 10, 3, 14)   # n8
Pbox17 = (6, 15, 14, 13, 7, 8, 1, 3, 10, 11, 5, 4, 12, 2, 0, 9)   # n9
Pbox18 = (15, 2, 5, 1, 4, 12, 9, 14, 10, 11, 8, 0, 6, 13, 3, 7)   # n10
Pbox19 = (11, 7, 5, 8, 4, 0, 3, 9, 10, 15, 13, 6, 2, 14, 1, 12)   # n11
Pbox20 = (2, 3, 14, 13, 5, 10, 8, 7, 1, 6, 9, 0, 4, 11, 15, 12)   # n12

Pboxtuto = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)  # Pboxtuto # n13

Pboxliste = [Pbox0, Pbox1, Pbox2, Pbox3, Pbox4, Pbox5, Pbox6, Pbox7, Pbox8, Pbox9, Pbox10, Pbox11, Pbox12, Pbox13, Pbox14, Pbox15, Pbox16, Pbox17, Pbox18, Pbox19, Pbox20, Pboxtuto]


def testv2(nb, name, nbc, temps):
    """
    Input : Nombre de Sbox par uniffdiff (au total : nb*5 Sbox)
    Name : pour identifier les fichiers
    Nombre de couples pour DECRYPT
    Tempsmaxrecherchechemin
    """
    K = Ktuto
    K5 = K[4]
    Pbox = Pboxtuto
    nbcouples = nbc
    tempsmaxrecherchechemin = temps
    columns = ['Sbox', 'Unifdiff', 'Resultat', 'Time', 'CompteurMaxListe', 'RechercheCheminTropLong', 'RechercheCoupleImpossible', 'Proba1', 'Proba2', 'Proba3', 'Proba4', '0', '2', '4', '6', '8', '10', '12', '14', '16']
    index = range(nb * 5)
    data = []

    # fichierlog = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'log.txt'
    # fichierresul = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'resultat.xlsx'
    # fichierLISTSBOX = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'LISTSBOX'
    # fichierdata = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'data'

    fichierlog = name + 'log.txt'
    fichierresul = name + 'resultat.xlsx'
    fichierLISTSBOX = name + 'LISTSBOX'
    fichierdata = name + 'data'

    with open(fichierlog, 'w'):      # clear log
        pass

    logging.basicConfig(filename=fichierlog, level=logging.INFO, format='%(asctime)s - %(message)s')
    logging.info('nb = ' + str(nb))
    logging.info('name = ' + name)
    logging.info('nbcouples = ' + str(nbcouples))
    logging.info('tempsmaxrecherchechemin = ' + str(tempsmaxrecherchechemin))
    with open(fichierlog, 'r'):
        pass  # pour voir en temps réeel

    nblog = 25    # Intervalle log
    logging.info('Début calcul LISTSBOX')
    with open(fichierlog, 'r'):
        pass

    LISTSBOX = []
    for i in range(nb):
        for unifdiff in [4, 6, 8, 10, 12]:
            Sbox, unifdiff, compteurtab = permutdiffmax(unifdiff)
            LISTSBOX.append([Sbox, unifdiff, compteurtab])

    logging.info('Fin calcul LISTSBOX')
    compteur = 0
    tempsdebut = time.time()

    for elem in LISTSBOX:
        if compteur % nblog == 0:   # LOG
            if compteur == 0:
                logging.info('count ' + str(compteur))
            else:
                logging.info('count ' + str(compteur) + '  timeavg ' + str((time.time() - tempsdebut) / compteur))
            with open(fichierlog, 'r'):
                pass  # pour voir en temps réeel
        if compteur % 100 == 0:
            print(compteur)

        Sbox = elem[0]
        K[4] = np.random.randint(0, 2**16)  # Varier K5
        K5 = K[4]
        unifdiff = elem[1]
        compteurtab = elem[2]

        sortiepossible.cache_clear()   # Vider cache pour ne pas favorier la suite
        PboxLayer.cache_clear()
        boolCheminTropLong = False
        boolCoupleImpossible = False

        a = time.time()
        try:
            K5cal, compteurMAXLISTE, tabproba = decryptK5(Sbox, Pbox, K, nbcouples, tempsmaxrecherchechemin)
        except RechercheCheminTropLong:
            boolCheminTropLong = True
            K5cal = None
            compteurMAXLISTE = 0
            tabproba = [0, 0, 0, 0]
        except RechercheCoupleImpossible:
            boolCoupleImpossible = True
            K5cal = None
            compteurMAXLISTE = 0
            tabproba = [0, 0, 0, 0]

        Temps = time.time() - a
        Resul = (K5cal == K5)
        Sboxstr = '_'.join([str(elem) for elem in Sbox])
        data.append([Sboxstr, unifdiff, Resul, Temps, compteurMAXLISTE, boolCheminTropLong, boolCoupleImpossible, *tabproba, *compteurtab])
        compteur += 1

    logging.info('Fin calculs')

    compteurResultat = 0
    compteurTime = 0
    compteurMaxListe = 0
    compteurchemin = 0
    compteurcouple = 0

    for i in range(0, len(data)):
        if data[i][2]:          # Resultat
            compteurResultat += 1
        compteurTime += data[i][3]  # Temps
        if data[i][4] > 0:       # CompteurMaxListe
            compteurMaxListe += 1
        if data[i][5]:           # Recherchechemintroplong
            compteurchemin += 1
        if data[i][6]:           # Recherchecoupleimpossible
            compteurcouple += 1

    ResultatAVG = (compteurResultat / (len(data))) * 100
    logging.info('ResultatAVG = ' + str(ResultatAVG))
    TIMEAVG = compteurTime / (len(data))
    logging.info('TIMEAVG = ' + str(TIMEAVG))
    logging.info('CompteurMaxListe = ' + str(compteurMaxListe))
    logging.info('Compteurchemin = ' + str(compteurchemin))
    logging.info('Compteurcouple = ' + str(compteurcouple))
    logging.info('Fin statistiques')

    df = pd.DataFrame(data, index=index, columns=columns)
    df.to_excel(fichierresul)
    with open(fichierLISTSBOX, 'wb') as f:
        pickle.dump(LISTSBOX, f)
    with open(fichierdata, 'wb') as g:
        pickle.dump(data, g)

    logging.info('Fin exportation')
    with open(fichierlog, 'r'):
        pass


def testv2Pbox(nb, name, nbc, temps):
    """
    Input : nb : nombre de Sbox par uniffdiff (au total : nb*5 Sbox)
            name : pour identifier les fichiers
            nbc : nombre de couples pour DECRYPT
            temps : tempsmaxrecherchechemin
    """
    K = Ktuto
    K5 = K[4]
    # Pbox = Pboxtuto
    nbcouples = nbc
    tempsmaxrecherchechemin = temps

    columns = ['Sbox', 'Unifdiff', 'Resultat', 'Time', 'CompteurMaxListe', 'RechercheCheminTropLong', 'RechercheCoupleImpossible', 'Proba1', 'Proba2', 'Proba3', 'Proba4', '0', '2', '4', '6', '8', '10', '12', '14', '16', 'Pbox']

    index = range(nb * 5 * (len(Pboxliste)))
    data = []

    # fichierlog = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'log.txt'
    # fichierresul = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'resultat.xlsx'
    # fichierLISTSBOX = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'LISTSBOX'
    # fichierdata = '/content/gdrive/My Drive/Colab Notebooks/Resul/'+name+'data'

    fichierlog = name + 'log.txt'
    fichierresul = name + 'resultat.xlsx'
    fichierLISTSBOX = name + 'LISTSBOX'
    fichierdata = name + 'data'

    with open(fichierlog, 'w'):      # clear log
        pass

    logging.basicConfig(filename=fichierlog, level=logging.INFO, format='%(asctime)s - %(message)s')
    logging.info('nb = ' + str(nb))
    logging.info('name = ' + name)
    logging.info('nbcouples = ' + str(nbcouples))
    logging.info('tempsmaxrecherchechemin = ' + str(tempsmaxrecherchechemin))
    with open(fichierlog, 'r'):
        pass  # pour voir en temps réeel

    nblog = 25    # Intervalle log

    logging.info('Début calcul LISTSBOX')
    with open(fichierlog, 'r'):
        pass

    LISTSBOX = []
    for i in range(nb):
        for unifdiff in [4, 6, 8, 10, 12]:
            Sbox, unifdiff, compteurtab = permutdiffmax(unifdiff)
            LISTSBOX.append([Sbox, unifdiff, compteurtab])

    logging.info('Fin calcul LISTSBOX')

    compteur = 0
    tempsdebut = time.time()

    lenPboxliste = len(Pboxliste)

    for elem in LISTSBOX:

        Sbox = elem[0]
        K[4] = np.random.randint(0, 2**16)  # Varier K5
        K5 = K[4]
        unifdiff = elem[1]
        compteurtab = elem[2]

        for u in range(lenPboxliste):
            if compteur % nblog == 0:   # LOG
                if compteur == 0:
                    logging.info('count ' + str(compteur))
                else:
                    logging.info('count ' + str(compteur) + '  timeavg ' + str((time.time() - tempsdebut) / compteur))
                with open(fichierlog, 'r'):
                    pass  # pour voir en temps réeel

            if compteur % 100 == 0:
                print(compteur)

            sortiepossible.cache_clear()   # Vider cache pour ne pas favorier la suite
            PboxLayer.cache_clear()
            boolCheminTropLong = False
            boolCoupleImpossible = False

            a = time.time()
            try:
                K5cal, compteurMAXLISTE, tabproba = decryptK5(Sbox, Pboxliste[u], K, nbcouples, tempsmaxrecherchechemin)
            except RechercheCheminTropLong:
                boolCheminTropLong = True
                K5cal = None
                compteurMAXLISTE = 0
                tabproba = [0, 0, 0, 0]
            except RechercheCoupleImpossible:
                boolCoupleImpossible = True
                K5cal = None
                compteurMAXLISTE = 0
                tabproba = [0, 0, 0, 0]

            Temps = time.time() - a

            Resul = (K5cal == K5)
            Sboxstr = '_'.join([str(elem) for elem in Sbox])
            data.append([Sboxstr, unifdiff, Resul, Temps, compteurMAXLISTE, boolCheminTropLong, boolCoupleImpossible, *tabproba, *compteurtab, u])
            compteur += 1

    logging.info('Fin calculs')

    compteurResultat = 0
    compteurTime = 0
    compteurMaxListe = 0
    compteurchemin = 0
    compteurcouple = 0

    for i in range(0, len(data)):
        if data[i][2]:          # Resultat
            compteurResultat += 1
        compteurTime += data[i][3]  # Temps
        if data[i][4] > 0:       # CompteurMaxListe
            compteurMaxListe += 1
        if data[i][5]:           # Recherchechemintroplong
            compteurchemin += 1
        if data[i][6]:           # Recherchecoupleimpossible
            compteurcouple += 1

    ResultatAVG = (compteurResultat / (len(data)))*100
    logging.info('ResultatAVG = '+str(ResultatAVG))

    TIMEAVG = compteurTime / (len(data))
    logging.info('TIMEAVG = '+str(TIMEAVG))

    logging.info('CompteurMaxListe = '+str(compteurMaxListe))
    logging.info('Compteurchemin = '+str(compteurchemin))
    logging.info('Compteurcouple = '+str(compteurcouple))

    logging.info('Fin statistiques')

    df = pd.DataFrame(data, index=index, columns=columns)
    df.to_excel(fichierresul)
    with open(fichierLISTSBOX, 'wb') as f:
        pickle.dump(LISTSBOX, f)
    with open(fichierdata, 'wb') as g:
        pickle.dump(data, g)

    logging.info('Fin exportation')
    with open(fichierlog, 'r'):
        pass

a = time.time()

for i in range(0,10):
    decryptK5(listSboxtest[0][5], Pboxtuto, Ktuto, 2, 10)

print(time.time()-a)