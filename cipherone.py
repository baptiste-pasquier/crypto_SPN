# -*- coding: utf-8 -*-
"""
Chiffrement de type SPN sur un tour
"""

from random import randint


def paire():
    """
    2 entiers distincts
    """
    a = randint(0, 15)
    b = randint(0, 15)
    while b == a:
        b = randint(0, 15)

    return a, b


def function(liste):
    """
    Définition d'une fonction à partir d'une liste
    """
    return lambda x: liste[x]


def inverse(liste):
    """
    Fonction réciproque
    """
    return lambda x: liste.index(x)


cipher = [6, 4, 0xc, 5, 0, 7, 2, 0xe, 1, 0xf, 3, 0xd, 8, 0xa, 9, 0xb]
S = function(cipher)
R = inverse(cipher)
k0 = 15
k1 = 7


def CipherOne(m):
    """
    Chiffrement
    """
    return S(m ^ k0) ^ k1


def decrypt():
    """
    Déchiffrement -> calcul de k0 et k1
    """
    def calculk1():
        ensemblek1 = set(x for x in range(0, 16))
        while len(ensemblek1) > 1:
            m0, m1 = paire()
            c0, c1 = CipherOne(m0), CipherOne(m1)
            u0u1 = m0 ^ m1
            ensemble = set()
            for t in range(0, 16):
                v0exp = t ^ c0
                v1exp = t ^ c1
                u0exp = R(v0exp)
                u1exp = R(v1exp)

                if u0exp ^ u1exp == u0u1:
                    ensemble.add(t)
            ensemblek1 = ensemblek1 & ensemble
        k1cal = ensemblek1.pop()
        return(k1cal)

    k1cal = calculk1()

    def calculk0():
        m = randint(0, 15)
        c = CipherOne(m)
        v = c ^ k1cal
        u = R(v)
        k0 = m ^ u
        return k0

    k0cal = calculk0()

    return k0cal, k1cal
