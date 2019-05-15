"""
Dieses Programm implementiert den RSA Algorithmus zum verschlüsseln.
Er wählt zufällig zwei Primzahlen aus einer txt-Datei von Primzahlen und
nutzt sie um den Public und den Private Key zu erzeugen. Unter verwendung der Schlüssel
ist es möglich Nachichten zu verschlüsseln oder zu entschlüsseln.
"""

import random

def gcd(a, b):
    """
    Euklidischer Algorithmus, Rückgabe des ggt von a und b
    """
    if (b == 0):
        return a
    else:
        return gcd(b, a % b)

def xgcd(a, b):
    """
    Erweiterter Euklidischer Algorithmus
    """
    x, old_x = 0, 1
    y, old_y = 1, 0

    while (b != 0):
        quotient = a // b
        a, b = b, a - quotient * b
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    return a, old_x, old_y

def chooseE(totient):
    """
    Wähle eine Zufallszahl e für die gilt 1 < e < totient und prüft ob e und der totient
    teilerfremd sind ggT(e, totient) = 1
    """
    while (True):
        e = random.randrange(2, totient)

        if (gcd(e, totient) == 1):
            return e

def chooseKeys():
    """
    Wählt zufällig zwei primzahlen aus einer liste von Primzahlen die bis 100k geht.
    Sie erstellt eine txt Datei und speichert die beiden Zahlen für eine spätere Benutzung.
    Bei Benutzung der Primzahlen verarbeitet und speichert sie den Public und den Privat Key
    in zwei seperaten Dateien.
    """

    # choose two random numbers within the range of lines where 
    # the prime numbers are not too small and not too big
    rand1 = random.randint(100, 300)
    rand2 = random.randint(100, 300)

    # store the txt file of prime numbers in a python list
    fo = open('primes-to-100k.txt', 'r')
    lines = fo.read().splitlines()
    fo.close()

    # store our prime numbers in these variables
    prime1 = int(lines[rand1])
    prime2 = int(lines[rand2])

    # compute n, totient, e
    n = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    e = chooseE(totient)

    # compute d, 1 < d < totient such that ed = 1 (mod totient)
    # e and d are inverses (mod totient)
    gcd, x, y = xgcd(e, totient)

    # make sure d is positive
    if (x < 0):
        d = x + totient
    else:
        d = x

    # write the public keys n and e to a file
    f_public = open('public_keys.txt', 'w')
    f_public.write(str(n) + '\n')
    f_public.write(str(e) + '\n')
    f_public.close()

    f_private = open('private_keys.txt', 'w')
    f_private.write(str(n) + '\n')
    f_private.write(str(d) + '\n')
    f_private.close()

def encrypt(message, file_name = 'public_keys.txt', block_size = 2):
    """
    Verschlüsselt eine Nachricht (string) durch Berechnung des ASCII-Werts jedes Zeichens
    hoch e modulo n und gibt einen Zahlen String zurück.
    
    file_name bezieht sich auf die Datei wo der Public Key liegt. Wenn eine Datei nicht
    vorhanden ist, dann wird die Nachicht mit dem eigenen Public Key verschlüsselt.
    Sonst kann der Public Key von jemand anderem verwendet werden, der in einer anderen
    Datei gespeichert ist
    
    block_size bezieht sich darauf wie viele Zeichen eine gruppe von Zahlen in jedem Index
    von verschlüsselten Blöcken ausmachen.
    """

    try:
        fo = open(file_name, 'r')

    # check for the possibility that the user tries to encrypt something
    # using a public key that is not found
    except FileNotFoundError:
        print('That file is not found.')
    else:
        n = int(fo.readline())
        e = int(fo.readline())
        fo.close()

        encrypted_blocks = []
        ciphertext = -1

        if (len(message) > 0):
            # initialize ciphertext to the ASCII of the first character of message
            ciphertext = ord(message[0])

        for i in range(1, len(message)):
            # add ciphertext to the list if the max block size is reached
            # reset ciphertext so we can continue adding ASCII codes
            if (i % block_size == 0):
                encrypted_blocks.append(ciphertext)
                ciphertext = 0

            # multiply by 1000 to shift the digits over to the left by 3 places
            # because ASCII codes are a max of 3 digits in decimal
            ciphertext = ciphertext * 1000 + ord(message[i])

        # add the last block to the list
        encrypted_blocks.append(ciphertext)

        # encrypt all of the numbers by taking it to the power of e
        # and modding it by n
        for i in range(len(encrypted_blocks)):
            encrypted_blocks[i] = str((encrypted_blocks[i]**e) % n)

        # create a string from the numbers
        encrypted_message = " ".join(encrypted_blocks)

        return encrypted_message

def decrypt(blocks, block_size = 2):
    """
    Entschlüsselt einen String von Zahlen, indem die Zahlen hoch d modulo n gerechnet werden
    und gibt die Nachricht als String zurück.
    block_size gibt an, wie viele Zeichen eine Gruppe von Zahlen in
    jedem Index von Blöcken ausmachen
    """

    fo = open('private_keys.txt', 'r')
    n = int(fo.readline())
    d = int(fo.readline())
    fo.close()

    # turns the string into a list of ints
    list_blocks = blocks.split(' ')
    int_blocks = []

    for s in list_blocks:
        int_blocks.append(int(s))

    message = ""

    # converts each int in the list to block_size number of characters
    # by default, each int represents two characters
    for i in range(len(int_blocks)):
        # decrypt all of the numbers by taking it to the power of d
        # and modding it by n
        int_blocks[i] = (int_blocks[i]**d) % n
        
        tmp = ""
        # take apart each block into its ASCII codes for each character
        # and store it in the message string
        for c in range(block_size):
            tmp = chr(int_blocks[i] % 1000) + tmp
            int_blocks[i] //= 1000
        message += tmp

    return message

def main():
    # we select our primes and generate our public and private keys,
    # usually done once
    choose_again = input('Möchten sie einen neuen Public und Privat Key generieren ? (j oder n) ')
    if (choose_again == 'j'):
        chooseKeys()

    instruction = input('Möchten sie verschlüsseln oder entschlüsseln (v oder e): ')
    if (instruction == 'v'):
        message = input('Was möchten sie verschlüsseln?\n')
        option = input('Möchtest du mit deinem eigenen Public Key verschlüsseln? (j oder n) ')

        if (option == 'j'):
            print('Verschlüsseln...')
            print(encrypt(message))
        else:
            file_option = input('Geben sie den Namen der Datei ein in welcher der Public Key ist: ')
            print('Verschlüsseln...')
            print(encrypt(message, file_option))

    elif (instruction == 'e'):
        message = input('Was möchten sie entschlüsseln?\n')
        print('Entschlüsseln...')
        print(decrypt(message))
    else:
        print('Das ist keine gültige Eingabe.')

main()
