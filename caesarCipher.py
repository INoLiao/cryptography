#########################################
## Author: I-No Liao                   ##
## Date of update: 2020/02/13          ##
## Caesar Cipher Implementation        ##
#########################################

# reference: http://practicalcryptography.com/ciphers/caesar-cipher/

import re
from ngramStatistics import ngramStatistics

# Caesar Cipher
# Implementation includes
#   - Caesar Encryption
#   - Caesar Decryption
#   - Caesar Decipher
class Caesar:

    def __init__(self):
        self.encodeMap = {}
        self.decodeMap = {}
        for index, letter in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
            self.encodeMap[letter] = index
            self.decodeMap[index] = letter

        # define english n-gram dictionary
        self.quadgramFile = "english_quadgrams.txt"

    # Encrypt plain text using Caecar Cipher by key of k.
    # @param plaintext: str
    # @param key: int
    # @return str
    def encrypt(self, plaintext, key):
        if not plaintext or key == 0:
            return None

        # initialize
        ciphertext = ""

        # ensure only uppercase letters
        plaintext = re.sub("[^A-Z]", "", plaintext.upper())

        # encrypt
        for letter in plaintext:
            newCode = (self.encodeMap[letter] + key) % 26
            ciphertext += self.decodeMap[newCode]

        return ciphertext

    # Decrypt ciphertext encrypted by Caesar Cipher (with key)
    # @param ciphertext: str
    # @param key: int
    # @return str
    def decrypt(self, ciphertext, key):
        if not ciphertext or not key:
            return None

        # initialize
        plaintext = ""

        # ensure only uppercase letters
        ciphertext = re.sub("[^A-Z]", "", ciphertext.upper())

        # decrypt
        for letter in ciphertext:
            recoveredCode = (self.encodeMap[letter] - key) % 26
            plaintext += self.decodeMap[recoveredCode]

        return plaintext

    # Decipher ciphertext encrypted by Caesar Cipher (without key)
    # @param ciphertext: str
    # @return dict({int: [float, str]})
    def decipher(self, ciphertext):
        if not ciphertext:
            return None

        # initialize
        results = {}
        quadgram = ngramStatistics(self.quadgramFile, " ")

        # ensure only uppercase letters
        ciphertext = re.sub("[^A-Z]", "", ciphertext.upper())

        # dicipher
        for key in range(1, 27):
            plaintext = self.decrypt(ciphertext, key)
            results[key] = [quadgram.getScore(plaintext), plaintext]

        return results

if __name__ == "__main__":
    print(">> Caesar Cipher Application")
    caesar = Caesar()

    print(">> Encryption:")
    ciphertext = caesar.encrypt("the voyage of oblivion", 8)
    print(">> %s" %(ciphertext))

    print(">> Decryption:")
    plaintext = caesar.decrypt(ciphertext, 8)
    print(">> %s" %(plaintext))

    print(">> Decipher:")
    print("-------------------------------------------------------------------------------")
    results = caesar.decipher(ciphertext)
    for key, result in results.items():
        print("key: " + str(key) + ", score: " + str(result[0]) + ", plain text:" + result[1])
    print("-------------------------------------------------------------------------------")

