#########################################
## Author: I-No Liao                   ##
## Date of update: 2020/02/13          ##
## Vigenere Cipher Implementation      ##
#########################################

# reference: http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/

import re
import heapq
from itertools import permutations
from ngramStatistics import ngramStatistics

# Vigenere Cipher
# Implementation includes
#   - Vigenere Encryption
#   - Vigenere Decryption
#   - Vigenere Decipher
class Vigenere:

    def __init__(self):
        self.encodeMap = {}
        self.decodeMap = {}
        for index, letter in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
            self.encodeMap[letter] = index
            self.decodeMap[index] = letter

        # define english n-gram dictionary
        self.bigramFile = "english_bigrams.txt"
        self.trigramFile = "english_trigrams.txt"
        self.quadgramFile = "english_quadgrams.txt"

        # decipher settings
        self.maxKeyLen = 20
        self.maxCandidateNum = 100

    # Encrypt plain text using Caecar Cipher by key of k.
    # @param plaintext: str
    # @param key: str
    # @return str
    def encrypt(self, plaintext, key):
        if not plaintext or not key:
            return None

        # initialize
        ciphertext = ""

        # ensure only uppercase letters
        plaintext = re.sub("[^A-Z]", "", plaintext.upper())
        key = re.sub("[^A-Z]", "", key.upper())

        # encrypt
        keyIndex = 0
        for letter in plaintext:
            keyCode = self.encodeMap[key[keyIndex]]
            newCode = (self.encodeMap[letter] + keyCode) % 26
            ciphertext += self.decodeMap[newCode]
            keyIndex = (keyIndex + 1) % len(key)

        return ciphertext

    # Decrypt ciphertext encrypted by Vigenere Cipher (with key)
    # @param ciphertext: str
    # @param key: str
    # @return str
    def decrypt(self, ciphertext, key):
        if not ciphertext or not key:
            return None

        # initialize
        plaintext = ""

        # ensure only uppercase letters
        ciphertext = re.sub("[^A-Z]", "", ciphertext.upper())
        key = re.sub("[^A-Z]", "", key.upper())

        # decrypt
        keyIndex = 0
        for letter in ciphertext:
            keyCode = self.encodeMap[key[keyIndex]]
            recoveredCode = (self.encodeMap[letter] - keyCode) % 26
            plaintext += self.decodeMap[recoveredCode]
            keyIndex = (keyIndex + 1) % len(key)

        return plaintext

    # Decipher ciphertext encrypted by Vigenere Cipher (without key)
    # @param ciphertext: str
    # @return List[(keyLen, bestKey, bestScore, plaintext)]
    def decipher(self, ciphertext):
        if not ciphertext or len(ciphertext) <= 2:
            return None

        # initialize
        results = []
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        maxKeyLen = min(self.maxKeyLen, len(ciphertext))
        bigram = ngramStatistics(self.bigramFile, " ")
        trigram = ngramStatistics(self.trigramFile, " ")
        quadgram = ngramStatistics(self.quadgramFile, " ")

        # ensure only uppercase letters
        ciphertext = re.sub("[^A-Z]", "", ciphertext.upper())

        # decipher
        print(">> ------------------------------ Decipher Report ------------------------------")
        for keyLen in range(2, maxKeyLen + 1):
            candidates = [] # min heap that stores nodes of (score, key)

            # bigram - for bitext
            for bitext in permutations(letters, 2):
                partialKey = "".join(bitext)
                key = partialKey + "A" * (keyLen - len(partialKey))
                plaintext = self.decrypt(ciphertext, key)

                score = 0
                for i in range(0, len(ciphertext), keyLen):
                    score += bigram.getScore(plaintext[i:i + len(partialKey)])

                candidate = (score, partialKey)
                self.pushCandidate(candidates, candidate, self.maxCandidateNum)

            # trigram - for tritext
            if keyLen >= 3:
                newCandidates = [] # min heap that stores nodes of (score, key)
                for i in range(len(candidates)):
                    for char in letters:
                        partialKey = candidates[i][1] + char
                        key = partialKey + "A" * (keyLen - len(partialKey))
                        plaintext = self.decrypt(ciphertext, key)

                        score = 0
                        for j in range(0, len(ciphertext), keyLen):
                            score += trigram.getScore(plaintext[j:j + len(partialKey)])

                        candidate = (score, partialKey)
                        self.pushCandidate(newCandidates, candidate, self.maxCandidateNum)
                candidates = newCandidates

            # quadgram - for quadtext and beyond
            newCandidates = [] # min heap that stores nodes of (score, key)
            for i in range(keyLen - 3):
                for j in range(len(candidates)):
                    for char in letters:
                        partialKey = candidates[j][1] + char
                        key = partialKey + "A" * (keyLen - len(partialKey))
                        plaintext = self.decrypt(ciphertext, key)

                        score = 0
                        for k in range(0, len(ciphertext), keyLen):
                            score += quadgram.getScore(plaintext[k:k + len(partialKey)])

                        candidate = (score, partialKey)
                        self.pushCandidate(newCandidates, candidate, self.maxCandidateNum)

                candidates = newCandidates
                newCandidates = []

            # get best key for current key length
            bestKey, bestScore = None, float("-inf")
            for i in range(len(candidates)):
                key = candidates[i][1]
                plaintext = self.decrypt(ciphertext, key)
                score = quadgram.getScore(plaintext)
                if score > bestScore:
                    bestKey, bestScore = key, score
            plaintext = self.decrypt(ciphertext, bestKey)

            print("(" + str(keyLen) + ", " + str(bestKey) + ", " + str(bestScore) + "), plaintext: " + plaintext)
            results.append((keyLen, bestKey, bestScore, plaintext))

        print(">> -----------------------------------------------------------------------------")
        return results

    # @param minHeap: List[Tuple(float, str)]
    # @param candidate: Tuple(float, str)
    # @param maxHeapSize: int
    # @return None
    def pushCandidate(self, minHeap, candidate, maxHeapSize):
        if not candidate:
            return None

        if (len(minHeap) < maxHeapSize):
            heapq.heappush(minHeap, candidate)
        else:
            if (candidate[0] > minHeap[0][0]):
                heapq.heappushpop(minHeap, candidate)

        return None


if __name__ == "__main__":
    print(">> Vigenere Cipher Application")
    vigenere = Vigenere()

    print(">> Encryption:")
    # ciphertext = vigenere.encrypt("hi my name is ino liao it is my pleasure to meet you i am a master of computer science student at rice", "code")
    ciphertext = vigenere.encrypt("happy valintines day to my sweetest wife thank you for the joys you bring to me every single day love you", "ltc")
    print(">> %s" %(ciphertext))

    print(">> Decryption:")
    plaintext = vigenere.decrypt(ciphertext, "ltc")
    print(">> %s" %(plaintext))

    print(">> Decipher:")
    vigenere.decipher(ciphertext)

    # print(">> Decipher:")
    # vigenere.decipher("ZOHESTFZOWZUPGEEGZZMGZGDZFRNUDWJHYYFNPHELCETTZBJYDEMPWEEMSVPRRLPILXCWR")
