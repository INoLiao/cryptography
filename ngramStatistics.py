#########################################
## Author: I-No Liao                   ##
## Date of update: 2020/02/13          ##
## N-gram Statistics Implementation    ##
#########################################

# reference: http://www.practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/

import math

# N-gram Statistics
# Based on the language of English, ngram statistics can calculate the fitness score of a text to English. The higher the score, the fitter the text is to English.
class ngramStatistics:

    # Constructor
    # @param ngramFile: str
    # @param delimiter: str
    def __init__(self, ngramFile, delimiter = " "):
        if not ngramFile:
            print(">> Error: ngramFile is empty")
            return None

        # initialize
        self.ngramMap = {} # { word: frequency }
        self.ngramProbMap = {} # { word: probability }
        
        # read file
        with open(ngramFile, "r") as f:
            for data in f:
                word, frequency = data.split(delimiter)
                self.ngramMap[word] = int(frequency)

        # word length
        self.wordLen = len(word)

        # calculate probabilities
        self.totalFrequency = sum(self.ngramMap.values())

        # 1. for words not in ngramFile: min probability for frequency of 0
        self.minScore = math.log10(0.01 / self.totalFrequency)

        # 2. for words in ngramFile
        for word, frequency in self.ngramMap.items():
            self.ngramProbMap[word] = math.log10(frequency / self.totalFrequency)

    # Get the score of the input text
    # @param text: str
    # @return float
    def getScore(self, text):
        if not text:
            print(">> Error: text is empty")
            return None

        # initialize
        score = 0

        # calculate score
        for i in range(len(text) - self.wordLen + 1):
            score += self.ngramProbMap[text[i:i + self.wordLen]] if text[i:i + self.wordLen] in self.ngramProbMap else self.minScore

        return score
