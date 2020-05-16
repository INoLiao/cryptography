from ngram_score import ngram_score
from pycipher import Vigenere
import re
from itertools import permutations

qgram = ngram_score('english_quadgrams.txt')
trigram = ngram_score('english_trigrams.txt')
bigram = ngram_score('english_bigrams.txt')
ctext = 'ZOHESTFZOWZUPGEEGZZMGZGDZFRNUDWJHYYFNPHELCETTZBJYDEMPWEEMSVPRRLPILXCWR'
ctext = re.sub(r'[^A-Z]','',ctext.upper())

# keep a list of the N best things we have seen, discard anything else
class nbest(object):
    def __init__(self,N=1000):
        self.store = []
        self.N = N
        
    def add(self,item):
        self.store.append(item)
        self.store.sort(reverse=True)
        self.store = self.store[:self.N]
    
    def __getitem__(self,k):
        return self.store[k]

    def __len__(self):
        return len(self.store)

#init
N=100
for KLEN in range(3,10):
    rec = nbest(N) # rec[k] = kth (score, key, plainText)

    # find parents (N possible parents with higher scores are selected)
    # parents are at length of 3 so use trigram to calculate score
    for i in permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZ',3):
        key = ''.join(i) + 'A'*(KLEN-len(i))
        pt = Vigenere(key).decipher(ctext)
        score = 0
        for j in range(0,len(ctext),KLEN):
            score += trigram.score(pt[j:j+3])
        rec.add((score,''.join(i),pt[:30]))

    # find children
    next_rec = nbest(N)
    for i in range(0,KLEN-3):

        # traverse all parents
        for k in xrange(N):

            # for each parent, extend the key by one letter
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                key = rec[k][1] + c
                fullkey = key + 'A'*(KLEN-len(key))
                pt = Vigenere(fullkey).decipher(ctext)
                score = 0
                
                # only check scores for letters that have been deciphered
                for j in range(0,len(ctext),KLEN):
                    score += qgram.score(pt[j:j+len(key)])

                next_rec.add((score,key,pt[:30]))

        # current key length has been analyzed
        rec = next_rec
        next_rec = nbest(N)

    # calculate best score by quadGram
    bestkey = rec[0][1]
    print bestkey
    pt = Vigenere(bestkey).decipher(ctext)
    bestscore = qgram.score(pt)
    for i in range(N):
        pt = Vigenere(rec[i][1]).decipher(ctext)
        score = qgram.score(pt)
        if score > bestscore:
            bestkey = rec[i][1]
            bestscore = score       
    print bestscore,'Vigenere, klen',KLEN,':"'+bestkey+'",',Vigenere(bestkey).decipher(ctext)
