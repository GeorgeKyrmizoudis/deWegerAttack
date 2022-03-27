# -*- coding: utf-8 -*-
"""
Created on Fri Mar 25  2022

@author: George Kyrmizoudis 

In 2002, B. de Weger (B. de Weger, "Cryptanalysis of RSA with Small Prime Difference.", Applicable Algebra in Engineering, Communication and Computing, Vol. 13, pp. 17-28, 2002.) found
an efficient method so as to retrieve the secret exponent in cases where Wiener attack fails to disclose it. de Weger came up to this conclusion by using elementary ineqaulities
to prove that the fraction e/(sqrt{N}-1)^{2} is a better approximation to k/d than e/N. 

Here a demonstration of the the efficiency of de Weger's method on the RSA cryptosystem is presented. We perform an example of de Weger attack on an RSA instance, given a public key (e,N)=(2524051,3860201). Through this process
 d can be revealed and hence we can decrypt a stolen encrypted message c. I hope that you will find this code helpful. Observe the outputs and compare the results! 

Enjoy! Should you feel free to contact me, if any problem or questions come up.

@Disclaimer-License: At this point, we clarify that we just perform a well known attack of  literature. However, I grant you persmission to use this programme for own purpose, citing the developer(s).   
"""
from fractions import Fraction
import math

def main():
   (e,N)=(2524051,3860201) #The given public key
   c= [186456, 2341840, 2341840, 2541292, 1425189, 1273163, 1717368, 2541292, 2341840, 1717368, 985314, 3598544, 1425189, 1385775, 1813172] #The stolen encrypted message
   a=cont_frac(e,N)
   Wiener=Convergents(e,N)
   b=cont_frac(e,N+1-math.floor(2*math.sqrt(N)))
   dW=Convergents(e,N+1-math.floor(2*math.sqrt(N)))
   print(f'The partial quotients of {Fraction(e,N)} are : {a}\n')
   print(f'The convergents of {Fraction(e,N)} are: {Wiener}\n')
   print(f'We will apply  Wiener attack in order to identify the private exponent d.\n')
   d=Wiener_Attack(e,N)
   print(f'We test one by one every possible private exponent. We find out that the secret exponent is d={d}.\n')
   message(d,c,N)
   print(f'Now we perform de Weger`s method to obtain d.\n')
   print(f'We see that the partial quotients of {Fraction(e,N+1-math.floor(2*math.sqrt(N)))} are : {b}\n')
   print(f'Moreover, the convergents of {Fraction(e,N+1-math.floor(2*math.sqrt(N)))} are: {dW}\n')
   D=Wiener_Attack(e,N+1-math.floor(2*math.sqrt(N)))
   print(f'We find that secret exponent d={D}.\n')
   message_2(D,c,N)

def cont_frac(p,q):
    '''This function calculates the partial quotients of a rational number p/q'''
    
    f=Fraction(p,q)
    a=[]
    if f==0:
        return 0
    else:
        i=0
        a.append(math.floor(f))
        f=f-a[i]
        while f>0:
            i=i+1
            a.append(math.floor(1/f))
            f=(1/f)-a[i]
    return a

def dectobin(a):
    '''This function converts a number from its decimal form to its binary one'''
    
    a=int(a)
    if a==0:
        return 0
    r = []
    while a > 0:
        q = a / 2
        b = a % 2
        r.append(int(b))
        if (a%2!=0) & (q!=1):
            q = q - 0.5
        a = q  
    r.reverse()
    return r

def square_and_multiply(a,c,b):
    '''The implementation of the well known square and multiply algorithm'''
    
    z=1
    x=dectobin(c)
    for i in range(len(x)):
        j=len(x)-i-1
        if x[j]==1:
            z=(z*a)%b
        a=(a**2)%b
    return z

def Convergents(p,q): 
    '''Here the convergents of a rational number are computed'''  
            
    rep=cont_frac(p,q)              #We compute the continued fraction representation of p/q
    P=[]
    Q=[]  
    P.append(rep[0])                #p_0=a_0
    P.append(rep[0]*rep[1]+1)       #p_1=a_0*a_1+1
    Q.append(1)                     #q_0=1
    Q.append(rep[1])                #q_1=a_1
    Convergents=[]
    Convergents.append(Fraction(P[0],Q[0]))   
    Convergents.append(Fraction(P[1],Q[1]))   
    for i in range(2,len(rep)):
        P.append(rep[i]*P[i-1]+P[i-2])          #We compute the numerators of the every convergent and we append the number in a list
        Q.append(rep[i]*Q[i-1]+Q[i-2])          #Similarly as above for the denominators 
        Convergents.append(Fraction(P[i],Q[i])) #Here we have a list, which elements are the convergents of p/q
    return Convergents

def deWeger(e,N):
    '''This function performs the de Weger method of retrieving d.'''
    
    NdW=N+1-math.floor(2*math.sqrt(N))
    F=Convergents(e,NdW)
    for i in F:
        den=int(i.denominator)
        mul=den*e
        if square_and_multiply(2,mul,N)==2:
            return den
    return 'FAIL'

def Wiener_Attack(a,b):
    '''This functions conducts a search for d, according to Wiener's method.'''
    
    F=[]
    F=Convergents(a,b)
    for i in F:
        den=int(i.denominator)
        mul=den*a
        if square_and_multiply(2,mul,b)==2:
            return den
    return 'FAIL'

def decryption(c,d,N):
    '''This function performs the decryption process. Specifically, it computes the decryption of every letter of the encrypted message and then
    it converts every number to a character, since every letter is encoded via ord().'''
    
    m=[]
    M=[]
    for i in c:
        m.append(square_and_multiply(i,d,N))
    for i in m:
        M.append(chr(i))
    return M


def message(d,c,N): 
    '''This function prints the appropriate message, according to the output of Wiener attack.'''
    
    if d=='FAIL':
        print(f'Unfortunately,  Wiener attack fails. This is the reason why we cannot decipher  the encrypted message....' )
    else:
        m=decryption(c,d,N)
        print(f'The plaintext is {m}')
        
def message_2(d,c,N): 
    '''This function prints the appropriate message, according to the output of de Weger attack.'''
    
    if d=='FAIL':
        print(f'Unfortunately,  de Weger attack fails. This is the reason why we cannot decipher  the encrypted message....' )
    else:
        m=decryption(c,d,N)
        print(f'The plaintext  is {m}')


if __name__ == '__main__': main()






