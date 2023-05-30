#!/usr/bin/env python
# coding: utf-8

# ### SET UP BEFORE PADDING

# ******KERNEL MUST BE RESTARTED PRIOR TO PROCESSING A NEW MESSAGE******


#Static unsigned character list
#These characters are digits of the number pi
S = [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,98, 167, 5, 243, 192, 199, 115, 140, 
     152, 147, 43, 217, 188, 76, 130, 202,30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 
     18,190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,169, 104, 121, 145, 21, 178,
     7, 63, 148, 194, 16, 137, 11, 34, 95, 33,128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 
     151, 3,255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,79, 184, 56, 210, 150, 164,
     125, 182, 118, 252, 107, 226, 156, 116, 4, 241,69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 
     45, 168, 2,27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,85, 71, 163, 35, 221, 81, 
     175, 58, 195, 92, 249, 206, 186, 197, 234, 38,44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 
     129, 77, 82,106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,120, 136, 149, 139, 
     227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 
     248, 235, 117, 75, 10,49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20]

inputs = input()


#Convert input(string) into a bytearray in utf-8 formatting
M = bytearray(inputs, 'utf-8')

print(M)


# ### PADDING PHASE


#Since we are using a 16 byte checksum, assign value of 16 to variable x
x = 16
padded = x - (len(M) % 16)

#must add a block if the length of the message is a multiple of 16

if len(M) % 16 == 0:
    x = x + 1
    
#The padded variable is assigned a value of the new length
#congruent to 0 modulo 16
#we add padding to the message to ensure that we have full blocks


#Define function that appends the message into a byte-array of length = to padded variable

def pad_append(padded):
    byte_arr = bytearray(padded for i in range(padded))
    return byte_arr

M = M + pad_append(padded)
print(M)


# ### CHECKSUM PHASE

#clear the checksum so that the checksum = 0

def clear_checksum(x):
    
    byte_arr = bytearray(0 for i in range(x))
    return byte_arr

C = clear_checksum(x)

print(clear_checksum)


# ### APPENDSUM PHASE

#append 16-byte non-linear checksum
#if the 16-byte non-linear checksum function is not added to the end of the hash, the hash function is 
#vulnerable to being decrypted 
#the MD2 does not use the Merkle-Damg˚ard construction, unlike most other hash functions

#intitialize the last calculated checksum to 0 --> L = 0

L = 0 

#loop through the bytearray of the original message and append to M, the padded message
#loop through n number of times, where n = the length of the bytearray of the original message, divided by 
#the number of bytes (x = 16)
#floor division is used so not to get an integer with a decimal

#n = len(M) // x

for i in range(len(M) // x):
    for j in range(x):
        c = M[i * x + j] 
        C[j] ^= S[c^ L]
        L = C[j]
        

#Append the checksum to the original message bytearray
M = M + C

print(M)


# ### INITIALIZE MD BUFFER

#set buffer_X = 48 as we are using a 48-byte buffer to compute the message digest
#by using 48-byte buffer, we are creating 3 blocks of 16-byte length

buffer_X = 48


#initialize the buffer to 0

def buffer(buffer_X):
    
    byte_arr = bytearray(0 for i in range(buffer_X))
    return byte_arr

buffer = buffer(buffer_X)


# ### PROCESS MESSAGE IN 16-BYTE BLOCKS

#process each 16-byte block for the buffer of 48


for i in range(len(M) // x):
    for j in range(x):
        buffer[x + j] = M[i * x + j]
        buffer[2 * x + j] = buffer[x + j] ^ buffer[j]
        
    #initialize t = 0
    t = 0
    
    #perform 18 rounds of iteration
    rounds = 18
    for j in range(rounds):
        for k in range(buffer_X):
            buffer[k] = buffer[k] ^ S[t]
            t = buffer[k]
        t = (t + j) % len(S)

print(buffer)


# ### OUTPUT

#the function outputs a 32-byte output
#must use zfill(2) as the hex() function defaults by not providing the leading 0
#therefore, outputting a 31-byte message instead of 32-byte
for i in buffer[0:16]:
    output = ''.join(map(lambda x: hex(x).zfill(2).lstrip("0x"), buffer[0:16]))
    
print("The 32-byte hash output of the original message is: \n", "\033[1m" + output)

