import aes
def normalization(plaintext):
    plaintext_normalization = [plaintext[0][0],plaintext[0][1],plaintext[1][0],plaintext[1][1]]
    return plaintext_normalization
def normalization_matrix(plaintext):
    plaintext_martix = [[plaintext[0],plaintext[1]],
                        [plaintext[2],plaintext[3]]
                        ]
    return plaintext_martix
#character to integer（十进制）
def asc_to_bin(plaintext_char):
    plaintext_int = []
    a_hex = hex(ord(plaintext_char[0]))
    b_hex = hex(ord(plaintext_char[1]))
    for i in range(2):
        plaintext_int.append(int(a_hex[i+2],16))
        plaintext_int.append(int(b_hex[i+2],16))
    return plaintext_int
#character to integer（十进制）
def bin_to_asc(cyphertext_hex):
    cyphertext_char = []
    a_char = chr(cyphertext_hex[0]*16+cyphertext_hex[2])
    b_char = chr(cyphertext_hex[1]*16+cyphertext_hex[3])
    cyphertext_char.append(a_char)
    cyphertext_char.append(b_char)
    return cyphertext_char

def saes_encrypt_asc(plaintext_char,key):
    plaintext_int = asc_to_bin(plaintext_char)
    plaintext_int = normalization_matrix(plaintext_int)
    cyphertext_int = aes.saes_encrypt(plaintext_int,key)
    cyphertext_int = normalization(cyphertext_int)
    cyphertext_char = bin_to_asc(cyphertext_int)
    return cyphertext_char

def saes_decrypt_asc(cyphertext_char,key):
    cyphertext_int = asc_to_bin(cyphertext_char)
    cyphertext_int = normalization_matrix(cyphertext_int)
    plaintext_int = aes.saes_decrypt(cyphertext_int,key)
    plaintext_int = normalization(plaintext_int)
    plaintext_char = bin_to_asc(plaintext_int)
    return plaintext_char

if __name__ == "__main__":
    key = '0010110101010101'
    plaintext_char = ['A', 'B']
    cyphertext_char =saes_encrypt_asc(plaintext_char,key)
    print(cyphertext_char)
    plaintext_char = saes_decrypt_asc(cyphertext_char,key)
    print(plaintext_char)


