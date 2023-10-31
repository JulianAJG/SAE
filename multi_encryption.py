import aes
#双重加解密（这里的key是32bit）
def double_saes_encrypt(plaintext,key):
    key_0 = key[:16]
    key_1 = key[16:]
    cyphertext = aes.saes_encrypt(plaintext,key_0)
    cyphertext = aes.saes_encrypt(cyphertext,key_1)
    return cyphertext
def double_saes_decrypt(cyphertext,key):
    key_0 = key[:16]
    key_1 = key[16:]
    plaintext = aes.saes_decrypt(cyphertext,key_1)
    plaintext = aes.saes_decrypt(plaintext,key_0)
    return plaintext
#中间相遇攻击（要算很久，不用测试了）（这里的key也是32bit）
def meet_in_the_middle_attack(plaintext,cyphertext)-> list :
    middle_key_list = []
    for i in range(65534):
        key_0 = bin(i)[2:].zfill(16)
        for j in range(65534):
            key_1 = bin(j)[2:].zfill(16)
            plaintext_middle = aes.saes_encrypt(plaintext,key_0)
            cyphertext_middle = aes.saes_decrypt(cyphertext,key_1)
            if plaintext_middle == cyphertext_middle:
                middle_key_list.append(key_0+key_1)   
    return middle_key_list

#三重加密（这里的key是48bit）
def treble_saes_encrypt(plaintext,key):
    key_0 = key[:16]
    key_1 = key[16:32]
    key_2 = key[32:]
    cyphertext = aes.saes_encrypt(plaintext,key_0)
    cyphertext = aes.saes_encrypt(cyphertext,key_1)
    cyphertext = aes.saes_encrypt(cyphertext,key_2)
    return cyphertext
def treble_saes_decrypt(cyphertext,key):
    key_0 = key[:16]
    key_1 = key[16:]
    key_2 = key[32:]
    plaintext = aes.saes_decrypt(cyphertext,key_2)
    plaintext = aes.saes_decrypt(plaintext,key_1)
    plaintext = aes.saes_decrypt(plaintext,key_0)
    return plaintext

if __name__ == "__main__":
    key = '0010110101010101'+'0010110101010101'
    key = '00101101010101010010110101010101'
    plaintext = [[10,4],[7,9]]
    cyphertext = double_saes_encrypt(plaintext,key)
    print(cyphertext)
    plaintext = double_saes_decrypt(cyphertext,key)
    print(plaintext)
    middle_key_list = meet_in_the_middle_attack(plaintext,cyphertext)
    print(middle_key_list)