import aes
import ascii_aes

def xor(tensor1,tensor2)->list:
    result = [[0,0],[0,0]]
    for i in range(2):
        for j in range(2):
            result[i][j] = tensor1[i][j] ^ tensor2[i][j]
    return result

def normalization_matrix(List):
    tensor = [[List[0],List[1]],[List[2],List[3]]]
    return tensor

def normalization(tensor):
    return [item for sublist in tensor for item in sublist]

def cbc_enpencrypt(plaintext_chain,key,IV):
    chain_length = len(plaintext_chain)
    block_length = int(chain_length/2)
    cyphertext_chain = []
    plaintext_block = []
    middle_block = [[] for _ in range(block_length)]
    cyphertext_block = [[] for _ in range(block_length)]

    #分块
    for i in range(0, chain_length, 2):
        plaintext_block.append(plaintext_chain[i:i+2])
    for p in range(block_length):
        plaintext_block[p] = ascii_aes.asc_to_bin(plaintext_block[p])
        plaintext_block[p] = normalization_matrix(plaintext_block[p])
    for j in range(block_length):
        #异或
        middle_block[j] = xor(plaintext_block[j],IV)
        #加密
        cyphertext_block[j]= aes.saes_encrypt(middle_block[j],key)
        IV = cyphertext_block[j]
    # cyphertext_block = normalization(cyphertext_block)
    for q in range(block_length):
        cyphertext_block[q] = normalization(cyphertext_block[q])
        cyphertext_block[q] = ascii_aes.bin_to_asc(cyphertext_block[q])
    cyphertext_chain = normalization(cyphertext_block)
    return cyphertext_chain
# [[7, 4], [14, 3]] -> [7,4,14,3]
def cbc_decrypt(cyphertext_chain,key,IV):
    chain_length = len(cyphertext_chain)
    block_length = int(chain_length/2)
    plaintext_chain = []
    cyphertext_block = []
    middle_block = [[] for _ in range(block_length)]
    plaintext_block = [[] for _ in range(block_length)]
    #分块
    for i in range(0, chain_length, 2):
        cyphertext_block.append(cyphertext_chain[i:i+2])
    for p in range(block_length):
        cyphertext_block[p] = ascii_aes.asc_to_bin(cyphertext_block[p])
        cyphertext_block[p] = normalization_matrix(cyphertext_block[p])
    for j in range(block_length):
        #解密
        middle_block[j]= aes.saes_decrypt(cyphertext_block[j],key)
        #异或
        plaintext_block[j] = xor(middle_block[j],IV)
        IV = cyphertext_block[j]
    for q in range(block_length):
        plaintext_block[q] = normalization(plaintext_block[q])
        plaintext_block[q] = ascii_aes.bin_to_asc(plaintext_block[q])
    plaintext_chain = normalization(plaintext_block)
    return plaintext_chain

if __name__ == "__main__":
    IV = [
        [1,2],
        [3,4]
    ]
    plaintext_chain = ['A','B','C','D']
    key = '0010110101010101'
    cyphertext_chain = cbc_enpencrypt(plaintext_chain,key,IV)
    print(cyphertext_chain)
    plaintext_chain = cbc_decrypt(cyphertext_chain,key,IV)
    print(plaintext_chain)



