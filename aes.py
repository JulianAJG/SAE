# S-盒
s_box = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]
inverse_s_box = [
    0xA, 0X5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
]
#混淆函数
mix_function = [[1,4],
                [4,1]]
inverse_mix_function = [[9,2],
                        [2,9]]
#密钥扩展
#SubNib:
def SubNib(input_byte, s_box):
    # 将输入拆分为两个4位的部分
    left_half = input_byte[:4]
    right_half = input_byte[4:]

    # 使用自定义的S-盒替代
    substituted_left_half = bin(s_box[int(left_half, 2)])[2:].zfill(4)
    substituted_right_half = bin(s_box[int(right_half, 2)])[2:].zfill(4)

    # 合并替代后的两个部分
    substituted_byte = substituted_left_half + substituted_right_half

    return substituted_byte
def RotNib(input_byte):
    # 将输入拆分为两个4位的部分
    left_half = input_byte[:4]
    right_half = input_byte[4:]

    # 进行左循环移位
    rotated_byte = right_half + left_half

    return rotated_byte

def expand_key(key,s_box):
    Round_Constant_1 = 0b10000000
    Round_Constant_2 = 0b00110000
    w0 = key[0:8]
    w1 = key[8:16]
    w1_substituted = RotNib(w1)
    w1_substituted = SubNib(w1_substituted, s_box)

    w2 = int(w0, 2) ^ Round_Constant_1 ^ int(w1_substituted, 2)
    w2 = bin(w2)[2:].zfill(8)

    w3 = int(w2,2) ^ int(w1,2)
    w3 = bin(w3)[2:].zfill(8)
    w3_substituted1 = RotNib(w3)
    w3_substituted = SubNib(w3_substituted1,s_box)

    w4 = int(w2,2) ^ Round_Constant_2 ^ int(w3_substituted,2)
    w4 = bin(w4)[2:].zfill(8)

    w5 = int(w4,2) ^int(w3,2)
    w5 = bin(w5)[2:].zfill(8)

    return w0,w1,w2,w3,w4,w5

#function
#密钥加
def round_key_addition(plaintext, w0, w1):
    key = [int(w0[0:4],2),int(w0[4:8],2),
           int(w1[0:4],2),int(w1[4:8],2)]
    
    # 对plaintext中的每个字节进行轮密钥加操作
    encrypted_text = []
    for i in range(4):
        encrypted_text.append(int(hex(plaintext[i]^key[i]),16))

    return encrypted_text

#半字节代替
def SubNibble(input_nibble, s_box):
    input_int = int(input_nibble, 2)
    substituted_nibble = s_box[input_int]
    return substituted_nibble

def subNibble_list(plaintext, s_box):
    substituted_result = []
    for number in plaintext:
        hex_str = hex(number)[2:].zfill(2)  # 转换为2位的十六进制字符串
        binary_str = format(int(hex_str, 16), '04b')  # 转换为4位的二进制字符串
        substituted_nibble = SubNibble(binary_str, s_box)
        substituted_result.append(substituted_nibble)
    return substituted_result

#行位移
def shift_rows(matrix):
    # 对矩阵的第二行进行行位移
    matrix = [
            [matrix[0],matrix[2]],
            [matrix[1],matrix[3]]
            ]
    matrix[1] = matrix[1][1:] + matrix[1][:1]

    return matrix

#列混淆
def multiply(a, b):
    bin_a = bin(a)[2:].zfill(4)  # 转换为4位二进制
    bin_b = bin(b)[2:].zfill(4)  # 转换为4位二进制
    result_bin = gf4_multiply(bin_a, bin_b)
    result_decimal = int(result_bin, 2)
    return result_decimal
# GF(2^4) 乘法函数
def gf4_multiply(a, b):
    int_a = int(a, 2)
    int_b = int(b, 2)
    irreducible_poly = int('10011', 2)
    product = 0
    for i in range(4):
        if int_b & 1:
            product ^= int_a
        if int_a & 0x08:
            int_a = (int_a << 1) ^ irreducible_poly
        else:
            int_a <<= 1
        int_b >>= 1
    result = format(product, '04b')
    return result

def mix_column(plaintext,mix_function):
    plaintext_prime = [[0,0],[0,0]]
    plaintext_prime[0][0] = multiply(mix_function[0][0],plaintext[0][0])^multiply(mix_function[0][1],plaintext[1][0])
    plaintext_prime[1][0] = multiply(mix_function[1][0],plaintext[0][0])^multiply(mix_function[1][1],plaintext[1][0])
    plaintext_prime[0][1] = multiply(mix_function[0][0],plaintext[0][1])^multiply(mix_function[0][1],plaintext[1][1])
    plaintext_prime[1][1] = multiply(mix_function[1][0],plaintext[0][1])^multiply(mix_function[1][1],plaintext[1][1])
    return plaintext_prime

def normalization(plaintext):
    plaintext_normalization = [plaintext[0][0],plaintext[1][0],plaintext[0][1],plaintext[1][1]]
    return plaintext_normalization

def normalization_matrix(plaintext):
    plaintext_martix = [[plaintext[0],plaintext[2]],
                        [plaintext[1],plaintext[3]]
                        ]
    return plaintext_martix
#加密
def saes_encrypt(plaintext,key):
    w0,w1,w2,w3,w4,w5 = expand_key(key,s_box)
    plaintext = normalization(plaintext)
    plaintext = round_key_addition(plaintext,w0,w1)
    plaintext = subNibble_list(plaintext,s_box)
    plaintext = shift_rows(plaintext)
    plaintext = mix_column(plaintext,mix_function)
    plaintext = normalization(plaintext)
    plaintext = round_key_addition(plaintext,w2,w3)
    plaintext = subNibble_list(plaintext,s_box)
    plaintext = shift_rows(plaintext)
    plaintext = normalization(plaintext)
    plaintext = round_key_addition(plaintext,w4,w5)
    cyphertext = normalization_matrix(plaintext)
    return cyphertext
    
#解密
def saes_decrypt(cyphertext,key):
    w0,w1,w2,w3,w4,w5 = expand_key(key,s_box)
    cyphertext = normalization(cyphertext)
    cyphertext = round_key_addition(cyphertext,w4,w5)
    cyphertext = shift_rows(cyphertext) 
    cyphertext = normalization(cyphertext)
    cyphertext = subNibble_list(cyphertext,inverse_s_box) 
    cyphertext = round_key_addition(cyphertext,w2,w3) 
    cyphertext = normalization_matrix(cyphertext)
    cyphertext = mix_column(cyphertext,inverse_mix_function)
    cyphertext = normalization(cyphertext) 
    cyphertext = shift_rows(cyphertext)
    cyphertext = normalization(cyphertext)
    cyphertext = subNibble_list(cyphertext,inverse_s_box)
    plaintext = round_key_addition(cyphertext,w0,w1)
    plaintext = normalization_matrix(plaintext)
    return plaintext


if __name__ == "__main__":
    # plaintext = [[10,4],[7,9]]
    # plaintext = '1111111111111111'
    plaintext='0000011100111000'
    num1 = int(plaintext[0:4], 2)
    num2 = int(plaintext[4:8], 2)
    num3 = int(plaintext[8:12], 2)
    num4 = int(plaintext[12:16], 2)
    plaintext = [[num1, num2], [num3, num4]]
    plaintext=[[10,4],[7,9]]
    print(plaintext)
    key = '0010110101010101'
    cyphertext = saes_encrypt(plaintext,key)
    c1 = "{:0>4d}".format(int(bin(cyphertext[0][0])[2:]))
    c2 = "{:0>4d}".format(int(bin(cyphertext[0][1])[2:]))
    c3 = "{:0>4d}".format(int(bin(cyphertext[1][0])[2:]))
    c4 = "{:0>4d}".format(int(bin(cyphertext[1][1])[2:]))
    cc = c1+c2+c3+c4 #密文转为二进制
    print(cc)
    num1 = int(cc[0:4], 2)
    num2 = int(cc[4:8], 2)
    num3 = int(cc[8:12], 2)
    num4 = int(cc[12:16], 2)
    plaintext = [[num1, num2], [num3, num4]]
    print(plaintext)
    plaintext = saes_decrypt(cyphertext,key)
    print(cyphertext)
    print(plaintext)
