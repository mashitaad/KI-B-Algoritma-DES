import random

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
     24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

def permute(block, table):
    return [block[x - 1] for x in table]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def string_to_bit_array(text):
    bit_array = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')
        bit_array.extend([int(x) for x in binval])
    return bit_array

def bit_array_to_string(bit_array):
    return ''.join(chr(int(''.join([str(x) for x in bit_array[i:i+8]]), 2)) for i in range(0, len(bit_array), 8))

def expansion(block):
    return permute(block, E)

def substitute(expanded_half_block):
    subblocks = [expanded_half_block[k * 6:(k + 1) * 6] for k in range(8)]
    result = []
    for i in range(8):
        row = (subblocks[i][0] << 1) + subblocks[i][5]
        col = (subblocks[i][1] << 3) + (subblocks[i][2] << 2) + (subblocks[i][3] << 1) + subblocks[i][4]
        val = S_BOX[i][row][col]
        binval = bin(val)[2:].rjust(4, '0')
        result += [int(x) for x in binval]
    return result

def feistel(right, subkey):
    expanded_right = expansion(right)
    xored = xor(expanded_right, subkey)
    substituted = substitute(xored)
    return permute(substituted, P)

def des_encrypt_decrypt(block, keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for i in range(16):
        temp_right = right
        right = xor(left, feistel(right, keys[i]))
        left = temp_right
    return permute(right + left, IP_INV)

def key_generator():
    return [random.randint(0, 1) for _ in range(64)]

def des(text, key, encrypt=True):
    keys = [key for _ in range(16)]  
    bit_text = string_to_bit_array(text)
    encrypted_bits = des_encrypt_decrypt(bit_text, keys)
    return bit_array_to_string(encrypted_bits)

#Modes of Operation
def pad_text(text, block_size=8):
    padding_len = block_size - (len(text) % block_size)
    return text + chr(padding_len) * padding_len

def unpad_text(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# ECB (Electronic Codebook) Mode
def des_ecb(text, key, encrypt=True):
    text = pad_text(text) if encrypt else text
    block_size = 8
    result = ''
    for i in range(0, len(text), block_size):
        block = text[i:i+block_size]
        result += des(block, key, encrypt)
    return result if encrypt else unpad_text(result)

# CBC (Cipher Block Chaining) Mode
def des_cbc(text, key, iv, encrypt=True):
    text = pad_text(text) if encrypt else text
    block_size = 8
    result = ''
    prev_block = iv
    for i in range(0, len(text), block_size):
        block = text[i:i+block_size]
        if encrypt:
            block = ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(block, prev_block)]) 
            encrypted_block = des(block, key, True)
            prev_block = encrypted_block
            result += encrypted_block
        else:
            decrypted_block = des(block, key, False)
            decrypted_block = ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(decrypted_block, prev_block)])  
            prev_block = block
            result += decrypted_block
    return result if encrypt else unpad_text(result)

# CFB (Cipher Feedback) Mode
def des_cfb(text, key, iv, encrypt=True):
    block_size = 8
    result = ''
    prev_block = iv
    for i in range(0, len(text), block_size):
        encrypted_iv = des(prev_block, key, True)
        block = text[i:i+block_size]
        if encrypt:
            result_block = ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(encrypted_iv, block)])
            prev_block = result_block
            result += result_block
        else:
            result_block = ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(encrypted_iv, block)])
            prev_block = block
            result += result_block
    return result

# OFB (Output Feedback) Mode
def des_ofb(text, key, iv):
    block_size = 8
    result = ''
    prev_block = iv
    for i in range(0, len(text), block_size):
        encrypted_iv = des(prev_block, key, True)
        block = text[i:i+block_size]
        result_block = ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(encrypted_iv, block)])
        prev_block = encrypted_iv
        result += result_block
    return result

# CTR (Counter) Mode
def des_ctr(text, key, nonce):
    block_size = 8
    result = ''
    for i in range(0, len(text), block_size):
        counter = nonce + i // block_size
        counter_block = des(str(counter).rjust(block_size, '\x00'), key, True)
        block = text[i:i+block_size]
        result_block = ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(counter_block, block)])
        result += result_block
    return result

if __name__ == "__main__":
    plaintext = input("Masukkan plaintext: ") 
    iv = ''.join(chr(random.randint(0, 255)) for _ in range(8))  # IV untuk CBC, CFB, OFB
    nonce = random.randint(0, 1000000)  # Nonce untuk CTR

    # Menggunakan key hardcoded untuk ECB
    key_ecb = [0, 1, 0, 1, 0, 1, 0, 1,  
               1, 0, 1, 0, 1, 0, 1, 0,
               0, 1, 0, 1, 0, 1, 0, 1,
               1, 0, 1, 0, 1, 0, 1, 0,
               0, 1, 0, 1, 0, 1, 0, 1,
               1, 0, 1, 0, 1, 0, 1, 0,
               0, 1, 0, 1, 0, 1, 0, 1,
               1, 0, 1, 0, 1, 0, 1, 0]
    
    # Menggunakan key generator untuk mode selain ECB
    key = key_generator()

    print("ECB Mode:")
    encrypted_ecb = des_ecb(plaintext, key_ecb, True)  
    decrypted_ecb = des_ecb(encrypted_ecb, key_ecb, False)
    print(f"Encrypted: {encrypted_ecb}")
    print(f"Decrypted: {decrypted_ecb}")

    print("\nCBC Mode:")
    encrypted_cbc = des_cbc(plaintext, key, iv, True) 
    decrypted_cbc = des_cbc(encrypted_cbc, key, iv, False)
    print(f"Encrypted: {encrypted_cbc}")
    print(f"Decrypted: {decrypted_cbc}")

    print("\nCFB Mode:")
    encrypted_cfb = des_cfb(plaintext, key, iv, True) 
    decrypted_cfb = des_cfb(encrypted_cfb, key, iv, False)
    print(f"Encrypted: {encrypted_cfb}")
    print(f"Decrypted: {decrypted_cfb}")

    print("\nOFB Mode:")
    encrypted_ofb = des_ofb(plaintext, key, iv)
    decrypted_ofb = des_ofb(encrypted_ofb, key, iv)
    print(f"Encrypted: {encrypted_ofb}")
    print(f"Decrypted: {decrypted_ofb}")

    print("\nCTR Mode:")
    encrypted_ctr = des_ctr(plaintext, key, nonce) 
    decrypted_ctr = des_ctr(encrypted_ctr, key, nonce)
    print(f"Encrypted: {encrypted_ctr}")
    print(f"Decrypted: {decrypted_ctr}")

