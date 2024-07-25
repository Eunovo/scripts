import hashlib

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def generate_checksum(data: bytes):
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

def encode(data: bytes):
  data = data + generate_checksum(data)
  leading_zeros = len(data) - len(data.lstrip(b'\x00'))
  encoded = ''
  num = int.from_bytes(data, 'big')
  while num > 0:
    num, remainder = divmod(num, 58)
    encoded = alphabet[remainder] + encoded
  base58str = alphabet[0] * leading_zeros + encoded
  return base58str

def decode(data: str):
  num = 0
  for char in data:
    num *= 58
    num += alphabet.index(char)
  
  ret = num.to_bytes((num.bit_length() + 7) // 8, 'big')
  expected_checksum = generate_checksum(ret[:-4])
  assert(expected_checksum == ret[-4:])
  return ret[:-4]