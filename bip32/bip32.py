import hmac
import hashlib
import sys

from bip32 import base58check
from bip32 import secp256k1

def hmac_sha512(key, data):
  return hmac.new(key, data, hashlib.sha512).digest()

def hash160(data: bytes):
  return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def SERp(private_key: bytes):
  private_key_num = int.from_bytes(private_key, 'big')
  key = secp256k1.ECKey()
  key.from_int(private_key_num, True)
  return key.get_pubkey().get_bytes(False)

class FromParentPublicKey:
  def __init__(self, parent_public_key: bytes, chain_code: bytes) -> None:
    assert(len(parent_public_key) == 33)
    assert(len(chain_code) == 32)
    self.parent_public_key = parent_public_key
    self.chain_code = chain_code

  def DeriveChildPublicKey(self, index):
    is_hardened = (index >> 31) != 0
    if (is_hardened):
      raise ValueError('Cannot derive hardened child public key from parent public key')
    data = self.parent_public_key + index.to_bytes(4, 'big')
    I = hmac_sha512(self.chain_code, data)
    I_L, I_R = I[:32], I[32:]
    I_L_num = int.from_bytes(I_L, 'big')
    if I_L_num >= secp256k1.SECP256K1_ORDER or I_L_num == 0:
      # Resulting key is invalid
      return None
    parent_public_key = secp256k1.ECPubKey()
    parent_public_key.set(self.parent_public_key)
    I_L_key = secp256k1.ECKey()
    I_L_key.from_int(I_L_num)
    child_public_key = I_L_key.get_pubkey() + parent_public_key
    child_chain_code = I_R
    return FromParentPublicKey(child_public_key.get_bytes(False), child_chain_code)

class FromParentPrivateKey:
  def __init__(self, parent_private_key: bytes, chain_code: bytes) -> None:
    assert(len(parent_private_key) == 32)
    assert(len(chain_code) == 32)
    self.parent_private_key = parent_private_key
    self.chain_code = chain_code

  def DeriveChildPrivateKey(self, index):
    is_hardened = (index >> 31) != 0
    data = b'\x00' + self.parent_private_key + index.to_bytes(4, 'big') if is_hardened else SERp(self.parent_private_key) + index.to_bytes(4, 'big')
    I = hmac_sha512(self.chain_code, data)
    I_L, I_R = I[:32], I[32:]
    I_L_num = int.from_bytes(I_L, 'big')
    if I_L_num >= secp256k1.SECP256K1_ORDER or I_L_num == 0:
      # Resulting key is invalid
      return None
    child_private_key = (I_L_num + int.from_bytes(self.parent_private_key, 'big')) % secp256k1.SECP256K1_ORDER
    child_chain_code = I_R
    # print(f"Parent Key: {self.parent_private_key.hex()} Chain Code: {self.chain_code.hex()} Child Key: {child_private_key.to_bytes(32, 'big').hex()} Chain Code: {child_chain_code.hex()}")
    return FromParentPrivateKey(child_private_key.to_bytes(32, 'big'), child_chain_code)
  
  def DeriveChildPublicKey(self, index):
    is_hardened = (index >> 31) != 0
    assert(not is_hardened)
    derived = self.DeriveChildPrivateKey(index)
    public_key = secp256k1.ECKey.from_int(int.from_bytes(derived.parent_private_key, 'big')).get_public_key()
    return FromParentPublicKey(public_key, derived.chain_code)    


def GenerateMasterKey(seed: bytes):
  I = hmac_sha512(b'Bitcoin seed', seed)
  I_L, I_R = I[:32], I[32:]
  I_L_num  = int.from_bytes(I_L, 'big')
  if (I_L_num >= secp256k1.SECP256K1_ORDER or I_L_num == 0):
    raise ValueError('Invalid private key')
  return FromParentPrivateKey(I_L, I_R)

HRPS = ['xprv', 'xpub', 'tprv', 'tpub']
VERSION_BYTES = {
  'xprv': b'\x04\x88\xAD\xE4',
  'xpub': b'\x04\x88\xB2\x1E',
  'tprv': b'\x04\x35\x83\x94',
  'tpub': b'\x04\x35\x87\xCF'
}

def DeserializeExtKeyFromStr(ext_key):
  hrp = ext_key[:4]
  if (hrp not in HRPS):
    raise ValueError('Invalid HRP')
  
  ext_key_bytes = base58check.decode(ext_key)
  assert(ext_key_bytes[:4] == VERSION_BYTES[hrp])
  assert(len(ext_key_bytes) == 78)

  depth = int.from_bytes(ext_key_bytes[4:5], 'big')
  parent_fingerprint = ext_key_bytes[5:9]
  index = ext_key_bytes[9:13]
  chain_code = ext_key_bytes[13:45]
  key_data = ext_key_bytes[45:]

  if (hrp[2] == 'r'):
    return (FromParentPrivateKey(key_data[1:], chain_code), depth, parent_fingerprint, index)
  return (FromParentPublicKey(key_data, chain_code), depth, parent_fingerprint, index)

def ParsePath(path: str):
  if (path[0] != 'm'):
    raise ValueError('Invalid path')
  if (len(path) == 1):
    return []
  path = path[2:]
  path = path.split('/')
  indexes = []
  for p in path:
    if (p[-1] == "'" or p[-1] == "h" or p[-1] == "H"):
      indexes.append(int(p[:-1]) | 0x80000000)
    else:
      indexes.append(int(p))
  return indexes

def ToExtKeyString(hrp: str, depth: int, parent_fingerprint: bytes, index: bytes, chain_code: bytes, key_data: bytes):
  key_data_prefix = bytes.fromhex('00') if len(key_data) == 32 else bytes([])
  key = VERSION_BYTES[hrp] + depth.to_bytes(1, 'big') + parent_fingerprint + index + chain_code + key_data_prefix + key_data
  ext_key_str = base58check.encode(key)
  assert(len(ext_key_str) == 111)
  assert(ext_key_str[:4] == hrp)
  return ext_key_str

def ToPublicKey(private_key: bytes) -> bytes:
  key = secp256k1.ECKey()
  key.from_int(int.from_bytes(private_key, 'big'))
  return key.get_pubkey().get_bytes(False)

def GetFingerPrint(private_key: bytes) -> bytes:
  return hash160(ToPublicKey(private_key))[:4]

def test():
  vectors = [
    {
      'seed': "000102030405060708090a0b0c0d0e0f",
      'path': "m",
      'ext_pub': "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
      'ext_prv': "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    },
    {
      'seed': "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      'path': "m/0",
      'ext_pub': "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
      'ext_prv': "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    },
    {
      'seed': "000102030405060708090a0b0c0d0e0f",
      'path': "m/0H",
      'ext_pub': "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
      'ext_prv': "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    },
    {
      'seed': "000102030405060708090a0b0c0d0e0f",
      'path': "m/0H/1",
      'ext_pub': "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
      'ext_prv': "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    },
    {
      'seed': "000102030405060708090a0b0c0d0e0f",
      'path': "m/0H/1/2H",
      'ext_pub': "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
      'ext_prv': "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    },
    {
      'seed': "000102030405060708090a0b0c0d0e0f",
      'path': "m/0H/1/2H/2",
      'ext_pub': "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
      'ext_prv': "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    },
    {
      'seed': "000102030405060708090a0b0c0d0e0f",
      'path': "m/0H/1/2H/2/1000000000",
      'ext_pub': "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
      'ext_prv': "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    },
    {
      'seed': "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
      'path': "m",
      'ext_pub': "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
      'ext_prv': "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
    },
    {
      'seed': "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
      'path': "m/0h",
      'ext_pub': "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
      'ext_prv': "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
    }
  ]

  for vector in vectors:
    print(vector['path'])
    uses_hardening = vector['path'].lower().count('h') > 0 or vector['path'].lower().count("'") > 0
    indexes = ParsePath(vector['path'])
    ext_key = GenerateMasterKey(bytes.fromhex(vector['seed']))
    key = secp256k1.ECKey()
    key.from_int(int.from_bytes(ext_key.parent_private_key, 'big'))
    ext_pub_key = FromParentPublicKey(
      key.get_pubkey().get_bytes(False),
      ext_key.chain_code
    )
    depth = 0
    fingerprint = bytes.fromhex('00000000')
    child_index = bytes.fromhex('00000000')
    for index in indexes:
      fingerprint = GetFingerPrint(ext_key.parent_private_key)
      ext_key = ext_key.DeriveChildPrivateKey(index)
      
      if (not uses_hardening):
        ext_pub_key = ext_pub_key.DeriveChildPublicKey(index)

      depth = depth + 1
      child_index = index.to_bytes(4, 'big')
      assert(ext_key is not None)
    
    ext_prv = ToExtKeyString('xprv', depth, fingerprint, child_index, ext_key.chain_code, ext_key.parent_private_key)
    (de_ext_prv, de_depth, de_fingerprint, de_index) = DeserializeExtKeyFromStr(vector['ext_prv'])
    assert(isinstance(de_ext_prv, FromParentPrivateKey))
    assert(de_depth == depth)
    assert(de_fingerprint == fingerprint)
    assert(de_index == child_index)
    assert(de_ext_prv.chain_code == ext_key.chain_code)
    assert(de_ext_prv.parent_private_key == ext_key.parent_private_key)
    assert(ext_prv == vector['ext_prv'])

    if (not uses_hardening):
      ext_pub = ToExtKeyString('xpub', depth, fingerprint, child_index, ext_pub_key.chain_code, ext_pub_key.parent_public_key)
      (de_ext_pub, de_depth, de_fingerprint, de_index) = DeserializeExtKeyFromStr(vector['ext_pub'])
      assert(isinstance(de_ext_pub, FromParentPublicKey))
      assert(de_depth == depth)
      assert(de_fingerprint == fingerprint)
      assert(de_index == child_index)
      assert(de_ext_pub.chain_code == ext_pub_key.chain_code)
      assert(de_ext_pub.parent_public_key == ext_pub_key.parent_public_key)
      assert(ext_pub == vector['ext_pub'])

  print("All tests completed successfully!")
    


def main():
  """
  Usage:
  test - run test vectors
  derive - accepts <ext_key> <path> then derives child key at that path and outputs the result
  """
  command = sys.argv[1]
  if (command == 'test'):
    test()
  elif (command == 'derive'):
    ext_key_str, path = sys.argv[2], sys.argv[3]
    (ext_key, depth, fingerprint, child_index) = DeserializeExtKeyFromStr(ext_key_str)
    indexes = ParsePath(path)
    depth = 0
    for (i, index) in enumerate(indexes):
      if isinstance(ext_key, FromParentPublicKey):
        fingerprint = hash160(ext_key.parent_public_key)[:4]
        ext_key = ext_key.DeriveChildPublicKey(index)
      else:
        fingerprint = GetFingerPrint(ext_key.parent_private_key)
        ext_key = ext_key.DeriveChildPrivateKey(index)

      depth = depth + 1
      child_index = index.to_bytes(4, 'big')
      assert(ext_key is not None)
    
    if isinstance(ext_key, FromParentPublicKey):
      print("Ext Key: ", ToExtKeyString(ext_key_str[:4], depth, fingerprint, child_index, ext_key.chain_code, ext_key.parent_public_key))
      print("Public Key: ", ext_key.parent_public_key.hex())
    else:
      print("Ext Key: ", ToExtKeyString(ext_key_str[:4], depth, fingerprint, child_index, ext_key.chain_code, ext_key.parent_private_key))
      print("Private Key: ", ext_key.parent_private_key.hex())
      print("Public Key: ", ToPublicKey(ext_key.parent_private_key).hex())

  else:
    print("Invalid command")


if __name__ == "__main__":
  main()
