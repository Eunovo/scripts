"""
Useful for generating SP various descriptors for testing
"""
from bip32 import bip32
from bech32 import bech32

def generate_sp_descriptors(seed: str, paths: list[str]):
  master_key = bip32.GenerateMasterKey(bytes.fromhex(seed))
  keys = []
  for path in paths:
    ext_key = master_key
    indexes = bip32.ParsePath("m"+path)
    depth = 0
    for index in indexes:
      ext_key = ext_key.DeriveChildPrivateKey(index)
      depth += 1
      assert(ext_key)

    ext_key_str = bip32.ToExtKeyString('xprv', 0, b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", master_key.chain_code, master_key.parent_private_key)
    ext_pubkey_str = bip32.ToExtKeyString('xpub', 0, b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", master_key.chain_code, bip32.ToPublicKey(master_key.parent_private_key))
    privkey = ext_key.parent_private_key.hex()
    pubkey = bip32.ToPublicKey(ext_key.parent_private_key).hex()
    keys.append((ext_key_str+path, ext_pubkey_str+path, privkey, pubkey))
  
  for key in keys:
    first_key = key[2]
    for other in keys:
      for second_key in [other[2], other[3]]:
        raw_sp_key = "000000000000000000" + first_key + ("00"+second_key if len(second_key) == 64 else second_key)
        bech32_sp_key = bech32.encode("spprv" if len(second_key) == 64 else "sppub", bytes.fromhex(raw_sp_key))
        print(f"sp({key[0]},{other[0 if len(second_key) == 64 else 1]})\nsp({bech32_sp_key})\n{first_key} {second_key}\n")

SEED = "000102030405060708090a0b0c0d0e0f"
PATHS = [
  "",
  "/352h/0h/0h/1h/0",
  "/352h/0h/0h/0h/0",
  "/352/0/0/0/0",
  "/0h",
  "/0"
]

if __name__ == "__main__":
  generate_sp_descriptors(SEED, PATHS)
