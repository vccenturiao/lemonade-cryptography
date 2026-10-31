from lemonade import decrypt, encrypt

message = b"Hello Lemonade!"

crypt, key = encrypt(message)

print("Encrypted:")
print(crypt)

print("\nKey:")
print(key)

print("\nDecrypted:")
print(decrypt(crypt, key))