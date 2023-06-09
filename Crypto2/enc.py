from os import urandom
from Crypto.Cipher import AES

f = open("plain.txt", "r")
plaintext = f.read()

assert all([x.isupper() or x in '.,-_{ }' for x in plaintext])


class Cipher:
    def __init__(self):
        self.salt = urandom(15)
        key = urandom(16)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, message):
        return [self.cipher.encrypt(c.encode() + self.salt) for c in message]


def main():
    cipher = Cipher()
    encrypted = cipher.encrypt(plaintext)
    encrypted = "\n".join([c.hex() for c in encrypted])

    with open("cipher.txt", 'w+') as f:
        f.write(encrypted)


if __name__ == "__main__":
    main()