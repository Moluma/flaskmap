import rsa, base64, argparse

parser = argparse.ArgumentParser()
parser.add_argument("--enc_msg", help="Generates encrypted messages with the generated keys", action="store_true")
parser.add_argument("--dec_msg", help="Generates decrypted messages with the generated keys", action="store_true")
args = parser.parse_args()

def generate_keys(size):
    print("Generating keys, this may take a while...\n")
    pub, priv = rsa.newkeys(int(size)) #Secure size must be 2048 or above (4096 is a fine choice)
    #print(pub)
    #print(priv)
    b64pub = base64.b64encode(bytes(str(pub).encode())).decode('utf-8')
    b64priv = base64.b64encode(bytes(str(priv).encode())).decode('utf-8')

    print("Public Key:",b64pub)
    print("")
    print("Private Key:",b64priv)
    print("")


    print("Writing public key to public.key")
    with open("public.key", "wb") as file:
        file.write(b64pub.encode())
        file.close()
        print("Done!")

    print("Writing private key to private.key")
    with open("private.key", "wb") as file:
        file.write(b64priv.encode())
        file.close()
        print("Done!")

def encrypt_messages():
    with open("public.key", "rb") as publickey_file:
        public_key_var = publickey_file.read().decode()
        publickey_file.close()

    while True:
        try:
            print("")
            message = str((input("Message to encrypt: "))).encode()
            print("")

            pub_n, pub_e = (((base64.b64decode(public_key_var)).decode('utf-8').replace("PublicKey(","")).replace(")","")).split(", ")
            #Hace un strip al base64 decoded y saca las variables necesarias para el tipo rsa.PublicKey(n, e)

            crypto = rsa.encrypt(message, rsa.PublicKey(int(pub_n), int(pub_e)))
            b64crypto = base64.b64encode(crypto).decode('utf-8')
            print("Encrypted message:",b64crypto)
        except KeyboardInterrupt:
            print("")
            exit(1)

def decrypt_messages():
    with open("private.key", "rb") as privatekey_file:
        private_key_var = privatekey_file.read().decode()
        privatekey_file.close()

    while True:
        try:
            print("")
            message = str((input("Encrypted message: "))).encode()
            print("")

            n, e, d, p, q = (((base64.b64decode(private_key_var)).decode('utf-8').replace("PrivateKey(","")).replace(")","")).split(", ")
            #Hace un strip al base64 decoded y saca las variables necesarias para el tipo rsa.PrivateKey(n, e, d, p, q)

            plaintext = rsa.decrypt(bytes(base64.b64decode(message)), rsa.PrivateKey(int(n), int(e), int(d), int(p), int(q)))
            print("")
            print("Decrypted message:",plaintext.decode())
        except KeyboardInterrupt:
            print("")
            exit(1)

if args.enc_msg:
    encrypt_messages()
elif args.dec_msg:
    decrypt_messages()
else:
    generate_keys(int(input("Size (>= 2048 recommended): ")))
