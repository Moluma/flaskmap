import requests
import base64
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def RSA_encrypt(message, key):
    crypto = rsa.encrypt(message.encode(), key)
    b64crypto = base64.b64encode(crypto).decode('utf-8')
    return b64crypto

def AES_decrypt(b64_input, b64_key):
    try:
        key = base64.b64decode(b64_key)
        ciphertext, tag = b64_input.split("::")
        ciphertext = base64.b64decode(ciphertext)
        tag = base64.b64decode(tag)

        cipher = AES.new(key, AES.MODE_SIV, nonce=None)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return str(plaintext.decode('utf-8'))
    except ValueError:
        print("Incorrect decryption")
    except KeyError:
        print("Incorrect decryption")
    except:
        print("Something went wrong")

with open("public.key", "rb") as publickey_file:
    public_key_var = publickey_file.read().decode()
    publickey_file.close()
    pub_n, pub_e = (((base64.b64decode(public_key_var)).decode('utf-8').replace("PublicKey(","")).replace(")","")).split(", ")
    key = rsa.PublicKey(int(pub_n), int(pub_e))

api_endpoint = input("Flaskmap endpoint url: ") #"http://localhost:5000/scan/one" #"http://localhost:5000/scan/multiple"

while True:
    try:
        symmetric_key = get_random_bytes(32*2)
        b64_key = base64.b64encode(symmetric_key).decode('utf-8')
        target = input("\nHost(s) to scan (separated by ',' if multiple): ")
        ports = input("Ports: ")
        nmap_args = input("Nmap arguments: ")

        if ports in ["all", "*",]:
            ports = "1-6335"
        if ports == "":
            ports = "0-1000"

        enc_target = RSA_encrypt(target, key)
        enc_ports = RSA_encrypt(ports, key)
        enc_nmap_args = RSA_encrypt(nmap_args, key)
        enc_b64_key = RSA_encrypt(b64_key, key)

        data = {"target":enc_target, "ports":enc_ports, "nmap_args":enc_nmap_args, "AES_key":enc_b64_key}
        response = requests.post(api_endpoint, json=data)

        print("Response:\n")
        output = response.json()
        try:
            if output["time_spent"]:
                print("Time spent:",AES_decrypt(output["time_spent"], b64_key))
            if output["results"]:
                print("\nResults:",AES_decrypt(output["results"], b64_key))
        except KeyError:
            print("\nResults: server is not configured to send results!")
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt received, exiting!")
        exit(1)
