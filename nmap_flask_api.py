import rsa
from flask import Flask, request, jsonify
import base64
import random, string
from datetime import datetime
import nmap
import os
from Crypto.Cipher import AES

scans_storage_path = "/home/kali/tools/flaskmap/scans"
host = 'localhost'
port = 5000
key_size = 4096
random_key_gen_at_start = False #Generates a new pair of keys at every boot, new public key needs to be transfered to clients
send_scans = True #The results are AES-encrypted and sent to the client
store_scans_csv = True #If set to False and send_scans is also set to False no scan data will be stored nor sent so the scans will be wasted

def AES_encrypt(clear_text, b64_key):
    key = base64.b64decode(b64_key)
    cipher = AES.new(key, AES.MODE_SIV, nonce=None)

    ciphertext, tag = cipher.encrypt_and_digest(clear_text.encode())

    b64_cipher = base64.b64encode(ciphertext).decode('utf-8')
    b64_tag = base64.b64encode(tag).decode('utf-8')

    end_result = f"{b64_cipher}::{b64_tag}"
    return str(end_result)

def generate_keys(size):
    print("Generating keys, this may take a while...\n")
    pub, priv = rsa.newkeys(int(size)) #Secure size must be 2048 or above (4096 is a fine choice)
    b64pub = base64.b64encode(bytes(str(pub).encode())).decode('utf-8')
    b64priv = base64.b64encode(bytes(str(priv).encode())).decode('utf-8')

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

if random_key_gen_at_start != False:
    generate_keys(key_size)

if store_scans_csv:
    if not os.path.exists(scans_storage_path+"/"):
        os.mkdir(scans_storage_path+"/")

app = Flask(__name__)
app.secret_key = ''.join((random.choice((list(string.ascii_letters)+list(string.digits)))) for _ in range(100))

with open("public.key", "rb") as publickey_file:
    public_key_var = publickey_file.read().decode()
    publickey_file.close()

with open("private.key", "rb") as privatekey_file:
    private_key_var = privatekey_file.read().decode()
    privatekey_file.close()

n, e, d, p, q = (((base64.b64decode(private_key_var)).decode('utf-8').replace("PrivateKey(","")).replace(")","")).split(", ")
key = rsa.PrivateKey(int(n), int(e), int(d), int(p), int(q))

@app.route("/scan/one", methods=["GET","POST"])
def scan_one():
    if request.method == "GET":
        return jsonify({'message': 'send your base64-encoded server-publickey-encrypted username and password like this:',
                        'sample':'{"target":"127.0.0.1", "ports":"80-443", "nmap_args":"args", "AES_key":"key"}'})
    elif request.method == "POST":
        req = request.json
        try:
            enc_target = req["target"]
            enc_ports = req["ports"]
            enc_args = req["nmap_args"]
            enc_aes_key = req["AES_key"]
            target = rsa.decrypt(bytes(base64.b64decode(enc_target)), key).decode()
            ports = rsa.decrypt(bytes(base64.b64decode(enc_ports)), key).decode()
            args = rsa.decrypt(bytes(base64.b64decode(enc_args)), key).decode()
            aes_key = rsa.decrypt(bytes(base64.b64decode(enc_aes_key)), key).decode()

            print(f"Command: nmap target {ports} {args}")
            print(f'Targets to scan: {target}')
            print(f"Scanning {target}...")

            start_time = datetime.now()
            scanner = nmap.PortScanner()
            results = scanner.scan(target, ports, arguments=args)
            time_spent = datetime.now()-start_time
            target_path = scans_storage_path+"/"+target+"/"

            if not os.path.exists(target_path):
                os.mkdir(target_path)

            if store_scans_csv:
                with open(target_path+start_time.strftime("%Y-%b-%d_%H_%M_%S")+".scan.csv", "w") as f:
                    csv = scanner.csv()
                    f.write(csv)

            if send_scans:
                return jsonify({"time_spent":AES_encrypt(str(time_spent), aes_key),"results":AES_encrypt(str(results), aes_key)})
            else:
                return jsonify({"time_spent":AES_encrypt(str(time_spent), aes_key),})
        except Exception as e:
            return jsonify({'message': 'something went wrong: review your content!',
                            'exception': e})
    else:
        return jsonify({'message': 'wrong method! Only GET and POST allowed!'})

@app.route("/scan/multiple", methods=["GET","POST"])
def scan_multiple():
    del_csv_line = "host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe\r\n"
    if request.method == "GET":
        return jsonify({'message': 'send your base64-encoded server-publickey-encrypted username and password like this:',
                        'sample':'{"targets":"127.0.0.1", "ports":"80-443", "nmap_args":"args", "AES_key":"key"}'})
    elif request.method == "POST":
        req = request.json
        try:
            enc_targets = req["target"]
            enc_ports = req["ports"]
            enc_args = req["nmap_args"]
            enc_aes_key = req["AES_key"]
            targets = (rsa.decrypt(bytes(base64.b64decode(enc_targets)), key).decode()).split(",")
            ports = rsa.decrypt(bytes(base64.b64decode(enc_ports)), key).decode()
            args = rsa.decrypt(bytes(base64.b64decode(enc_args)), key).decode()
            aes_key = rsa.decrypt(bytes(base64.b64decode(enc_aes_key)), key).decode()

            print(f"Command: nmap target {ports} {args}")
            print(f'Targets to scan: {(str(targets)).replace("[","").replace("]","").replace(",",", ")}')

            start_time = datetime.now()
            scanner = nmap.PortScanner()
            results = []
            delete_line = False
            for target in targets:
                target_path = scans_storage_path+"/multiple/"
                if not os.path.exists(target_path):
                    os.mkdir(target_path)

                print(f"Scanning {target}...")
                result = scanner.scan(target, ports, arguments=args)
                results.append(result)

                if store_scans_csv:
                    with open(target_path+start_time.strftime("%Y-%b-%d_%H_%M_%S")+".scan.csv", "a") as f:
                        csv = scanner.csv()
                        if delete_line:
                            csv = csv.replace(del_csv_line, "")
                        f.write(csv)
                        delete_line = True

            time_spent = datetime.now()-start_time

            if send_scans:
                return jsonify({"time_spent":AES_encrypt(str(time_spent), aes_key),"results":AES_encrypt(str(results), aes_key)})
            else:
                return jsonify({"time_spent":AES_encrypt(str(time_spent), aes_key),})
        except Exception as e:
            return jsonify({'message': 'something went wrong: review your content!',
                            'exception': e})
    else:
        return jsonify({'message': 'wrong method! Only GET and POST allowed!'})

#Run app, the following block of code must be the last thing in the file
if __name__ == "__main__":
    app.run(debug=False, host=host, port=port) #debug ONLY for testing
