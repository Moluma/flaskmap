# flaskmap
Flask based Nmap API

## General installation:
``` shell
git clone https://github.com/Moluma/flaskmap
pip3 install -r requeriments.txt
```
## API setup:
RSA files (`public.key` and `private.key`) will be generated after launching `generate_rsa.py`. Share the contents of `public.key` with the clients as you wish.
``` shell
python3 generate_rsa.py
python3 nmap_flask_api.py
```
Change the config variables at the beginning of the `nmap_flask_api.py` file as you wish.
``` shell
scans_storage_path = "/home/kali/tools/flaskmap/scans"
host = 'localhost'
port = 5000
key_size = 4096
random_key_gen_at_start = False #Generates a new pair of keys at every boot, new public key needs to be transfered to clients
send_scans = True #The results are AES-encrypted and sent to the client
store_scans_csv = True #If set to False and send_scans is also set to False no scan data will be stored nor sent so the scans will be wasted
```
## Client usage: 
The client must have the server's `public.key` file in order to send requests
``` shell
python3 client.py
```
Default API endpoints are:
``` shell
http://localhost/scan/one
http://localhost/scan/multiple
```
