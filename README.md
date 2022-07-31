# flaskmap
Flask based Nmap API

## General installation:
``` shell
git clone https://github.com/Moluma/flaskmap
pip3 install -r requeriments.txt
```
API setup:
RSA files (*public.key* and *private.key*) will be generated after launching *generate_rsa.py*. Share the contents of *public.key* with the clients as you wish.
``` shell
python3 generate_rsa.py
python3 nmap_flask_api.py
```
## Client usage: 
The client must have the server's *public.key* file in order to send the request
``` shell
python3 client.py
```
