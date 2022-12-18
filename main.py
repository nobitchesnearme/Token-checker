import os 
import colorama 
from colorama import Fore
import datetime
from datetime import datetime 
import time
import requests
import ctypes
import sys
import httpx
import threading
import random
import time
import json
import os
import re
import sys
import binascii
import subprocess
import requests
import base64
import platform
import json as jsond
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from uuid import uuid4
from colorama import Fore, init
from itertools import cycle
from Crypto.Util.Padding import pad, unpad
from typing import Optional, Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from base64 import b64encode as enc
from timeit import default_timer as timer
from datetime import timedelta


class api:
    name = ownerid = secret = version = ""

    def __init__(self, name, ownerid, secret, version):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version

    sessionid = enckey = ""

    def init(self):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv,
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            sys.exit()

      

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            sys.exit()

        self.sessionid = json["sessionid"]

    def license(self, key, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv,
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def var(self, name):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv,
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def file(self, fileid):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("file").encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv,
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            sys.exit()
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("webhook").encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv,
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def log(self, message):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("log").encode()),
            "pcuser": encryption.encrypt(os.getenv("username"), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv,
        }

        self.__do_request(post_data)

    def __do_request(self, post_data):

        rq_out = requests.post("https://keyauth.win/api/1.0/", data=post_data)

        return rq_out.text

   
    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = ""

    user_data = user_data_class()

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() != "Windows":
            return subprocess.Popen(
                "hal-get-property --udi /org/freedesktop/Hal/devices/computer --key system.hardware.uuid".split()
            )

        cmd = subprocess.Popen(
            "wmic useraccount where name='%username%' get sid",
            stdout=subprocess.PIPE,
            shell=True,
        )

        (suppost_sid, error) = cmd.communicate()

        suppost_sid = suppost_sid.split(b"\n")[1].strip()

        return suppost_sid.decode()


class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(
                message.encode(), _key.encode(), _iv.encode()
            ).decode()
        except:
            print(
                "Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username"
            )
            time.sleep(5)
            sys.exit()

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(
                message.encode(), _key.encode(), _iv.encode()
            ).decode()
        except:
            print(
                "Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username"
            )
            time.sleep(5)
            sys.exit()

keyauthapp = api(
    "BOOSTBOTT", # App name
    "rjIOGOUq2t", # Owner Id
    "9c2ac0b42b73c0018bf74df166d7ffff543f008933927919cfc5fb61869d379f", # App Secret
    "1.0",
)

keyauthapp.init()

with open("config.json", "r") as config:
    config = json.load(config)

keyauthapp.license(config["license"])


class logger:
    def __init__(self):
        self.times = time.strftime("%H:%M:%S")

    def success(self, msg: str):
        print(f"{Fore.LIGHTBLACK_EX}{self.times}.00 {Fore.GREEN}VDT{Fore.LIGHTBLACK_EX} > {Fore.WHITE}Valid Token{Fore.LIGHTBLACK_EX}= {token}  ")

    def invalid(self, msg: str):
        print(f"{Fore.LIGHTBLACK_EX}{self.times}.00 {Fore.YELLOW}BDT{Fore.LIGHTBLACK_EX} > {Fore.WHITE}Invalid Token{Fore.LIGHTBLACK_EX}= {token}  ")

    def end(self, msg: str):
        print(f"{Fore.LIGHTBLACK_EX}{self.times}.00 {Fore.GREEN}INF{Fore.LIGHTBLACK_EX} > Finsihed Click Enter to End  ")



                  

ctypes.windll.kernel32.SetConsoleTitleW(f"Token Checker | Key={config}  | Expires in= 110821.00 (days)")

os.system('cls')
with open("tokens.txt") as f:
    for line in f:
        token = line.strip("\n")
        headers = {'Content-Type': 'application/json', 'authorization': token}
        url = "https://discordapp.com/api/v6/users/@me/library"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            logger().success(f"{token}")
            with open("results/valid.txt", 'a') as f:
                    f.write(token + '\n')

        else:
            logger().invalid(f"{token}")
            with open("results/invalid.txt", 'a') as f:
                    f.write(token + '\n')
    else:
        logger().end("")
   