#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import json
import time
import hashlib
from urllib2 import Request, urlopen, HTTPError
from binascii import b2a_hex, a2b_hex
# pycoin dependency 0.80 https://github.com/richardkiss/pycoin
from pycoin.key import Key
from pycoin.encoding import from_bytes_32, public_pair_to_sec
from pycoin.ecdsa import public_pair_for_secret_exponent, generator_secp256k1
import random


CLIENT_PRV_KEY = 'a937fc6a79e0ad67a259bb74a1fb89289d30aafe39395a45959f51e463af18ef'
CLIENT_PUB_KEY = '036afd5d8ddbb3434ebd14a91d0a1e71b4a5d35dc526ac488732e306ad4cf28a59'
SERVER_PUB_KEY = '0201f423cd5bb21aafede6841e105bfa078f372a6c11840960f3c5152714f6754b'

HOST = 'https://business.wallet.io'

def generateKeyPair():
    privKeySeed = random.randint(0, generator_secp256k1.order())
    privateKey = hex(privKeySeed)
    privateKey = privateKey.replace("0x", "").replace("L", "")

    key = Key(privKeySeed, prefer_uncompressed=False, is_compressed=True)
    publicKey = key.sec_as_hex()

    return {
        'privateKey': privateKey,
        'publicKey': publicKey
    }


def _hash(message):
    return hashlib.sha256(message.encode('utf-8')).digest()

def _sign(message, privKey):
    privKey = Key(secret_exponent=from_bytes_32(a2b_hex(privKey)))
    return b2a_hex(privKey.sign(_hash(message))).decode('utf-8')


def _verify(message, signature, pubKey):
    ecKey = Key.from_sec(a2b_hex(pubKey))
    return ecKey.verify(_hash(message), a2b_hex(signature))


def call(url, params, optPrvKey=None, optPubKey=None, optServerKey=None, optHost=None):
    timestamp = str(time.time())
    params = {} if params is None else params
    data = json.dumps(params, sort_keys=True, separators=(',', ':'))
    signatureSubject = 'POST|' + url + '|' + data + '|' + timestamp

    prvKey = (CLIENT_PRV_KEY if optPrvKey is None else optPrvKey)
    pubKey = (CLIENT_PUB_KEY if optPubKey is None else optPubKey)
    serverPubKey = (SERVER_PUB_KEY if optServerKey is None else optServerKey)
    host = (HOST if optHost is None else optHost)

    sign = _sign(signatureSubject, prvKey)

    headers = {'Content-Type': 'application/json',
               'api-auth-key': pubKey,
               'api-auth-timestamp': timestamp,
               'api-auth-sign': sign}
    request = Request(host + url, headers=headers, data=data)
    response = urlopen(request)

    authSign = response.headers['api-resp-sign']
    result = response.read().decode('utf-8')
    jsonResult = json.loads(result, 'utf-8')

    if (authSign is None or authSign == ''):
        raise Exception('no server api-resp-sign header')

    timestamp = response.headers['api-resp-timestamp']
    data = json.dumps(jsonResult, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    signatureSubject = 'POST|' + url + \
        '|' + str(response.code) + '|' + data + '|' + timestamp

    verifyResult = _verify(signatureSubject, authSign, serverPubKey)
    if verifyResult != True:
        raise Exception('server response verification error')

    return json.loads(result)
