from steem.steemd import Steemd
from steem.wallet import Wallet
from steem.instance import set_shared_steemd_instance

from steem.transactionbuilder import TransactionBuilder
from steembase import operations
from steembase.account import PrivateKey
from steembase.memo import get_shared_secret, init_aes, _pad, _unpad
from steem.utils import compat_bytes

from contextlib import suppress
from binascii import hexlify, unhexlify
from collections import OrderedDict
from datetime import datetime
import json

epoch = datetime.utcfromtimestamp(0)

steemd_nodes = [
    'http://127.0.0.1:8765'
]
set_shared_steemd_instance(Steemd(nodes=steemd_nodes))
custom_instance = Steemd(nodes=steemd_nodes)
pr = custom_instance.get_chain_properties()
wallet_instance = Wallet(steemd_instance=custom_instance)


def encrypt(priv, pub, nonce, message):
    shared_secret = get_shared_secret(priv, pub)
    aes, check = init_aes(shared_secret, nonce)
    raw = compat_bytes(message, 'utf8')
    " Padding "
    BS = 16
    if len(raw) % BS:
        raw = _pad(raw, BS)
    " Encryption "
    enc_msg = aes.encrypt(raw)
    cipher = hexlify(enc_msg).decode('ascii')
    return cipher, check, len(enc_msg)


def decrypt(priv, pub, nonce, message):
    shared_secret = get_shared_secret(priv, pub)
    aes, check = init_aes(shared_secret, nonce)
    plaintext = aes.decrypt(unhexlify(compat_bytes(message, 'ascii')))
    plaintext = _unpad(plaintext.decode('utf8'), 16)
    return plaintext, check


def comment():
    messages = [
        {
            'parent_author': '',
            'parent_permlink': 'common-post',
            'author': 'user011',
            'permlink': 'post-028',
            'title': 'post',
            'body': 'post',
            'json_metadata': '{"tags":["tag00"],"app":"steemit/0.1","format":"markdown"}'
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.Comment(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner('user011', 'posting')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


def import_keys():
    # Name account: user011
    # Private owner key  : 5KRTDwnJFT6sqg85R7vwmJZxq3kNHvFDvN6UTMZNN45NdqJcp3M
    # Public owner key   : BMT7DP6y5Ai1zK1sCvcxaosr4jYvEbMf5v4QftRi31Mek4BTZ8TFA
    # Private active key : 5JYrXkcEkYL7wfcqUdriDqDXTH7hSSpCzh5M8XxkDy2jd24MRrh
    # Public active key  : BMT5b5gUDJmXNZ4e41P4YF765u5rueXasG4pTwvn6RmmjjPNPrdyt
    # Private posting key: 5KA9a1774Ux4khFZFdVrhgUC6CTJDJyZWq5ngFVC173cmMFxdcL
    # Public posting key : BMT8VAb7Yan2HRBSSGqi2dJeSB7uHXnTZcVRkGq89cuimpRmDFYR4
    # Private memo key   : 5Kidmv7RHnXpaXSkiJQ61mnJZGcjLcPJn6WRmZzqCH13JJcBKfE
    # Public memo key    : BMT7unMyzVRmnZHTKg6gLXgZUYBAAbPQdGdixuxsX7ifWskpnGcPX
    #
    # Name account: user012
    # Private owner key  : 5K8MvZJi6sinTegAVgr19gnxj2NqwYpMcv9fvUsfEumLDkcbMCm
    # Public owner key   : BMT6SjacruP5rdQtxv3DpzSFTNUeVSES5diGs7XiiD8qv8FzsYxKY
    # Private active key : 5JrbbaGmYjEqHAxFSsn3RgoFpXZFX7Gz5EKYJo71ke5iNNpaZeN
    # Public active key  : BMT7okuTqLNNsDhRALZ2XX2Up7JVbUa8jjtjwK3jk6H8Djg7qmPW2
    # Private posting key: 5K1UvdpQLyRMBe17BGeumZirtHBa2id2DvVRGi6CeTYVuchQM3o
    # Public posting key : BMT8dm6C19ZGR9yGjvcK8HwgGGg2Y1CSpCpxXLrWsw1jgxKdUjTKo
    # Private memo key   : 5KbqodapZuWe4R7cKux4YPPRw1vcvhRcguy89RUBXufutu5esEX
    # Public memo key    : BMT7hQntbAnehUp2xbrrGi8am2nV2jLS5pGGXTFi38KYwcyoLEjjL

    # user011
    wallet_instance.addPrivateKey(wif='5KRTDwnJFT6sqg85R7vwmJZxq3kNHvFDvN6UTMZNN45NdqJcp3M')
    wallet_instance.addPrivateKey(wif='5JYrXkcEkYL7wfcqUdriDqDXTH7hSSpCzh5M8XxkDy2jd24MRrh')
    wallet_instance.addPrivateKey(wif='5KA9a1774Ux4khFZFdVrhgUC6CTJDJyZWq5ngFVC173cmMFxdcL')
    wallet_instance.addPrivateKey(wif='5Kidmv7RHnXpaXSkiJQ61mnJZGcjLcPJn6WRmZzqCH13JJcBKfE')
    # user012
    wallet_instance.addPrivateKey(wif='5K8MvZJi6sinTegAVgr19gnxj2NqwYpMcv9fvUsfEumLDkcbMCm')
    wallet_instance.addPrivateKey(wif='5JrbbaGmYjEqHAxFSsn3RgoFpXZFX7Gz5EKYJo71ke5iNNpaZeN')
    wallet_instance.addPrivateKey(wif='5K1UvdpQLyRMBe17BGeumZirtHBa2id2DvVRGi6CeTYVuchQM3o')
    wallet_instance.addPrivateKey(wif='5KbqodapZuWe4R7cKux4YPPRw1vcvhRcguy89RUBXufutu5esEX')


def unix_time_millis(dt):
    return int((dt - epoch).total_seconds() * 1000000)


def private_message():
    msg_obj = OrderedDict([
        ("subject", "python"),
        ("body", "Message from python script 00000000000000000000000000000000000015"),
    ])
    json_enc = json.JSONEncoder()
    json_msg = json_enc.encode(msg_obj)

    nonce = unix_time_millis(datetime.utcnow())
    priv1 = PrivateKey('5Kidmv7RHnXpaXSkiJQ61mnJZGcjLcPJn6WRmZzqCH13JJcBKfE')
    priv2 = PrivateKey('5KbqodapZuWe4R7cKux4YPPRw1vcvhRcguy89RUBXufutu5esEX')

    cipher, check, msg_len = encrypt(priv1, priv2.pubkey, nonce, json_msg)
    plaintext, check2 = decrypt(priv2, priv1.pubkey, nonce, cipher)

    if check != check2:
        return

    messages = [
        {
            'from': 'user011',
            'to': 'user012',
            'from_memo_key': 'BMT7unMyzVRmnZHTKg6gLXgZUYBAAbPQdGdixuxsX7ifWskpnGcPX',
            'to_memo_key': 'BMT7hQntbAnehUp2xbrrGi8am2nV2jLS5pGGXTFi38KYwcyoLEjjL',
            'sent_time': nonce,
            'checksum': check,
            'message_size': msg_len,
            'encrypted_message': cipher
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.PrivateMessage(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner('user011', 'posting')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


def run():
    if 0:
        import_keys()

    private_message()


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        run()