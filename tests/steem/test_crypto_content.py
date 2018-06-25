from steem.steemd import Steemd
from steem.wallet import Wallet
from steem.instance import set_shared_steemd_instance

from steem.transactionbuilder import TransactionBuilder
from steembase import operations
from steembase import memo as Memo
from steembase.account import PrivateKey
from steembase.memo import get_shared_secret, init_aes, _pad, _unpad
from steem.utils import compat_bytes

from contextlib import suppress
from binascii import hexlify, unhexlify
from collections import OrderedDict
from datetime import datetime
from time import gmtime
import calendar
import json

epoch = datetime.utcfromtimestamp(0)

steemd_nodes = [
    'http://127.0.0.1:8765'
    # 'http://91.134.171.33:8765'
]
set_shared_steemd_instance(Steemd(nodes=steemd_nodes))
custom_instance = Steemd(nodes=steemd_nodes)
pr = custom_instance.get_chain_properties()
wallet_instance = Wallet(steemd_instance=custom_instance)

priv1 = PrivateKey('5KN6RkfuuQmZFBAwRe8TXqfrdLmydtUK1mV2gwbauhSaqewCvTM')
priv2 = PrivateKey('5Hw9Hpts79c7JaKfXEK2auRsuw2VNceVXubNsugYM3ax93zZcRq')


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
    # Name account: user001
    # Private owner key  : 5K4fYaZuuiGioP6tf8pqJPGzfuHa9hq9xW8WVSD4utMkooTZ3ZR
    # Public owner key   : BMT54NcV9KJqUSo8CKNAEd7XS6vWnJCn5zJnDHA6YDhZpnVHEduKp
    # Private active key : 5J6qAMLSqfyN1VLKZ7memQA3KDHEbnpHbYUcWKA21oLtwMPwWoU
    # Public active key  : BMT8BRg9kH2rX7bkbkpDqUtF5skZ3xcpoLwJCYGUvVP4j9vkQGG2e
    # Private posting key: 5JX8xFWtm94HP1soVoDSC7YR6mnef4P54qbAez539gKyXzsHmd8
    # Public posting key : BMT7P3FmGtRkT8S1GjSv45CQ8tbPX11i3BZk2vGoSTqWPJG72XWS4
    # Private memo key   : 5KN6RkfuuQmZFBAwRe8TXqfrdLmydtUK1mV2gwbauhSaqewCvTM
    # Public memo key    : BMT5B7NTVNQtQqhpK735amAWoYt15PJsHPPxDKPQobahttU6xKdEK

    # Name account: user002
    # Private owner key  : 5Jx32tTf6iTB9nrT8RWdT9rRSfSw6V7ygEZWEb8HjQ9gQnkj3Lz
    # Public owner key   : BMT83GTCtrKcU4ZiWJveSicvYEFsV3HqbEkLZrBnG6P6spJxHRR3N
    # Private active key : 5HzHCAQHM7fGzEjaaXLZbPKpVNTRpUqGcEboVbbdmSzribhrzRA
    # Public active key  : BMT8RtrrSTW1xvFMJfMnF6WimrwZsHVgDM8XnQa1vBkcW6zQKU8xn
    # Private posting key: 5KYsXypMYYYVrrDW38VrKZcFDNYcRyo3vHiBFSwPkSPfrc8PD1J
    # Public posting key : BMT8LodLQLNNXx6x7zpDpfgeqKhJDGq21Pt16mXLnd1QdxdAReUuA
    # Private memo key   : 5Hw9Hpts79c7JaKfXEK2auRsuw2VNceVXubNsugYM3ax93zZcRq
    # Public memo key    : BMT869dJrWzZXmwM439cfLqabZjB3mF5c7Vi6qQPfqE6tc5cHzgtu

    # user001
    wallet_instance.addPrivateKey(wif='5K4fYaZuuiGioP6tf8pqJPGzfuHa9hq9xW8WVSD4utMkooTZ3ZR')
    wallet_instance.addPrivateKey(wif='5J6qAMLSqfyN1VLKZ7memQA3KDHEbnpHbYUcWKA21oLtwMPwWoU')
    wallet_instance.addPrivateKey(wif='5JX8xFWtm94HP1soVoDSC7YR6mnef4P54qbAez539gKyXzsHmd8')
    wallet_instance.addPrivateKey(wif='5KN6RkfuuQmZFBAwRe8TXqfrdLmydtUK1mV2gwbauhSaqewCvTM')
    # user002
    wallet_instance.addPrivateKey(wif='5Jx32tTf6iTB9nrT8RWdT9rRSfSw6V7ygEZWEb8HjQ9gQnkj3Lz')
    wallet_instance.addPrivateKey(wif='5HzHCAQHM7fGzEjaaXLZbPKpVNTRpUqGcEboVbbdmSzribhrzRA')
    wallet_instance.addPrivateKey(wif='5KYsXypMYYYVrrDW38VrKZcFDNYcRyo3vHiBFSwPkSPfrc8PD1J')
    wallet_instance.addPrivateKey(wif='5Hw9Hpts79c7JaKfXEK2auRsuw2VNceVXubNsugYM3ax93zZcRq')


def unix_time_millis(dt):
    return int((dt - epoch).total_seconds() * 1000000)


def unix_time_seconds(dt):
    return int((dt - epoch).total_seconds())


def post_encrypted_content(owner, author, permlink, price, msg, enc_msg, order_id):
    nonce = unix_time_seconds(datetime.utcnow())

    if owner == '':
        cipher, check, msg_len = encrypt(priv1, priv1.pubkey, nonce, enc_msg)
        plaintext, check2 = decrypt(priv1, priv1.pubkey, nonce, cipher)
        apply_order = False
    else:
        cipher, check, msg_len = encrypt(priv2, priv1.pubkey, nonce, enc_msg)
        plaintext, check2 = decrypt(priv2, priv1.pubkey, nonce, cipher)
        apply_order = True

    if check != check2:
        return

    messages = [
        {
            'parent_author': '',
            'parent_permlink': 'category',
            'author': author,
            'permlink': permlink,
            'title': permlink,
            'body': msg,
            'json_metadata': '',
            'encrypted_message': cipher,
            'sent_time': nonce,
            'message_size': msg_len,
            'checksum': check,
            'price': price,
            'owner': owner,
            'order_id': order_id,
            'apply_order': apply_order
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.EncryptedContent(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner(author, 'posting')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


def create_content_order(author, permlink, owner, price):
    messages = [
        {
            'author': author,
            'permlink': permlink,
            'owner': owner,
            'price': price,
            'json_metadata': ''
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.ContentOrderCreate(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner(owner, 'active')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


def cancel_content_order(owner, order_id):
    messages = [
        {
            'owner': owner,
            'order_id': order_id,
            'json_metadata': ''
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.ContentOrderCancel(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner(owner, 'active')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


def apply_content_order(author, order_id):
    order = custom_instance.get_content_order_by_id(order_id)
    comment = custom_instance.get_content(author, order['permlink'])

    created = datetime.strptime(comment['created'], '%Y-%m-%dT%H:%M:%S')
    nonce = unix_time_seconds(created)
    plaintext, check2 = decrypt(priv1, priv1.pubkey, nonce, comment['encrypted_body'])

    post_encrypted_content(order['owner'], comment['author'], comment['permlink'], order['price'], comment['body'], plaintext, order['id'])


def run():
    if 0:
        import_keys()

    num = '006'

    author = 'user001'
    owner = 'user002'
    permlink = 'crypto-post-python-{}'.format(num)
    price = '10.000 BMT'
    msg = 'Open message {}'.format(num)
    enc_msg = "Closed message from python script {}".format(num)

    post_encrypted_content('', author, permlink, price, msg, enc_msg, 0)

    post = custom_instance.get_content(author, permlink)

    create_content_order(author, permlink, owner, price)
    orders = custom_instance.get_content_orders(owner, author, 100)
    for ord in orders:
        if ord['status'] == 'open':
            cancel_content_order(ord['owner'], ord['id'])

    create_content_order(author, permlink, owner, price)
    orders = custom_instance.get_content_orders(owner, author, 100)
    for ord in orders:
        if ord['status'] == 'open':
            apply_content_order(ord['author'], ord['id'])


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        run()