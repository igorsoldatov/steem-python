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
mainnet = False

if mainnet:
    address = 'http://91.134.171.33:8765'
else:
    address = 'http://127.0.0.1:8765'
steemd_nodes = [address]
set_shared_steemd_instance(Steemd(nodes=steemd_nodes))
custom_instance = Steemd(nodes=steemd_nodes)
pr = custom_instance.get_chain_properties()
wallet_instance = Wallet(steemd_instance=custom_instance)

if mainnet:
    priv1 = PrivateKey('5J2wPb6BVAyZZYpmJHRks1DgCLEHRmzAyrwzbsvX3xaHibH8XLM')
    priv2 = PrivateKey('5Hw9Hpts79c7JaKfXEK2auRsuw2VNceVXubNsugYM3ax93zZcRq')
else:
    priv1 = PrivateKey('5KN6RkfuuQmZFBAwRe8TXqfrdLmydtUK1mV2gwbauhSaqewCvTM')
    priv2 = PrivateKey('5KDkjj6MV2EsoabJqMqfVrXz2hnsmsPFyqiycyduy5ycKjNRYpD')


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

    try:
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
    except ValueError:
        donothing = True


def import_keys_mainnet():
    # Name account: user001
    # Public ownerkey    : BMT5uoRoGVGyuVNbY43TkH9WBU2QEiTjHQv28pMHXnZ7G7nLneKbA
    # Private owner key  : 5JnWUyuk9jT3nW7x2pwFkz7qVLV7pgpKAXnM8dXAShwZqcXCYee
    # Public active key  : BMT8eBDBAoGhPJotea3xMumpxeD7KZ3JQHK3Nu3oB9rd6hm7D7yoG
    # Private active key : 5JxeAeCgHhxnTXYux5FsXZWq84VmxYhJZdouZ8bXAkcjrzPVoj8
    # Public posting key : BMT7rLYKSpuoukZ5iTraidz432uRFrGLunKP1Zy3v3cLjiGjfJPrN
    # Private posting key: 5J2srqnG4cKyRdqKPZ9bwmytPmudpQthF96BUA9Sek3cseZjrPR
    # Public memo key    : BMT7o4Az56RoUhLay68NaUFh56sgCjStvEBt7kGzVGBqPuuQjgbpr
    # Private memo key   : 5J2wPb6BVAyZZYpmJHRks1DgCLEHRmzAyrwzbsvX3xaHibH8XLM
    #
    # Name account: user002
    # Public owner key   : BMT6QnUbX5e1Fo9J8tD6Gz1ygkttEjvYCoDHGZPFkN9SqWjPuNg3L
    # Private owner key  : 5JU8abbTWxEiwakSWUNvfebuLuTb75Dz8jBG5bZ73M2kcyhYaav
    # Public active key  : BMT6qSVaREQzPteRvjScAcdVaR72NMvZoT48Lz1WU8zP6wGpF9jAd
    # Private active key : 5KfvQrWFMifCKqPkDBaagkxK8J2JoSaPeZoKs93rrTmKgbYEh9P
    # Public posting key : BMT8LiPDB2YEwFR7DRkgdTHb1NfX96dPFPoiTgQrFnukaXmAQkKdH
    # Private posting key: 5Jdhhq9MJCK6NN5TtUZXjtX7QXaJvvL29JBaJu6PKDGvJeB6rnr
    # Public memo key    : BMT58GceeEnG9TRDHjGcnTY3sWfPtwKEdD6kemCyuTihfsma7Db9d
    # Private memo key   : 5KDkjj6MV2EsoabJqMqfVrXz2hnsmsPFyqiycyduy5ycKjNRYpD

    try:
        # user001
        wallet_instance.addPrivateKey(wif='5JnWUyuk9jT3nW7x2pwFkz7qVLV7pgpKAXnM8dXAShwZqcXCYee')
        wallet_instance.addPrivateKey(wif='5JxeAeCgHhxnTXYux5FsXZWq84VmxYhJZdouZ8bXAkcjrzPVoj8')
        wallet_instance.addPrivateKey(wif='5J2srqnG4cKyRdqKPZ9bwmytPmudpQthF96BUA9Sek3cseZjrPR')
        wallet_instance.addPrivateKey(wif='5J2wPb6BVAyZZYpmJHRks1DgCLEHRmzAyrwzbsvX3xaHibH8XLM')
        # user002
        wallet_instance.addPrivateKey(wif='5JU8abbTWxEiwakSWUNvfebuLuTb75Dz8jBG5bZ73M2kcyhYaav')
        wallet_instance.addPrivateKey(wif='5KfvQrWFMifCKqPkDBaagkxK8J2JoSaPeZoKs93rrTmKgbYEh9P')
        wallet_instance.addPrivateKey(wif='5Jdhhq9MJCK6NN5TtUZXjtX7QXaJvvL29JBaJu6PKDGvJeB6rnr')
        wallet_instance.addPrivateKey(wif='5KDkjj6MV2EsoabJqMqfVrXz2hnsmsPFyqiycyduy5ycKjNRYpD')
    except ValueError:
        donothing = True


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


def create_account(new_account_name):
    key1 = PrivateKey()
    key2 = PrivateKey()
    key3 = PrivateKey()
    key4 = PrivateKey()
    messages = [
        {
            'fee': '10.000 BMT',
            'creator': 'initminer',
            'new_account_name': new_account_name,
            'json_metadata': '',
            'memo_key': str(key4.pubkey),
            'owner': {
                'account_auths': [],
                'key_auths': [[str(key1.pubkey), 1]],
                'weight_threshold': 1
            },
            'active': {
                'account_auths': [],
                'key_auths': [[str(key2.pubkey), 1]],
                'weight_threshold': 1
            },
            'posting': {
                'account_auths': [],
                'key_auths': [[str(key3.pubkey), 1]],
                'weight_threshold': 1
            }
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.AccountCreate(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner('initminer', 'posting')
    tb.sign()
    tx = tb.broadcast()

    wallet_instance.addPrivateKey(wif=str(key1))
    wallet_instance.addPrivateKey(wif=str(key2))
    wallet_instance.addPrivateKey(wif=str(key3))
    wallet_instance.addPrivateKey(wif=str(key4))

    print(tx)


def comment(author, permlink, body):
    messages = [
        {
            'parent_author': '',
            'parent_permlink': 'category001',
            'author': author,
            'permlink': permlink,
            'title': permlink,
            'body': body,
            'json_metadata': '{"tags":["tag000"],"app":"steemit/0.1","format":"markdown"}'
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.Comment(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner(author, 'posting')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


def vote(voter, author, permlink, weight):
    messages = [
        {
            'voter': voter,
            'author': author,
            'permlink': permlink,
            'weight': weight,
            'comment_bmchain': ''
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.Vote(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner(voter, 'posting')
    tb.sign()
    try:
        tx = tb.broadcast()
        print(tx)
    except ValueError:
        print("Can't vote")


def transfer(_from, _to, amount):
    messages = [
        {
            'from': _from,
            'to': _to,
            'amount': amount,
            'memo': ''
        }]

    tb = TransactionBuilder(no_broadcast=False, steemd_instance=custom_instance, wallet_instance=wallet_instance)
    ops = [operations.Transfer(**x) for x in messages]
    tb.appendOps(ops)
    tb.appendSigner(_from, 'posting')
    tb.sign()
    tx = tb.broadcast()

    print(tx)


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
        new_permlink = permlink
    else:
        cipher, check, msg_len = encrypt(priv2, priv1.pubkey, nonce, enc_msg)
        plaintext, check2 = decrypt(priv2, priv1.pubkey, nonce, cipher)
        apply_order = True
        new_permlink = permlink + '-' + str(nonce)

    if check != check2:
        return

    messages = [
        {
            'parent_author': '',
            'parent_permlink': 'category',
            'author': author,
            'permlink': new_permlink,
            'title': new_permlink,
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
    if 1:
        if mainnet:
            import_keys_mainnet()
        else:
            import_keys()

    acc = custom_instance.get_account('user001')
    if acc is None:
        create_account('user001')
        transfer('initminer', 'user001', '1000.000 BMT')

    acc = custom_instance.get_account('user002')
    if acc is None:
        create_account('user002')
        transfer('initminer', 'user002', '1000.000 BMT')

    num = '001'

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

    enc_comments = custom_instance.get_encrypted_discussions({'owner': owner, 'limit': 100})
    for enc_comment in enc_comments:
        created = datetime.strptime(enc_comment['created'], '%Y-%m-%dT%H:%M:%S')
        nonce = unix_time_seconds(created)
        plaintext, check2 = decrypt(priv2, priv1.pubkey, nonce, comment['encrypted_body'])
        print('message: {}'.replace(plaintext))


def main():
    num = '001'
    author = 'user001'
    owner = 'user002'
    permlink = 'crypto-post-python-{}'.format(num)
    price = '10.000 BMT'
    msg = 'Open message {}'.format(num)
    enc_msg = "Closed message from python script {}".format(num)

    create_account(author)
    create_account(owner)
    transfer('initminer', author, '1000.000 BMT')
    transfer('initminer', owner, '1000.000 BMT')
    post_encrypted_content('', author, permlink, price, msg, enc_msg, 0)


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        run()