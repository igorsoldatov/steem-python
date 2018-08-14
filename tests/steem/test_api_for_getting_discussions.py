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
import time

epoch = datetime.utcfromtimestamp(0)
mainnet = True

if mainnet:
    address = 'http://91.134.171.33:8765'
    # address = 'http://91.134.171.38:9876'
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


def import_keys_initminer():
    try:
        # initminer
        wallet_instance.addPrivateKey(wif='5KJAwdBWVqX8yNKxVEYgYnA4tJUbiBYmxCWkSyojUYUrquguz73')
    except ValueError:
        donothing = True


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

    # Name account: initminer
    # Private owner key  : 5KJAwdBWVqX8yNKxVEYgYnA4tJUbiBYmxCWkSyojUYUrquguz73
    # Public owner key   : BMT76G5486bhLKXkXgN1nSkeDbpWEaiavF7i6tDULdpvyr69CLbHC

    try:
        # initminer
        wallet_instance.addPrivateKey(wif='5KJAwdBWVqX8yNKxVEYgYnA4tJUbiBYmxCWkSyojUYUrquguz73')
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


def unix_time_millis(dt):
    return int((dt - epoch).total_seconds() * 1000000)


def unix_time_seconds(dt):
    return int((dt - epoch).total_seconds())


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

    # string           tag;
    # uint32_t         limit = 0;
    # set<string>      filter_tags;
    # set<string>      select_authors; ///< list of authors to include, posts not by this author are filtered
    # set<string>      select_tags; ///< list of tags to include, posts without these tags are filtered
    # uint32_t         truncate_body = 0; ///< the number of bytes of the post body to return, 0 for all
    # optional<string> start_author;
    # optional<string> start_permlink;
    # optional<string> parent_author;
    # optional<string> parent_permlink;
    # string           owner; /// for getting private-posts

    # acc = custom_instance.get_account('user0001')
    # if acc is None:
    #     create_account('user0001')
    #     transfer('initminer', 'user0001', '1000.000 BMT')
    #
    # acc = custom_instance.get_account('user001')
    # if acc is None:
    #     create_account('user001')
    #     transfer('initminer', 'user001', '1000.000 BMT')
    #
    # acc = custom_instance.get_account('user002')
    # if acc is None:
    #     create_account('user002')
    #     transfer('initminer', 'user002', '1000.000 BMT')

    for i in range(0):
        new_acc = 'user' + str(i).zfill(3)
        new_permlink = 'post-' + str(i).zfill(4)
        acc = custom_instance.get_account(new_acc)
        if acc is None:
            create_account(new_acc)
            transfer('initminer', new_acc, '1000.000 BMT')
        post_encrypted_content('', new_acc, new_permlink, '1.000 BMT', 'open', 'close', 0)

    for i in range(0):
        owner = 'user' + str(i).zfill(3)
        create_content_order('user001', 'post-0001', owner, '1.000 BMT')
        time.sleep(3)

    orders = custom_instance.get_content_orders_by_comment('user001', 'post-0001', 'user002', 20)

    discussion_query = {
        "tag": 'user001',
        "limit": 2
    }

    disc16 = custom_instance.get_encrypted_discussions(discussion_query)

    last = len(disc16) - 1

    discussion_query = {
        "tag": '',
        'start_author': '',
        'start_permlink': 'sviatsv/test-private-content',
        "limit": 10
    }

    disc16_ = custom_instance.get_encrypted_discussions(discussion_query)

    disc01 = custom_instance.get_discussions_by_active(discussion_query)
    disc02 = custom_instance.get_discussions_by_blog({'tag': 'user001', 'limit': 100})
    disc03 = custom_instance.get_discussions_by_cashout(discussion_query)
    disc04 = custom_instance.get_discussions_by_children(discussion_query)
    disc05 = custom_instance.get_discussions_by_comments({'start_author': 'user001', 'limit': 100})
    disc06 = custom_instance.get_discussions_by_created(discussion_query)
    disc07 = custom_instance.get_discussions_by_feed({'tag': 'user001', 'limit': 100})
    disc08 = custom_instance.get_discussions_by_hot(discussion_query)
    disc09 = custom_instance.get_discussions_by_payout(discussion_query)
    disc10 = custom_instance.get_discussions_by_promoted(discussion_query)
    disc11 = custom_instance.get_discussions_by_trending(discussion_query)
    disc12 = custom_instance.get_discussions_by_votes(discussion_query)
    disc13 = custom_instance.get_comment_discussions_by_payout(discussion_query)
    disc14 = custom_instance.get_post_discussions_by_payout(discussion_query)
    # disc15 = custom_instance.get_discussions_by_author_before_date()
    disc16 = custom_instance.get_encrypted_discussions('', '', 100)
    stop = True


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


def main():
    if 1:
        if mainnet:
            import_keys_mainnet()
        else:
            import_keys()

    # create_account('user004')

    # transfer('initminer', 'user001', '1000.000 BMT')
    # transfer('initminer', 'user002', '1000.000 BMT')

    # comment('user001', 'post-004', 'Post from user001')
    # vote('user002', 'user001', 'post-004', 10000)

    discussion_query = {
        "tag": '',
        "limit": 100,
    }
    disc00 = custom_instance.get_discussions_by_created(discussion_query)

    disc01 = custom_instance.get_discussions_by_cashout(discussion_query)
    disc02 = custom_instance.get_discussions_by_hot(discussion_query)
    disc03 = custom_instance.get_discussions_by_trending(discussion_query)

    disc04 = custom_instance.get_discussions_by_payout(discussion_query)
    disc05 = custom_instance.get_comment_discussions_by_payout(discussion_query)
    disc06 = custom_instance.get_post_discussions_by_payout(discussion_query)

    breakpoint = True


def print_cashout(author, permlink):
    post = custom_instance.get_content(author, permlink)
    print('{} - {} - {} - {} - {} - {}'.format(post['permlink'],
                                     str(post['last_payout']),
                                     str(post['cashout_time']),
                                     str(post['total_payout_value']),
                                     str(post['pending_payout_value']),
                                     str(post['net_rshares'])))


def test_cashout_time1():
    z = 3

    discussion_query = {
        "tag": '',
        "limit": 100,
    }
    disc00 = custom_instance.get_discussions_by_created(discussion_query)

    import_keys_initminer()

    for i in range(10):
        new_account = 'user{}'.format(str(i).zfill(z))
        create_account(new_account)
        transfer('initminer', new_account, '1000.000 BMT')

    for i in range(10):
        author = 'user{}'.format(str(i).zfill(z))
        post = 'post-{}'.format(author)
        comment(author, post, post)
        for j in range(10):
            voter = 'user{}'.format(str(j).zfill(z))
            if voter != author:
                vote(voter, author, post, 10000)

    time.sleep(60*6)

    author = 'user{}'.format(str(1).zfill(z))
    permlink = 'post-{}'.format(author) + '-000'
    comment(author, permlink, permlink)
    for j in range(3):
        voter = 'user{}'.format(str(j).zfill(z))
        if voter != author:
            vote(voter, author, permlink, 10000)

    print_cashout(author, permlink)

    time.sleep(60 * 5)
    print_cashout(author, permlink)

    for j in range(3, 6):
        voter = 'user{}'.format(str(j).zfill(z))
        if voter != author:
            vote(voter, author, permlink, 10000)

    time.sleep(60 * 5)
    print_cashout(author, permlink)

    time.sleep(60 * 4)
    print_cashout(author, permlink)

    time.sleep(60 * 5)
    print_cashout(author, permlink)

    for j in range(6, 9):
        voter = 'user{}'.format(str(j).zfill(z))
        if voter != author:
            vote(voter, author, permlink, 10000)

    time.sleep(60 * 5)
    print_cashout(author, permlink)

    time.sleep(60 * 4)
    print_cashout(author, permlink)

    time.sleep(60 * 5)
    print_cashout(author, permlink)

    for j in range(9, 10):
        voter = 'user{}'.format(str(j).zfill(z))
        if voter != author:
            vote(voter, author, permlink, 10000)

    time.sleep(60 * 5)
    print_cashout(author, permlink)


def test_cashout_time2():
    z = 8
    author = 'user001'
    permlink = 'post-user001-006'

    comment(author, permlink, permlink)
    print_cashout(author, permlink)

    for i in range(1, 61):
        voter = 'user{}'.format(str(i).zfill(z))
        create_account(voter)
        transfer('initminer', voter, '1000.000 BMT')
        vote(voter, author, permlink, 10000)
        print_cashout(author, permlink)
        time.sleep(60)


def test_get_encrypted_content():
    limit = 5
    last_author = ''
    last_permlink = ''
    disc = custom_instance.get_encrypted_discussions({'limit': limit, 'author': 'maggi'})
    while len(disc) > 1:
        for post in disc:
            if last_author != post['author'] or last_permlink != post['permlink']:
                print('{}: {}'.format(post['id'], post['created']))
                last_author = post['author']
                last_permlink = post['permlink']
        disc = custom_instance.get_encrypted_discussions({'limit': limit, 'start_author': last_author, 'start_permlink': last_permlink})


def test_get_encrypted_content_by_author():
    limit = 3
    last_permlink = ''
    author = 'maggi'
    disc = custom_instance.get_encrypted_discussions({'limit': limit, 'tag': author})
    while len(disc) > 1:
        for post in disc:
            if last_permlink != post['permlink']:
                print('{}: {}'.format(post['id'], post['created']))
                last_permlink = post['permlink']
        disc = custom_instance.get_encrypted_discussions({'limit': limit, 'tag': author, 'start_permlink': last_permlink})


def test_create_data_get_encrypted_content_by_owner():
    z = 4
    price = '1.000 BMT'

    owner = 'fannuven'
    acc = custom_instance.get_account(owner)
    if acc is None:
        create_account(owner)
        transfer('initminer', owner, '1000.000 BMT')
        post_encrypted_content('', owner, owner, price, 'open msg', 'close msg', 0)

    for i in range(13, 20):
        author = 'user' + str(i).zfill(z)
        acc = custom_instance.get_account(author)
        if acc is None:
            create_account(author)
            transfer('initminer', author, '1000.000 BMT')
            time.sleep(4)
            create_content_order(owner, owner, author, price)

        permlink = 'post' + str(i).zfill(z)
        post_encrypted_content('', author, permlink, price, 'open msg', 'close msg', 0)
        time.sleep(6)
        create_content_order(author, permlink, owner, price)
        time.sleep(4)
        orders = custom_instance.get_content_orders_by_comment(author, permlink, owner, 1)
        if len(orders) == 1:
            order = orders[0]
            apply_content_order(author, order['id'])
            time.sleep(4)


def test_get_encrypted_content_by_owner():
    limit = 4
    last_author = ''
    last_permlink = ''
    owner = 'fannuven'
    disc = custom_instance.get_encrypted_discussions({'limit': limit, 'owner': owner})
    while len(disc) > 1:
        for post in disc:
            if last_permlink != post['permlink']:
                print('{}: {}'.format(post['id'], post['permlink']))
                last_author = post['author']
                last_permlink = post['permlink']
        disc = custom_instance.get_encrypted_discussions({'limit': limit, 'owner': owner, 'start_author': last_author, 'start_permlink': last_permlink})


def test_get_content_orders():
    owner = 'fannuven'
    author = 'user0013'
    limit = 3
    last_id = -1
    disc = custom_instance.get_content_orders(owner, author, last_id, limit)
    while len(disc) > 1:
        for order in disc:
            if last_id != order['id']:
                print('{}: {}'.format(order['id'], order['permlink']))
                last_id = order['id']
        disc = custom_instance.get_content_orders(owner, author, last_id, limit)
    sdf = 1


def test_get_content_orders_by_comment():
    author = 'fannuven'
    permlink = 'fannuven'
    owner = ''
    limit = 30
    last_owner = ''
    disc = custom_instance.get_content_orders_by_comment(author, permlink, owner, limit)
    while len(disc) > 1:
        for order in disc:
            if last_owner != order['owner']:
                print('{}: {}'.format(order['id'], order['permlink']))
                last_owner = order['owner']
                disc = custom_instance.get_content_orders_by_comment(author, permlink, last_owner, limit)
    asdf = 123


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        test_get_encrypted_content()
