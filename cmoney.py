import sys
import hashlib
import binascii
import rsa
import time
import os

def genesis():
    """Function to generate the first block"""
    if not os.path.isfile('mempool.txt'):
        open('mempool.txt', "x")
    with open('block_0.txt', 'w') as f:
        msg = "yummy yummy fruit salad 34"
        # new_hash = hashlib.sha256(msg.encode('utf8')).hexdigest()
        # salt = 0
        # print(new_hash[:2])
        # while new_hash[:2] != '00':
        #     salt += 1
        #     msg = f'yummy yummy fruit salad {salt}'
        #     new_hash = hashlib.sha256(msg.encode('utf8')).hexdigest()
            
        # print(new_hash)
        # print(msg)
        f.write(msg)
        print("Genesis block created in 'block_0.txt'")


def generate(wallet):
    """Function to generate a wallet"""

    with open(wallet, 'w') as f:
        (pubkey, privkey) = rsa.newkeys(1024)

        pubkeyBytes = pubkey.save_pkcs1(format='PEM')
        privkeyBytes = privkey.save_pkcs1(format='PEM')

        pubkeyString = pubkeyBytes.decode('ascii')
        privkeyString = privkeyBytes.decode('ascii')

        f.write(pubkeyString)
        f.write(privkeyString)
        pubkeyStringCleaned = pubkeyString.split("\n")[1]

        h = hashlib.sha256()
        h.update(pubkeyStringCleaned.encode('ascii'))
        tag = h.hexdigest()[:16]

        print(f"New wallet generated in '{wallet}' with tag {tag}")

def sign(msg, wallet):
    with open(wallet, 'rb') as f:
        keydata = f.read()
        
    privkey = rsa.PrivateKey.load_pkcs1(keydata)

    signature = rsa.sign(msg.encode(), privkey, 'SHA-256')
    # print(binascii.hexlify(signature).decode())
    return binascii.hexlify(signature).decode()
    
def unsign(msg, signature, wallet):
    with open(wallet, 'rb') as f:
        keydata = f.read()
        
    pubkey = rsa.PublicKey.load_pkcs1(keydata)

    try:
        rsa.verify(msg.encode(), binascii.a2b_hex(signature.encode()), pubkey)
        return True
    except rsa.pkcs1.VerificationError:
        return False

def address(wallet):
    """Function to get the public key from a wallet"""

    with open(wallet, 'rb') as f:
        keydata = f.read()
        
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    pubkeyString = pubkeyBytes.decode('ascii')
    pubkeyStringCleaned = pubkeyString.split("\n")[1]

    h = hashlib.sha256()
    h.update(pubkeyStringCleaned.encode('ascii'))
    tag = h.hexdigest()[:16]

    return tag    

def fund(tag, amount, file):
    """Function to fund the wallet."""

    t = time.localtime()
    current_time = time.strftime("%a %b %d %H:%M:%S %Z %Y", t)

    with open(file, 'w') as f:
        f.write(f"Transferred {amount} from sun_tzu to {tag} and the statement to '{file}' on {current_time}")

    transaction = f'Funded wallet {tag} with {amount} YaoCoins on {current_time}'
    print(transaction)

def transfer(wallet, tag, amount, file):
    """Function to transfer money"""

    t = time.localtime()
    current_time = time.strftime("%a %b %d %H:%M:%S %Z %Y", t)

    with open(file, 'w') as f:
        f.write(f"Transferred {amount} from {address(wallet)} to {tag} and the statement to '{file}' on {current_time}")

    transaction = f"Transferred {amount} from {wallet} to {tag} and the statement to '{file}' on {current_time}"
    print(transaction)

def balance(tag):
    """Function to check balance of a tag"""
    if not os.path.isfile('mempool.txt'):
        open('mempool.txt', "x")
    files = [f for f in os.listdir('.') if os.path.isfile(f) and f.startswith('block')]
    files.append('mempool.txt')
    tag_balance = 0

    for file in files:
        mempool = []
        with open(file, 'r') as f:
            mempool = f.readlines()
        
        for mem in mempool:
            transaction = mem.strip().split()
        
            if tag in transaction:
                amount = int(transaction[1])
                #add or subtract amount
                if transaction[3] == tag:
                    tag_balance -= amount
                else:
                    tag_balance += amount

    return tag_balance



def verify(wallet, file):
    """Function to verify transaction and send to mempool"""
    transaction = ""
    with open(file, 'r') as f:
        transaction = f.read()

    tag = address(wallet)
    if tag in transaction:
        # print('valid signature')
        amount = int(transaction.split()[1])
        if transaction.split()[3] == tag and amount > balance(tag):
            print(f"The transaction in file '{file}' with wallet '{wallet}' is not valid, and was not written to the mempool")
        else:
            # print('valid transaction')
            mempool = ""
            with open('mempool.txt', 'r') as f:
                mempool = f.read()
            mempool += '\n' + transaction
            with open('mempool.txt', 'w') as f:
                f.write(mempool)
            print(f"The transaction in file '{file}' with wallet '{wallet}' is valid, and was written to the mempool")
    else:
        print(f"The transaction in file '{file}' with wallet '{wallet}' is not valid, and was not written to the mempool")

def mine(difficulty):
    """Function to mine more blocks"""
    if [f for f in os.listdir('.') if os.path.isfile(f) and f.startswith('mempool')]:
        pass
    else:
        files = [f for f in os.listdir('.') if os.path.isfile(f) and f.startswith('mempool')]
        if len(files) == 0:
            with open('mempool.txt', 'w') as file:
                file.write("")

    files = [f for f in os.listdir('.') if os.path.isfile(f) and f.startswith('block_')]
    files.sort()
    new_block = f'block_{len(files)}.txt'
    last_block = files[-1]
    for i in range(len(files)):
        if f'block_{i}.txt' != files[i]:
            new_block = f'block_{i}.txt'
            last_block = f'block_{i-1}.txt'
            break

    h = hashlib.sha256()
    with open(last_block, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    last_hash = h.hexdigest()

    mempool = ""
    with open('mempool.txt', 'r') as f:
        mempool = f.read()
    with open('mempool.txt', 'w') as f:
        f.write("")
    
    nonce = 0
    block_content = f'{last_hash}\n\n{mempool}\n\nnonce: {nonce}'
    new_hash = hashlib.sha256(block_content.encode('utf8')).hexdigest()

    leading_zeroes = '0' * int(difficulty)
    while new_hash[:int(difficulty)] != leading_zeroes:
        nonce += 1
        block_content = f'{last_hash}\n\n{mempool}\n\nnonce: {nonce}'
        new_hash = hashlib.sha256(block_content.encode('utf8')).hexdigest()

    with open(new_block, 'w') as f:
        f.write(block_content)

    print(f'Mempool transactions moved to {new_block} and mined with difficulty {difficulty} and nonce {nonce}')

def validate():
    files = [f for f in os.listdir('.') if os.path.isfile(f) and f.startswith('block')]
    files.sort()
    value = True
    for i in range(len(files)-1):
        prev_file = ""
        hashed_file = ""
        with open(files[i], 'r') as f:
            prev_file = f.read()
        with open(files[i+1], 'r') as f:
            hashed_file = f.readlines()[0].strip()
        
        new_hash = hashlib.sha256(prev_file.encode('utf8')).hexdigest()
        # print(files[i], files[i+1])
        if new_hash == hashed_file:
            value = True
        else:
            value = False
            print(value)
            return
    print(value)

func = str(sys.argv)
if len(sys.argv) > 1:
    func = sys.argv[1]
    if not os.path.isfile('mempool.txt'):
        open('mempool.txt', "x")
    type(func)
    if func.upper() == "NAME": print("YaoCoin")
    elif func.upper() == "GENESIS": 
        genesis()
    elif func.upper() == "GENERATE": 
        generate(sys.argv[2])
    elif func.upper() == "ADDRESS": 
        print(address(sys.argv[2]))
    elif func.upper() == "FUND":
        fund(sys.argv[2], sys.argv[3], sys.argv[4])
    elif func.upper() == "TRANSFER":
        transfer(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif func.upper() == "BALANCE":
        print(balance(sys.argv[2]), end = '')
    elif func.upper() == "VERIFY":
        verify(sys.argv[2], sys.argv[3])
    elif func.upper() == "MINE":
        mine(sys.argv[2])
    elif func.upper() == "VALIDATE":
        validate()
    elif func.upper() == "SIGN":
        sign(sys.argv[2], sys.argv[3])
    elif func.upper() == "UNSIGN":
        unsign(sys.argv[2], sys.argv[3], sys.argv[4])