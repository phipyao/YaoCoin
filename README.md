# YaoCoin
Fully Functioning Cryptocurrency

"NAME": prints YaoCoin

"GENESIS": creates a genesis block with genesis()

"GENERATE": takes 1 parameter and creates a wallet with generate(wallet)

"ADDRESS": takes 1 parameter and gets public key from wallet with address(wallet)

"FUND": takes 1 parameters and funds a wallet with fund(tag, amount, file)

"TRANSFER": takes 4 parameters and transfers YaoCoins with transfer(wallet, tag, amount, file)

"BALANCE": takes 1 parameter and checks balance with balance(tag)

"VERIFY": takes 2 parameters and verifies transactions and sends them to the mempool with verify(wallet, file)

"MINE": takes 1 parameter and mines more blocks using provided difficulty with mine(difficulty)

"VALIDATE": checks if blockchain is valid with validate()
