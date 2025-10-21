# Phoenix Dev

More info:  
[Telegram Channel](https://t.me/phoenix_w3)  
[Telegram Chat](https://t.me/phoenix_w3_space)

[Инструкция на русcком](https://phoenix-14.gitbook.io/phoenix/proekty/ranger_finance)</br>
[Instruction English version](https://phoenix-14.gitbook.io/phoenix/en/projects/ranger_finance)


## Ranger Finance
Ranger Finance is a DeFi protocol built on Solana that aggregates liquidity across multiple DEXs using a Smart Order Router, minimizing slippage and ensuring the best trade execution. It serves as a unified trading hub supporting both spot and perpetual trading, with a Ranger Points reward system and an upcoming $RNGR token launch.


## Functionality
- Withdraw SOL from okx
- Swap SOL with stables
- Swap USDC/USDT
- 

## Requirements
- Python version 3.12 
- Private keys EVM
- Proxy (optional)


## Installation
1. Clone the repository:
```
git clone https://github.com/Phoenix0x-web3/ranger_finance.git
cd ranger_finance
```

2. Install dependencies:
```
python install.py
```

3. Activate virtual environment: </br>

`For Windows`
```
venv\Scripts\activate
```
`For Linux/Mac`
```
source venv/bin/activate
```

4. Run script
```
python main.py
```

## Project Structure
```
ranger_finance/
├── data/                     #Web3 intarface
├── files/
|   ├── logs/                 # Logs
|   ├── deposit_addresses.txt # Addresses for deposit SOL
|   ├── private_keys.txt      # Private keys EVM
|   ├── wallets.db            # Database
│   └── settings.yaml         # Main configuration file
├── functions/                # Functionality
└── utils/                    # Utils
```
## Configuration

### 1. files folder
- `private_keys.txt`: Private keys EVM
- `proxy.txt`: One proxy per line (format: `http://user:pass@ip:port`)
- `deposit_addresses.txt`: One address per line 


### 2. Main configurations
```yaml
# Whether to encrypt private keys
private_key_encryption: true

# Number of threads to use for processing wallets
threads: 1

#BY DEFAULT: [0,0] - all wallets
#Example: [2, 6] will run wallets 2,3,4,5,6
#[4,4] will run only wallet 4
range_wallets_to_run: [0,0]

# Whether to shuffle the list of wallets before processing
shuffle_wallets: true

# Working only if range_wallet_to_run = [0,0] 
# BY DEFAULT: [] - all wallets 
# Example: [1, 3, 8] - will run only 1, 3 and 8 wallets
exact_wallets_to_run: []

# Show wallet address in logs
show_wallet_address_logs: false

# Check for github updates
check_git_updates: true

# The log level for the application. Options: DEBUG, INFO, WARNING, ERROR
log_level : INFO

# Delay before running the new cicle of wallets after it has completed all actions (12 - 24 hrs default)
random_pause_wallet_after_completion:
  min: 43200
  max: 86400

# Random pause between wallets in seconds
random_pause_between_wallets:
  min: 60
  max: 180

# Random pause between actions in seconds
random_pause_between_actions:
  min: 60
  max: 180

# Random pause to start wallet in seconds
random_pause_start_wallet:
  min: 0
  max: 60

# OKX api keys
okx_api_key: ''
okx_api_secret: ''
okx_passphrase: ''

# Withdrawal amount in SOL from okx
withdrawal_amount:
  min: 0.8
  max: 1

# Amount of SOL kept for transaction fees
sol_balance_for_commissions: 0.05

# Minimum SOL balance to refill via swap from stables for fees
minimal_sol_balance: 0.005

# Refill SOL for transaction fees in usd
refill_usd_amount:
  min: 8
  max: 10

# Swaps count per cycle on SPOT
swaps_count:
  min: 5
  max: 10

# Referral codes
invite_codes: []
```

## Usage

For your security, you can enable private key encryption by setting `private_key_encryption: true` in the `settings.yaml`. If set to `false`, encryption will be skipped.

On first use, you need to fill in the `private_keys.txt` file once. After launching the program, go to `DB Actions → Import wallets to Database`.

<img src="https://imgur.com/WQLXWry.png" alt="Preview" width="600"/>

If encryption is enabled, you will be prompted to enter and confirm a password. Once completed, your private keys will be deleted from the private_keys.txt file and securely moved to a local database, which is created in the files folder.

<img src="https://imgur.com/2J87b4E.png" alt="Preview" width="600"/>

If you want to update proxy/twitter/discord/email you need to make synchronize with DB. After you made changes in these files, please choose this option.

<img src="https://imgur.com/lXT6FHn.png" alt="Preview" width="600"/>

Once the database is created, you can start the project by selecting `Ranger Finance → Start SPOT Activity (swaps)`.

<img src="https://imgur.com/dDU3ETf.png" alt="Preview" width="600"/>





