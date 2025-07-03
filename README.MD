 # About
Matrix-Lightning-Tip-Bot (MLTB) is a lightning network BTC tip bot for the matrix network. It is inspired by the LightningTipBot Telegram project at https://github.com/LightningTipBot/LightningTipBot.

@AE9999 has started this project so most appreciations belong to him. I am here to keep this project running and updating and adding new functions here.

# Warning
While I have tested this bot alot until now, it is still in 'beta', don't put in more than you are willing to lose.

# How to use
MLTB can either be used directly or be self run. Running your own instance requires access to a LNbits (https://lnbits.com/) instance that exposes the users API at `/users/api/v1/user`.

## Directly
I am are running a dedicated MLTB instance over at @lightning-wallet-bot:matrix.yourdevice.ch. Invite it to a room to get started immediately. After joining the bot should display the possible commands which are:

* **!help** - Read this help: `!help`
* **!help-boltz** - Detailed help for Boltz commands: `!help-boltz`
* **!tip** - Reply to a message to tip it: `!tip <amount> [<memo>]`
* **!generate-ln-address** - Get your own LN Address: `!generate-ln-address <your address name>`
* **!show-ln-addresses** - Show your generated LN Addresses: `!show-ln-addresses`
* **!balance** - Check your balance: `!balance`
* **!send** - Send funds to a user: `!send <amount> <@user> or <@user:domain.com> or <lightningadress@yourdomain.com> [<memo>]`
* **!invoice** - Receive over Lightning: `!invoice <amount> [<memo>]`
* **!pay** - Pay an invoice over Lightning: `!pay <invoice>`
* **!transactions** - List your transactions: `!transactions`
* **!link-to-zeus-wallet** - Connect your wallet in Zeus: `!link-to-zeus-wallet`
* **!party** - Start a Party: `!party`
* **!fiat-to-sats** - Convert fiat to satoshis: `!fiat-to-sats <amount> <currency (USD, EUR, CHF)>`
* **!sats-to-fiat** - Convert satoshis to fiat: `!sats-to-fiat <amount> <currency (USD, EUR, CHF)>`
* **!boltz-onchain2offchain** - Swap on-chain BTC to Lightning: `!boltz-onchain2offchain <amount>`
* **!boltz-offchain2onchain** - Swap Lightning to on-chain BTC: `!boltz-offchain2onchain <amount> <btc-address>`
* **!boltz-refund** - Request a refund for a swap: `!boltz-refund <swap-id>`
  *(Only shown if `--boltz-url` is configured)*
* **!donate** - Donate to the matrix-lighting-tip-bot project: `!donate <amount>`
* **!version** - Print the version of this bot: `!version`

Run `!help-boltz` for details on Boltz swap commands.

Boltz swap commands will only be available if `--boltz-url` is set in the configuration.
The bot monitors active swaps and will post updates when their status changes. Amounts below Boltz’s minimum will be rejected.

In direct messages with the bot, the leading `!` can be omitted for all commands.

## Running your own instance
We recommend running your own MLTB instance using Docker https://www.docker.com/.

Running your own instance is done by:
1. Install prequisites
2. Create a new user for your lnbits instance
3. Building the docker image.
4. Generating a local Database file
5. Create a new user on your matrix-server for the bot to use
6. Constructing a config file
7. Running a MLTB

### Install prequisites

You need to use latest Version of LNBits (1.1.0 currently) older versions prior to 1.0.0 will not work. 

Install java and libsqlite3 on your debian/ubuntu server with
`sudo apt install openjdk-17-jdk`
`sudo apt install libsqlite3-dev`

### Create a new user for your lnbits instance
- Create a new user on your instance which manages the wallets. Ensure the users API is enabled for that user (providing access to `/users/api/v1/user`). The user can be a normal user and does not need to be an admin or superuser account
- enable LNDHub for new users so the users can link their wallet the Zeus

### Build Docker image
Building the Docker image is done with:
1. Install Docker (https://www.docker.com/)
2. Run `./gradlew buildDocker`  to build the docker image. On Windows this might need the `--project-cache-dir=../cache` option due to caching issues.

### Generate local sqlite Database file
Generating the local Database file is done with:
1. Install Rust (https://www.rust-lang.org/tools/install)
2. Install diesel (sqlite only) by running `cargo install diesel_cli --no-default-features --features sqlite`.
3. Run `diesel migration run --database-url=wallet-bot.db` to generate a local sqlite Database file.

### Create a new matrix user for the bot
Create a new user on your matrix server which will be used my MLTB.

### Construct a config file
Construct a file `config.conf` with the following entries. The LNbits API key is
used for creating lightning addresses without the bearer token:
```
--matrix-server=https://matrix.my-matrixserver.org     # Your Matrix Instance
--matrix-username=your_user_for_the_bot                # The username of the account your created
--matrix-password=the_passwort_for_that_user_account   # The password of your matrix bot
--lnbits-url=http://mylnbitsurl.com                    # The url of your LNbits instance
--lnbits-bearer-token=<LNBITS-BEARER-TOKEN>            # Bearer token for your LNbits instance. Use it in the Authorization header.
--lnbits-api-key=<API KEY>                             # Used for creating lightning addresses without the bearer token
--boltz-url=https://api.boltz.exchange/v2             # Boltz API endpoint (optional)
--database-url=/data/db/tipbot.db                      # The absolute path to your generated db.
--allowed-matrix-server=https://matrix.my-matrixserver.org  # Allow user from other matrix servers to use your bot, if not set, all servers are allowed (optional, repeat multiple times)
```

### Running
For example run: 

```
docker run -d \
  --name matrix-tipbot \
  --restart always \
  -v /opt/lntipbot/data/config/config.conf:/data/config/config.conf \
  -v /opt/lntipbot/data/db/tipbot.db:/data/db/tipbot.db \
  matrix-lightning-tip-bot matrix-lightning-tip-bot @/data/config/config.conf
```

to start the MLTB container.

It is also possible to use the docker-compose file. This will require .env file containing the entries
```
CONFIG_DIR=<path-to-config-directory>
DATABASE_DIR=<path-to-database-directory>
CONFIG_FILE=@/data/config/config.conf
```
See https://docs.docker.com/compose/environment-variables/ for more information.

# Contact
The developer has public matrix room at `#matrix-lightning-tip-bot-discussion:s-software-solutions.nl`
# BTC Donations
Non lightning BTC donations are welcome at `bc1q72dzh04fwxx780w05twtmn5fxzegpawdn5zg3g`

Contributors lightning address (me) = node-runner@btcpay.yourdevice.ch

# Thanks
A big thanks the people over at LightningTipBot and @AE9999. This fork-project is in no way ment to replace or critique the great work they have been doing, merely to give more people access to the lightning network.

# Scheduled TODOs
- make this work as an registered AS (Application Service) on your matrix homeserver instead of using a matrix-user-account
- generate your own ln-address with the command !generate-ln-address (✅)
- send info when created invoice has been paid (✅)
- limit usage to specific matrix instances (✅)
- Inform users about donated funds (✅)
- integrate a fiat/rate conversion tool (✅)
- send sats directly to a lightning address (✅)
- list your transactions through the bot (✅)
- show your ln-address again (✅)
- link your wallet to Zeus Android or iOS App (✅)
