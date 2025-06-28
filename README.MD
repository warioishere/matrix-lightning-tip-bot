 # About
Matrix-Lightning-Tip-Bot (MLTB) is a lightning network BTC tip bot for the matrix network. It is inspired by the LightningTipBot Telegram project at https://github.com/LightningTipBot/LightningTipBot.

@AE9999 has started this project so he is the main actor here and all appreciations belong to him. Just updating and adding new functions here.

# Warning
While I have tested this bot, it is in 'beta', don't put in more than you are willing to lose.

# How to use
MLTB can either be used directly or be self run. Running your own instance requires access to a LNbits (https://lnbits.com/) instance that exposes the users API at `/users/api/v1/user`.

## Directly
I am are running a dedicated MLTB instance over at @lightning-wallet-bot:matrix.yourdevice.ch. Invite it to a room to get started immediately. After joining the bot should display the possible commands which are:

* **!tip** - Reply to a message to tip it: `!tip <amount> [<memo>]`
* **!generate-ln-address** - Get your own LN Address: `!generate-ln-address <your address name>`
* **!show-ln-addresses** - Show your generated LN Addresses: `!show-ln-addresses`
* **!balance** - Check your balance: `!balance`
* **!send** - Send funds to a user: `!send <amount> <@user> or <@user:domain.com> or <lightningadress@yourdomain.com> [<memo>]`
* **!invoice** - Receive over Lightning: `!invoice <amount> [<memo>]` (includes a QR code)
* **!pay** - Pay an invoice over Lightning: `!pay <invoice>`
* **!transactions** - List your transactions: `!transactions`
* **!link-to-zeus-wallet** - Connect your wallet in Zeus: `!link-to-zeus-wallet`
* **!help** - Read this help: `!help`
* **!donate** - Donate to the matrix-lighting-tip-bot project: `!donate <amount>`
* **!party** - Start a Party: `!party`
* **!fiat-to-sats** - Convert fiat to satoshis: `!fiat-to-sats <amount> <currency (USD, EUR, CHF)>`
* **!sats-to-fiat** - Convert satoshis to fiat: `!sats-to-fiat <amount> <currency (USD, EUR, CHF)>`
* **!version** - Print the version of this bot: `!version`

## Running your own instance
We recommend running your own MLTB instance using Docker https://www.docker.com/.

The bot stores its session data locally. Encryption keys are kept in the `matrix_store` table and messages are encrypted on the application service side without calling the client `/sync` API.

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

### Create a registration YAML file
Matrix application services authenticate using a registration file instead of a
regular Matrix account. Create a YAML file describing the bot and register it
with your homeserver.

Below is a minimal example derived from the `Registration` struct in
`src/application_service/registration.rs`:

```yaml
id: lightning-tip-bot
as_token: "<app-service-token>"
hs_token: "<homeserver-token>"
sender_localpart: "lightning-bot"
url: "http://localhost:9000"
de.sorunome.msc2409.push_ephemeral: true
receive_ephemeral: true
namespaces:
  users:
    - regex: "@lightning-bot:.*"
      exclusive: true
```

`sender_localpart` defines the Matrix localpart that the bot uses as its name.

For Synapse add the path to this file to the `app_service_config_files` list in
`homeserver.yaml` and restart your server. Provide the same path to the bot via
the `--registration-file` command line option. This replaces the earlier
username/password login.

You can generate a minimal registration file using the bundled utility:

```bash
cargo run --bin generate_registration -- \
    --id lightning-tip-bot \
    --sender-localpart lightning-bot \
    --url http://localhost:9000 \
    --output registration.yaml
```

The command writes `registration.yaml` with random tokens similar to the
example above and already enables ephemeral event support. Register this file
with your homeserver and pass the path via `--registration-file` when starting
the bot.

### Construct a config file
Construct a file `config.conf` with the following entries. The LNbits API key is
used for creating lightning addresses without the bearer token:
```
--matrix-server=https://matrix.my-matrixserver.org     # Your Matrix Instance
--registration-file=/path/to/registration.yaml         # Path to the application service registration
--lnbits-url=http://mylnbitsurl.com                    # The url of your LNbits instance
--lnbits-bearer-token=<LNBITS-BEARER-TOKEN>            # Bearer token for your LNbits instance. Use it in the Authorization header.
--lnbits-api-key=<API KEY>                             # Used for creating lightning addresses without the bearer token
--database-url=/db/db.db                               # The absolute path to your generated db.
--avatar-path=mxc://your.server/abcdef               # Optional avatar URL for the bot
--allowed-matrix-server=https://matrix.my-matrixserver.org  # Allow user from other matrix servers to use your bot, if not set, all servers are allowed (optional, repeat multiple times)
```

Encrypted client keys are automatically saved in the database's `matrix_store` table.
The bot always uses a fixed device ID `ASDEVICE` when interacting with the Matrix
Client-Server API so no device configuration is required.
If `--avatar-path` is set, the bot sets its avatar URL to this `mxc` link at startup
using `PUT /_matrix/client/v3/profile/{userId}/avatar_url`.

### Running
Run `docker run --rm  -v <path-to-config-directory>:/config/  -v <path-to-database-directory>:/db  matrix-lightning-tip-bot  matrix-lightning-tip-bot @/config/config.conf` to start the MLTB container.

For a persistent deployment you can run the container with `--restart always` and bind your actual paths:

```bash
sudo docker run -d \
  --restart always \
  -v /opt/lntipbot/mltb-wario/data/config/config_ruma.conf:/data/config/config.conf \
  -v /opt/lntipbot/mltb-wario/data/db/tipbot_ruma.db:/data/db/tipbot_ruma.db \
  -v /opt/lntipbot/mltb-wario/data/config/registration.yaml:/data/config/registration.yaml \
  matrix-lightning-tip-bot matrix-lightning-tip-bot @/data/config/config.conf
```

`config_ruma.conf` may look like this:

```
--matrix-server=https://matrix.yourdevice.ch
--registration-file=/data/config/registration.yaml
--database-url=/data/db/tipbot_ruma.db
--avatar-path=mxc://your.server/avatar
--lnbits-url=https://lnbits.yourdevice.ch
--lnbits-bearer-token=xxx
--lnbits-api-key=xxx
```

The bot exposes the Matrix Application Service API at the `url` given in the registration file. The server listens on the port from that URL. Ensure your homeserver sends transactions using `PUT` requests to the `/` paths defined in the spec.
Your homeserver **must** be able to reach this address and is responsible for
pushing events there. Once the registration file is listed under
`app_service_config_files`, Synapse will PUT transactions to
`/_matrix/app/v1/transactions/{txnId}` at that URL. The bot does not call
`/sync`; all events are delivered via these transactions. The bot verifies that
transactions include the correct `access_token` so only your homeserver can
deliver events. Queries to
`GET /_matrix/app/v1/users/{userId}` is publicly accessible and simply indicates
whether that user is registered.
Transactions use the standard [push events](https://spec.matrix.org/latest/application-service-api/#put_matrixappv1transactionstxnid)
format so the JSON body may contain `events`, `ephemeral`, `de.sorunome.msc2409.send_to_device`, and other optional fields.

For end-to-end encryption the bot relies on the Matrix Client-Server API
endpoints `POST /_matrix/client/v3/keys/upload`, `POST /_matrix/client/v3/keys/query`
and `POST /_matrix/client/v3/keys/claim`. These requests are issued automatically
whenever new keys need to be uploaded or claimed.

The bot checks each room for the `m.room.encryption` state event before sending a message. Messages to encrypted rooms are locally encrypted, while unencrypted rooms receive plain text.
Example code:

```rust
async fn room_is_encrypted(&self, room_id: &str) -> bool {
    // cache lookup omitted
    match self.as_client.room_is_encrypted(room_id).await {
        Some(true) => true,
        _ => false,
    }
}

async fn send_message(&self, room_id: &str, body: &str) {
    if self.room_is_encrypted(room_id).await {
        let (ty, content) = self
            .encryption
            .encrypt_text(room_id, body, &self.as_client)
            .await;
        self.as_client.send_raw(room_id, &ty, content).await;
    } else {
        self.as_client.send_text(room_id, body).await;
    }
}
```

The bot checks each room for the `m.room.encryption` state event before sending a message. Messages to encrypted rooms are locally encrypted, while unencrypted rooms receive plain text.
Example code:

```rust
async fn room_is_encrypted(&self, room_id: &str) -> bool {
    // cache lookup omitted
    match self.as_client.room_is_encrypted(room_id).await {
        Some(true) => true,
        _ => false,
    }
}

async fn send_message(&self, room_id: &str, body: &str) {
    if self.room_is_encrypted(room_id).await {
        let (ty, content) = self
            .encryption
            .encrypt_text(room_id, body, &self.as_client)
            .await;
        self.as_client.send_raw(room_id, &ty, content).await;
    } else {
        self.as_client.send_text(room_id, body).await;
    }
}
```

It is also possible to use the docker-compose file. This will require .env file containing the entries
```
CONFIG_DIR=<path-to-config-directory>
DATABASE_DIR=<path-to-database-directory>
CONFIG_FILE=@/config/config.conf
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
- make this work as an registered AS (Application Service) on your matrix homeserver instead of using a matrix-user-account (✅)
- generate your own ln-address with the command !generate-ln-address (✅)
- send info when created invoice has been paid (✅)
- limit usage to specific matrix instances (✅)
- Inform users about donated funds (✅)
- integrate a fiat/rate conversion tool (✅)
- send sats directly to a lightning address (✅)
- list your transactions through the bot (✅)
- show your ln-address again (✅)
- link your wallet to Zeus Android or iOS App (✅)
