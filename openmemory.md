# OpenMemory

## Overview

Ultimate CA Manager. The SmartCard-HSM provider (`sc-hsm-cloud`) is an offline root whose key exists only on one USB token during a signing window.

## Architecture

`ucm-ram-bridge` owns PC/SC, RAMOverHTTP, and the ceremony. Gunicorn talks to it over `/opt/ucm/data/ram-bridge.sock`. `ca.offline` stays set. Operator actions use `services.hsm.signing_window.operator_offline_blocks`. Protocol routes keep reading `ca.offline`.

## Components

- `backend/services/hsm/ram_bridge.py` — ceremony state machine: `begin_ceremony`, `connect_fake` (fake mode only), `inspect_token`, `prepare_token`, `set_assembly` (read shares from custodian tokens, import, unwrap), `roll_root_key`, `wipe_assembly`, `end_ceremony`.
- `backend/services/hsm/ceremony_service.py` — UCM side. Fails closed if the bridge is unreachable. Wipe regenerates linked CRLs before it will confirm. Key roll stores the new wrapped blob and self-signs bound offline roots. Share bytes are not returned.
- `backend/services/hsm/sc_hsm_apdu.py` — DKEK import/unwrap/wipe APDUs, share EF `CF01` (readable data object; `2F02` is the device certificate), n-of-n XOR shares and n-of-m Shamir shares, `FakeAssemblyToken` / `FakeCustodianToken`. SELECT uses P2=`00` and Le=`00`. Read is INS `B1`, write is INS `D7`.
- `utils/ca_signing_window.py` is the certificate validity window, not this ceremony.

## Patterns

Each custodian token holds one share in the share EF and no root key. The bridge copies a share into memory only for that share's import APDU, then zeroizes it. Assembly requires `threshold_n` connected tokens. Key roll requires all `total_m` tokens connected, writes new shares in `share_index` order (the same roster as create, not connect-token map order), and replaces `wrapped_root`. A wipe that cannot be confirmed does not set `wipe_confirmed`.

`create_root_key` generates the first root key on a chosen custodian and writes one share onto every connected token. It does not require an existing share file or wrapped root. `set_assembly` still reads shares that are already on the tokens. Roll still requires a key that is already assembled.

A token is ready for a new n-of-m scheme when it is initialized for DKEK shares and the key domain has not imported a share (`6A88` empty domain, or GET STATUS with outstanding shares equal to the configured count) and EF `CF01` is absent. A completed DKEK, a partial import, or a leftover share file is wiped first. `prepare_token` with `reinitialize` runs device INITIALIZE on a card that is already in use, using the current SO-PIN (the printed transport PIN only on a factory card) and one scheme: `none`, `random`, `shares`, or `domains`. The shares scheme sends tag `0x92` only. Firmware 4.0 rejects a block that also sends tag `0x97` with SW `6A80`. `prepare_token` refuses unless `confirm` is `DELETE`, and refuses while the root key is assembled. PINs are not audited. The ceremony panel exposes Check token, Prepare token, and Reinitialize device. Reinitialize takes the device scheme and the share count from the provider (`device_scheme`, `threshold_n`). An n-of-m ceremony does not ask for the share count again. No DKEK, a random DKEK, and key domains are chosen on the provider. The operator procedure is in `docs/HSM_DOCKER.md`.

The RAM bridge appends to the same `ucm.log` the System Logs page reads (`WatchedFileHandler`, Gunicorn keeps rotation). A changed token access line is also written from `ceremony_service` on the ceremony poll. SW `6A82` on share EF `CF01` means the card answered and has no share file; it is not a probe error. A wiped or empty `FakeCustodianToken` returns that status on SELECT, the same as a blank card.

The PKCS#11 user PIN is the one entered on the ceremony page for the token selected as the assembly device in this window. The bridge holds it in memory, leaves it out of `snapshot()`, and clears it when the window begins or ends. It does not read `SC_HSM_USER_PIN`. A later window can choose a different present token when the previous assembly card is absent, as long as `threshold_n` share-holders are connected. Creating the root key logs in twice with that PIN: the first read-write session generates the RSA key and logs out, and the second session wraps the key before it logs out. The wrap APDU is extended length (`80 72 id 92 00 00 00`), matching CardContact `wrapKey`. Import uses the default domain from device initialization. Deleting that domain and creating another one puts the PKCS#11 key outside the exportable DKEK, and WRAP returns SW `6985`. A completed device key makes CLEAR KEK and IMPORT return SW `6985` as well. Create and roll delete key id 1 and clear the DKEK before importing. SW `6985` on an empty domain that is still waiting for shares is left alone. Status probes skip the assembly card while either login is in progress. Key generation logs the assembly card out, so a later roll verifies that card's user PIN again before rewriting its share. The ceremony stores an `HsmKey` row; creating a CA binds that key and does not generate another one.

The ceremony panel polls while an `sc-hsm-cloud` provider is selected. `GET` detail includes `bridge.reachable`, `bridge.vpcd_connected`, and per-custodian `access` (`waiting` | `session` | `card` | `readable`). Readable means the bridge SELECT of share EF `CF01` returned 9000; the RAPDU data is discarded. A keepalive response is not paired with a command that has not been sent yet. The assembled key is shown as a 16-hex SHA-256 of the public PEM, never the PEM itself.

`ram-client` URLs come from `get_ram_public_origin()`. `UCM_RAM_PUBLIC_URL` or SystemConfig `ram_public_url` is a dedicated HTTPS origin and is not given `RAM_PORT`. When both are empty, the origin is the admin host plus `RAM_PORT` (direct port publish). `/hsm/ram/` on the admin vhost returns HTTP 405.

## User Defined Namespaces

- [Leave blank - user populates]
