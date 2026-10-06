# HSM Docker Deployment Guide

UCM includes SoftHSM2 in its Docker image. HSM features work out of the box, no extra configuration required.

## Quick Start

```bash
docker compose -f docker-compose.hsm.yml up -d
```

On first start, a default SoftHSM token (`UCM-Default`) is automatically initialized, with a random PIN unless `HSM_PIN` is set. UCM keeps the PIN in the `SoftHSM-Default` provider.

**Auto-registration:** UCM automatically creates an `SoftHSM-Default` provider in the database when it detects the Docker entrypoint initialized a token (`HSM_DEFAULT_PIN` env var). The provider appears immediately in the HSM page, no manual setup needed.

## Legacy PKCS#11 key normalization (upgrade)

On upgrade, UCM maintains compatibility for PKCS#11 providers created by older configuration paths:

- Legacy: `library_path` / `pin`
- Canonical: `module_path` / `user_pin`

Normalization runs at three levels:

1. **Migration 057**: automatically rewrites legacy JSON fields in all `pkcs11` rows in `hsm_providers`.
2. **Startup repair**: if the `SoftHSM-Default` row already exists, UCM normalizes its configuration at startup as well.
3. **Runtime fallback**: `PKCS11Provider` accepts legacy aliases on read (before validation).

**Expected outcome:** after upgrade, the `SoftHSM-Default` provider should no longer fail a connection test (no `module_path is required` error) and the UI should show `module_path` / `user_pin`.


## Persistent Tokens

Since 2.233, SoftHSM tokens are stored in the data volume, under `/opt/ucm/data/softhsm/tokens`, so they survive a recreated container (an upgrade) with no extra volume:

```bash
docker run -d --name ucm -p 8443:8443 \
  -v ucm-data:/opt/ucm/data \
  neyslim/ultimate-ca-manager:latest
```

**Upgrading from a volume at `/var/lib/softhsm/tokens`:** keep that volume mounted for the first start of 2.233. The entrypoint copies its tokens into the data volume when the data volume holds none yet, and the `SoftHSM-Default` provider keeps its PIN. The old volume can be removed afterwards.

If 2.233 first started without that volume, it created a new `UCM-Default` in the data volume and the provider switched to it, keeping the previous PIN. To go back to the old token: stop the container, empty `softhsm/tokens` in the data volume, mount the old volume again and start. The tokens are carried over and the provider opens them with its previous PIN. Do not sync the provider keys before that: a sync against the new, empty token removes their records.

Before 2.233, a container started without that volume kept its tokens inside the container and created a new one at every recreation: keys made there were lost with the old container. When the entrypoint has to create `UCM-Default` anew, it points an existing `SoftHSM-Default` provider aimed at `UCM-Default` to the new token and logs a warning; a provider edited to open another token is left alone.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HSM_AUTO_INIT` | `true` | Auto-create a default SoftHSM token on first start |
| `HSM_PIN` | *(random)* | PIN for the auto-initialized token |
| `HSM_SO_PIN` | *(random)* | SO PIN for the auto-initialized token |
| `RAM_PORT` | `8444` | SmartCard-HSM RAM bridge listen port for `ram-client` (not AWS CloudHSM) |
| `UCM_ALLOW_RUNTIME_PIP` | *(unset)* | Set to `1` to enable the in-app "Install dependencies" button (HSM page). Disabled by default since v2.142, see below. |

## Runtime PKCS#11 dependency installer

Since **v2.142**, `POST /api/v2/hsm/install-dependencies` (the "Install dependencies" button on the HSM page) is **disabled by default** and returns:

```json
HTTP/1.1 403 Forbidden
{
  "success": false,
  "error": "Runtime pip install is disabled. Set UCM_ALLOW_RUNTIME_PIP=1 to opt in, or install the dependency via your system package manager."
}
```

This closes a remote-code-installation surface in default deployments. Two ways to install missing PKCS#11 packages:

**Recommended: bake into the image / system package**
```dockerfile
# Dockerfile derivative
FROM neyslim/ultimate-ca-manager:2.142
USER root
RUN apt-get update && apt-get install -y python3-pkcs11 && rm -rf /var/lib/apt/lists/*
USER ucm
```

```bash
# DEB / RPM
sudo apt install python3-pkcs11           # Debian/Ubuntu
sudo dnf install python3-PyKCS11          # Fedora/RHEL
sudo systemctl restart ucm
```

**Opt-in: runtime pip install from the UI**
```yaml
# docker-compose.yml
services:
  ucm:
    image: neyslim/ultimate-ca-manager:2.142
    environment:
      - UCM_ALLOW_RUNTIME_PIP=1
```

```ini
# /etc/default/ucm or systemd drop-in (DEB/RPM)
UCM_ALLOW_RUNTIME_PIP=1
```

Then click **Install dependencies** on the HSM page. The opt-in is per-deployment. UCM never enables it implicitly.

## Manual Token Management

```bash
# List tokens
docker exec ucm softhsm2-util --show-slots

# Create additional token
docker exec ucm softhsm2-util --init-token --free \
  --label "MyToken" --pin 1234 --so-pin 5678

# Delete a token
docker exec ucm softhsm2-util --delete-token --serial <serial>
```

## Hardware HSM

For hardware HSMs (Thales, SafeNet, etc.), mount the vendor PKCS#11 library and device:

```yaml
services:
  ucm:
    image: neyslim/ultimate-ca-manager:latest
    devices:
      - /dev/pkcs11
    volumes:
      - /opt/vendor/lib:/opt/vendor/lib:ro
```

Then configure the provider in the UCM web UI with the vendor library path.

## Cloud HSM

Configure cloud HSM providers via the UCM web UI (Settings → HSM):

- **AWS CloudHSM**: uses PKCS#11 with the CloudHSM client library
- **Azure Key Vault**: requires `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- **Google Cloud KMS**: requires GCP service account credentials

## SmartCard-HSM (remote) — not AWS CloudHSM

Provider type `sc-hsm-cloud` is a USB SmartCard-HSM signing window for an **offline root**. It is unrelated to AWS CloudHSM. Custodian tokens assemble the root key inside one chip for a ceremony, then the key is wiped. Between ceremonies the CA stays offline.

### Where `ram-client` connects

The bridge listens on **`RAM_PORT` (default `8444`)**, separate from the web UI (`8443`). `ram-client` does not talk to the web UI. `POST /hsm/ram/` on the admin site is answered by the SPA route, which is GET-only, so the client prints `Server HTTP code 405`.

Pick one of these before the first ceremony. The command on the HSM page uses whichever origin is in effect.

**Direct ports (no reverse proxy).** Publish both ports. Leave `UCM_RAM_PUBLIC_URL` and Settings → RAM public URL empty. UCM advertises the admin host with `RAM_PORT`:

```bash
ram-client https://203.0.113.10:8444/hsm/ram/<connect_token>
```

**Reverse proxy.** The admin name only listens on 80 and 443, and 80 redirects to 443. Do not drop `:8444` from the direct URL and do not add `/hsm/ram/` to the admin server block. Add a second hostname that forwards to the host port mapped to `8444`, and set that origin with no extra port:

```bash
# container / ucm.env / systemd Environment=
UCM_RAM_PUBLIC_URL=https://ucm-api.example.com
```

The ceremony page then shows:

```bash
ram-client https://ucm-api.example.com/hsm/ram/<connect_token>
```

`UCM_RAM_PUBLIC_URL` wins over the value saved in Settings. Restart UCM after changing it. The bridge still listens on `RAM_PORT` inside the container; the public URL is only what keyholders dial.

Terminate TLS on the proxy and re-encrypt to the bridge (the bridge is already HTTPS, using the UCM certificate). A long `ram-client` session needs a long proxy read timeout. Example nginx server, in addition to the admin `server` that proxies to `8443`:

```nginx
server {
    listen 443 ssl http2;
    server_name ucm-api.example.com;

    ssl_certificate     /etc/nginx/ssl/ucm-api.crt;
    ssl_certificate_key /etc/nginx/ssl/ucm-api.key;

    location /hsm/ram/ {
        proxy_pass https://127.0.0.1:8444;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 1m;
    }
}
```

`proxy_ssl_verify off` is there because the bridge certificate is issued for the admin name, not for `127.0.0.1`. The name keyholders check is the proxy certificate for `ucm-api.example.com`.

### One-shot `ram-client` (token host)

Each keyholder runs `ram-client` **only for the signing window**, from the command the ceremony page shows. Do **not** pass `-p`. Do **not** install a standing systemd unit on the laptop that holds the token. When the window closes, stop the client.

### Preparing tokens and creating the root key

UCM does not require a factory-sealed card. A token that was initialized before, wiped, or set up in the CardContact Smart Card Shell can be brought into the ceremony from the HSM page. Share bytes, PINs, and APDU payloads are not written to System Logs and are not returned to the browser.

A token is ready for a new n-of-m scheme when all of these are true:

- It is initialized with the **DKEK shares** scheme, and the share count matches this provider’s threshold.
- The key domain is empty (no shares imported yet).
- There is no share file on the card (elementary file `CF01`).

**Check token** reads that state. The ceremony panel shows it per custodian. The same result is written once to System Logs (`ucm.ram_bridge`) when it changes. `SW=6A82` on the share file means the card answered and the file is not there yet. That is expected before the first share is written, and the panel shows it as a neutral line.

#### Card use is chosen once, on the provider

When you create the provider, **Card use** is the only place the device-key scheme is chosen.

| Card use | What the ceremony asks later |
| --- | --- |
| n-of-m ceremony | Threshold (how many shares must be present) and total (how many tokens receive a share). Reinitialize uses the threshold. It does not ask for a share count. |
| No DKEK, randomly generated DKEK, or key domains | That scheme, and a domain count when the choice is key domains. The ceremony initializes the card with the saved scheme. Create root key and assembly stay on the n-of-m path. |

#### Reinitialize device

This is the same operation as **Initialize device** in the CardContact shell. It clears every key and file on that card and applies the scheme saved on the provider. Use it for a card that is already in use, including a card whose key-domain status is `SW=6D00` (the card is not currently set up for key shares).

For an n-of-m provider the card is initialized for DKEK shares, and the share count is the provider threshold. A 1-of-2 provider initializes the card for 1 share. The total stays on the provider and is how many share files **Create root key** writes.

Enter the **SO-PIN** and a new user PIN (6–16 characters), then type `DELETE`. The SO-PIN is the initialization code currently on the card: the 16 hex characters printed on a factory card, or the SO-PIN set the last time the card was initialized. A mismatch returns `SW=6982`. `SW=6A80` means the card rejected the initialization data.

Reinitialize does not write share files. After reinitialize on an n-of-m provider, the card is empty and ready for **Create root key**.

`write:hsm` can reinitialize any custodian token. `contribute:hsm` can reinitialize only the token assigned to that user. Both require the signing window to be open, and both are refused while a root key is assembled. Wipe that key first.

#### Prepare token

**Prepare token** is the lighter wipe. On a card that already has a key-share domain, it deletes the share file and the key domain and leaves the scheme in place. On a card with no key-share domain, it initializes that card using the scheme saved on the provider. It also requires `DELETE`.

#### First ceremony

There is no share file until UCM writes one, and **Use as assembly device** only reads share files that are already on the tokens. The first key is created from the HSM page:

1. Open the signing window.
2. Every custodian starts `ram-client` from the command on their row. **Create root key** needs all `m` tokens connected, not only the threshold.
3. **Check token**. If the card is not an empty DKEK-shares domain, **Reinitialize device**. The share count is the threshold saved on the provider.
4. On one connected token, **Create root key on this token** and type `DELETE`.

That generates the root key on the chosen token, writes one share file onto every connected custodian, imports the threshold of shares, and stores the wrapped root. UCM keeps the wrapped blob and the public key. It does not keep the share bytes. A second create is refused once a key is assembled.

On a live token the bridge logs into the assembly card twice with the user PIN entered on the ceremony page. The first login generates the RSA key and logs out. The second login wraps that key, and logs out only after the card has answered the wrap. The PIN is held in the bridge for that signing window and cleared when the window ends. It is not a server environment variable: the next window may use a different card, and the people holding the shares do not administer the UCM host.

#### Later ceremony

Opening the next window clears the saved assembly slot. Any connected token that already holds a share can be **Use as assembly device**. The token that assembled the key last time does not have to be present: after the wipe it is only another share holder, and the rebuilt key does not stay on it.

Assembly reads the threshold of share files from the tokens that are connected now, then unwraps the stored root. With n-of-m, any `n` of the share holders are enough. With n-of-n, a missing token blocks assembly. **Roll root key** still needs the assembled key and every custodian connected, because it writes a new share onto the full roster.

#### Status words

| SW | Where it shows up | Meaning |
| --- | --- | --- |
| `6A82` | Share file select | The card answered. Elementary file `CF01` is not on the card. |
| `6A88` | Key-domain status | The key domain is empty. |
| `6D00` | Key-domain status | This card is not initialized for key shares. Reinitialize it and choose DKEK shares. |
| `9000` | Key-domain status, outstanding equals the configured count | The domain is waiting for shares. |
| `6982` | Reinitialize | The SO-PIN does not match the initialization code on the card. |
| `6A80` | Reinitialize | The card rejected the initialization data. Send one scheme. |

### Operator actions inside the window

While the offline-root signing window is open, these root-key operations are allowed:

- Publish a CRL or delta CRL
- Revoke a subordinate CA
- Revoke an end-entity certificate the root issued (including OCSP or TSA signer certs)
- Issue or renew a subordinate CA
- Sign an external CA CSR
- Renew the root certificate (same key, new validity)
- Issue or renew the delegated OCSP responder certificate
- Roll the root key (new key on the assembly token, wrap, replace the stored blob, hand out new shares)

The CA record stays `offline` for the whole window. Closing the window regenerates the CRL after the latest change, then wipes the assembled key and drops every RAM session.

### What stays refused

ACME, SCEP, EST, WSTEP, TSA responses, and unattended OCSP that would need the root key stay refused for the whole window. Protocol clients, the CRL scheduler, and auto-renewal do not get the assembled key.

### Image / package notes

The Docker image includes `pcscd`, OpenSC (`sc-hsm-tool`), `opensc-pkcs11`, and `vsmartcard-vpcd` (bookworm IFD for `libifdvpcd.so`, registered in `/etc/reader.conf.d/vpcd` on the default vpcd port **35963**). SoftHSM is unchanged. The entrypoint starts `pcscd`, then the RAM bridge (when `backend/services/hsm/ram_bridge.py` is present), then Gunicorn. DEB/RPM ship `ucm-ram-bridge.service`, ordered before `ucm.service`.

## Backup & Restore

```bash
# Backup tokens
docker cp ucm:/opt/ucm/data/softhsm/tokens ./hsm-backup/

# Restore tokens: docker cp writes as root, so hand them back to ucm, then restart
docker cp ./hsm-backup/. ucm:/opt/ucm/data/softhsm/tokens/
docker exec -u root ucm chown -R ucm:ucm /opt/ucm/data/softhsm
docker restart ucm
```

Or archive them from the data volume:

```bash
docker run --rm -v ucm-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/hsm-tokens.tar.gz -C /data/softhsm/tokens .
```
