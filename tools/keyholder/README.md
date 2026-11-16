# UCM keyholder agent

`ucm_keyholder.py` is what a keyholder runs on their own machine during a remote root-key ceremony. It works with a UCM SmartCard-HSM provider that uses public key authentication (`device_scheme: pka`). The design is in [`docs/design/sc-hsm-remote-ceremony-pka.md`](../../docs/design/sc-hsm-remote-ceremony-pka.md).

The agent never sends a PIN or key material to UCM. It signs with your own card, and the PIN goes to that card only.

## Requirements

* Your own CardContact SmartCard-HSM, in a reader attached to this machine. A PIN-pad reader is recommended.
* OpenSC (`opensc-pkcs11.so`, `sc-hsm-tool`, `pkcs11-tool`).
* Python 3.9 or later, with `pip install cryptography python-pkcs11`.
* A UCM account that holds a keyholder slot on the provider, and an API key for it. Keep the key in a file only you can read.

## Check the agent first

Get the agent from the UCM source repository at a tagged release, not from the UCM server you are about to authenticate to. Before every ceremony, run:

```
python3 ucm_keyholder.py --version
```

and read the SHA-256 aloud on the call. It must match the value published with the release and sent in the ceremony invitation. If it does not, stop: a modified agent could show you one plan and sign another.

## One-time enrollment

```bash
# 1. Create your authentication key on your card (EC, P-256).
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --login \
            --keypairgen --key-type EC:prime256v1 --id 10 --label ucm-keyholder

# 2. Export it for public key authentication. This file is public.
sc-hsm-tool --export-for-pub-key-auth keyholder.pka --key-reference 10

# 3. Upload it. The agent checks that the file belongs to the key on your card.
export UCM_URL=https://ucm.example.com UCM_PROVIDER_ID=7 UCM_API_KEY_FILE=~/.ucm-api-key
python3 ucm_keyholder.py --key-id 10 enroll keyholder.pka
```

On the enrollment call, read aloud the fingerprint that `python3 ucm_keyholder.py --key-id 10 fingerprint` prints. The witness compares it with the value in UCM and in the registration bundle the HSM site uses.

## Each ceremony

```bash
python3 ucm_keyholder.py --key-id 10 approve
```

The agent:

1. Fetches the open ceremony and recomputes the manifest hash.
2. Shows the root HSM device reference. The first time, you type it to pin it, after comparing it with what the site operator reads aloud. After that, a different device stops the agent.
3. Checks that the card in your reader holds the key enrolled for you.
4. Shows the planned operations and the signature budget, and prints the **SAS**. Read the SAS aloud. The operator's screen must show the same six digits. If they differ, do not approve.
5. After you type `APPROVE`, asks for your card PIN once. It then signs the manifest approval, requests a challenge from the root HSM, checks that the challenge is for the pinned device, and signs it.

To pin the server's TLS key as well, pass `--pin-sha256 <hex>` or set `UCM_SPKI_SHA256`.

## After the ceremony

```bash
python3 ucm_keyholder.py transcript                  # verify the hash chain and list every signature
python3 ucm_keyholder.py --key-id 10 transcript --countersign
```

Check every `signed` entry against the operations you approved. Countersign only if they match.

## Files

* `~/.config/ucm-keyholder/device-pins.json` (mode 0600): the root HSM device reference per UCM URL and provider.
