/**
 * HSM provider form: saving without retyping a secret keeps the stored one.
 * The API masks each secret as '***' and keeps the stored value on that sentinel;
 * an empty string would overwrite it.
 *
 * SmartCard-HSM (sc-hsm-cloud) never stores or echoes DKEK / share material.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import './pageRenderingSetup.jsx'

import { ProviderModal, accessStepReached } from '../HSMPage'

const CASES = [
  ['pkcs11', { pkcs11_library_path: '/usr/lib/softhsm/libsofthsm2.so', pkcs11_token_label: 'UCM-Default', pkcs11_pin: '***' }, 'user_pin'],
  ['aws-cloudhsm', { aws_cluster_id: 'c-1', aws_crypto_user: 'cu', aws_crypto_password: '***' }, 'hsm_password'],
  ['azure-keyvault', { azure_vault_url: 'https://v.vault.azure.net', azure_client_secret: '***' }, 'client_secret'],
  ['openbao', { openbao_url: 'https://bao.example', openbao_token: '***' }, 'token'],
]

const SHARE_FORBIDDEN_KEYS = [
  'share',
  'shares',
  'share_value',
  'share_bytes',
  'dkek_share',
  'dkek_shares',
  'share_material',
]

describe('HSM provider form, stored secrets', () => {
  it.each(CASES)('%s: a save without retyping sends the kept sentinel', async (type, fields, key) => {
    const onSave = vi.fn()
    render(<ProviderModal provider={{ id: 1, name: 'P', provider_type: type, ...fields }}
                          hsmStatus={null} onSave={onSave} onClose={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }))
    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(onSave.mock.calls[0][0].config[key]).toBe('***')
  })

  it('sc-hsm-cloud: never sends or echoes share material', async () => {
    const onSave = vi.fn()
    render(
      <ProviderModal
        provider={{
          id: 1,
          name: 'Offline Root',
          provider_type: 'sc-hsm-cloud',
          token_label: 'UCM-Root',
          threshold_n: 2,
          total_m: 3,
          custodians: [
            { user_id: 10, share_index: 1 },
            { user_id: 11, share_index: 2 },
            { user_id: 12, share_index: 3 },
          ],
          // Poison fields that must never be echoed into the save payload
          share: 'SHOULD-NOT-APPEAR',
          dkek_share: 'SHOULD-NOT-APPEAR',
          share_value: 'SHOULD-NOT-APPEAR',
        }}
        hsmStatus={null}
        onSave={onSave}
        onClose={() => {}}
      />
    )

    expect(screen.queryByDisplayValue('SHOULD-NOT-APPEAR')).toBeNull()
    expect(screen.queryByLabelText(/share value/i)).toBeNull()
    expect(screen.queryByLabelText(/dkek/i)).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'common.save' }))
    await waitFor(() => expect(onSave).toHaveBeenCalled())

    const payload = onSave.mock.calls[0][0]
    expect(payload.type).toBe('sc-hsm-cloud')
    const { config } = payload
    expect(config.token_label).toBe('UCM-Root')
    expect(config.device_scheme).toBe('shares')
    expect(config).not.toHaveProperty('dkek_shares')
    expect(config.threshold_n).toBe(2)
    expect(config.total_m).toBe(3)
    expect(config.custodians).toEqual([
      { user_id: 10, share_index: 1 },
      { user_id: 11, share_index: 2 },
      { user_id: 12, share_index: 3 },
    ])
    for (const key of SHARE_FORBIDDEN_KEYS) {
      expect(config).not.toHaveProperty(key)
    }
    expect(JSON.stringify(config)).not.toMatch(/SHOULD-NOT-APPEAR|dkek_share|share_bytes|share_value/i)
  })
})

describe('ceremony access steps', () => {
  it('waiting has not reached session or readable', () => {
    expect(accessStepReached('waiting', 'waiting')).toBe(true)
    expect(accessStepReached('waiting', 'session')).toBe(false)
    expect(accessStepReached('waiting', 'readable')).toBe(false)
  })

  it('readable has reached every step', () => {
    expect(accessStepReached('readable', 'waiting')).toBe(true)
    expect(accessStepReached('readable', 'session')).toBe(true)
    expect(accessStepReached('readable', 'card')).toBe(true)
    expect(accessStepReached('readable', 'readable')).toBe(true)
  })
})
