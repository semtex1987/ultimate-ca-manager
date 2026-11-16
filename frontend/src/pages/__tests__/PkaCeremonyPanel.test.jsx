/**
 * Public key authentication signing window (SmartCard-HSM, device_scheme 'pka').
 * The panel shows the SAS and quorum, never asks for a PIN, and shows a
 * connect URL only for the root HSM slot to write:hsm.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import './pageRenderingSetup.jsx'

import PkaCeremonyPanel, { pkaGuideKeys } from '../hsm/PkaCeremonyPanel'
import { ProviderModal, usesQuorum } from '../HSMPage'

const custodians = [
  { id: 1, share_index: 1, name: 'alice', is_me: true, enrolled: true, key_fingerprint: 'a'.repeat(64), approved: true, authenticated: true },
  { id: 2, share_index: 2, name: 'bob', is_me: false, enrolled: true, key_fingerprint: 'b'.repeat(64), approved: false, authenticated: false },
  { id: 3, share_index: 3, name: 'carol', is_me: false, enrolled: true, key_fingerprint: 'c'.repeat(64), approved: false, authenticated: false },
]

function openProvider(overrides = {}) {
  return {
    id: 7,
    name: 'Offline Root',
    provider_type: 'sc-hsm-cloud',
    device_scheme: 'pka',
    threshold_n: 2,
    total_m: 3,
    custodians,
    bridge: { reachable: true },
    wipe_confirmed: false,
    crl_stale: false,
    pka: {
      pinned_device_chr: 'DECC0000000099',
      keyholders_locked: true,
      has_root_key: true,
      root_connected: true,
      sas: '123-456',
      root_ram_client_url: 'https://ram.example/hsm/ram/secret-root-token',
      manifest: {
        ceremony_id: 'c-1',
        expires_at: '2026-11-15T20:00:00Z',
        operations: [{ type: 'publish_crl', label: 'CRL for Root A' }],
        max_signatures: 3,
      },
      live: {
        device_chr: 'DECC0000000099',
        manifest_sha256: 'f'.repeat(64),
        authenticated: ['1'],
        unlocked: false,
        signatures_used: 0,
        max_signatures: 3,
        hsm_status: { total: 3, missing: 0, required: 2, authenticated: 1 },
      },
      transcripts: [],
    },
    ...overrides,
  }
}

const noop = () => {}

describe('PkaCeremonyPanel', () => {
  it('shows the SAS, quorum and plan, and never asks for a PIN', () => {
    render(<PkaCeremonyPanel provider={openProvider()} canWriteHsm canContributeHsm
      onRefresh={noop} onLock={noop} onClose={noop} ocspAckChecked={false} setOcspAckChecked={noop} />)
    expect(screen.getByTestId('pka-sas').textContent).toBe('123-456')
    expect(screen.getByText('hsm.pka.quorum')).toBeTruthy()
    expect(screen.getByText(/CRL for Root A/)).toBeTruthy()
    expect(document.querySelector('input[type="password"]')).toBeNull()
    expect(screen.queryByText(/hsm\.ceremony\.userPin|hsm\.ceremony\.soPin/)).toBeNull()
  })

  it('shows the root slot command to write:hsm only, and no keyholder connect URL', () => {
    const { unmount } = render(<PkaCeremonyPanel provider={openProvider({ pka: { ...openProvider().pka, root_connected: false } })}
      canWriteHsm canContributeHsm onRefresh={noop} onLock={noop} onClose={noop}
      ocspAckChecked={false} setOcspAckChecked={noop} />)
    expect(screen.getByText(/ram-client https:\/\/ram\.example/)).toBeTruthy()
    unmount()
    const forKeyholder = openProvider({ pka: { ...openProvider().pka, root_connected: false, root_ram_client_url: undefined } })
    render(<PkaCeremonyPanel provider={forKeyholder} canWriteHsm={false} canContributeHsm
      onRefresh={noop} onLock={noop} onClose={noop} ocspAckChecked={false} setOcspAckChecked={noop} />)
    expect(screen.queryByText(/ram-client/)).toBeNull()
  })

  it('warns loudly when the connected device is not the pinned one', () => {
    const provider = openProvider()
    provider.pka.live.device_chr = 'DECC0000000777'
    render(<PkaCeremonyPanel provider={provider} canWriteHsm canContributeHsm
      onRefresh={noop} onLock={noop} onClose={noop} ocspAckChecked={false} setOcspAckChecked={noop} />)
    expect(screen.getByText('hsm.pka.deviceMismatch')).toBeTruthy()
  })

  it('guides each stage of the ceremony', () => {
    expect(pkaGuideKeys({ custodians: [{ enrolled: false }], pka: {} })).toEqual(['hsm.pka.guide.enroll'])
    expect(pkaGuideKeys({ custodians, pka: { keyholders_locked: false } })[0]).toBe('hsm.pka.guide.register')
    expect(pkaGuideKeys(openProvider())).toEqual(['hsm.pka.guide.approve', 'hsm.pka.guide.sas'])
    const unlocked = openProvider()
    unlocked.pka.live.unlocked = true
    expect(pkaGuideKeys(unlocked)[0]).toBe('hsm.pka.guide.operate')
  })
})

describe('provider form, public key authentication', () => {
  it('is the default card use for a new SmartCard-HSM provider and sends a roster', async () => {
    expect(usesQuorum('pka')).toBe(true)
    expect(usesQuorum('random')).toBe(false)
    const onSave = vi.fn()
    render(<ProviderModal provider={{ id: 1, name: 'Root', provider_type: 'sc-hsm-cloud', device_scheme: 'pka', threshold_n: 2, total_m: 3,
      custodians: [{ user_id: 10, share_index: 1 }, { user_id: 11, share_index: 2 }, { user_id: 12, share_index: 3 }] }}
      hsmStatus={null} onSave={onSave} onClose={noop} />)
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }))
    await waitFor(() => expect(onSave).toHaveBeenCalled())
    const { config } = onSave.mock.calls[0][0]
    expect(config.device_scheme).toBe('pka')
    expect(config.threshold_n).toBe(2)
    expect(config.total_m).toBe(3)
    expect(config.custodians).toHaveLength(3)
    expect(config).not.toHaveProperty('pinned_device_chr')
  })
})
