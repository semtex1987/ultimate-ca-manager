/**
 * Signing window for a SmartCard-HSM provider that uses public key
 * authentication (device_scheme 'pka').
 *
 * Keyholders approve and authenticate with their own cards through the
 * keyholder agent (tools/keyholder). This panel never asks for a PIN and
 * never handles key material. Design: docs/design/sc-hsm-remote-ceremony-pka.md
 */
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCircle, XCircle, Lock, LockOpen, Warning, Key, Copy, DownloadSimple, Plus, Trash, ShieldCheck } from '@phosphor-icons/react'
import { Badge, Button, Input, Select, CompactSection } from '../../components'
import { useNotification } from '../../contexts'
import { useClipboard } from '../../hooks'
import { hsmService } from '../../services'

export const PKA_OPERATION_TYPES = [
  'generate_root_key',
  'publish_crl',
  'revoke_certificate',
  'issue_subordinate_ca',
  'sign_csr',
  'renew_root_certificate',
  'issue_ocsp_responder',
  'other',
]

/** Ordered guide lines for the panel. Keys are i18n paths. */
export function pkaGuideKeys(provider) {
  const pka = provider?.pka || {}
  const live = pka.live || null
  const open = !!live
  const allEnrolled = (provider?.custodians || []).length > 0
    && (provider.custodians || []).every(c => c.enrolled)
  if (!open) {
    if (!allEnrolled) return ['hsm.pka.guide.enroll']
    if (!pka.keyholders_locked) return ['hsm.pka.guide.register', 'hsm.pka.guide.openFirst']
    return [pka.has_root_key ? 'hsm.pka.guide.open' : 'hsm.pka.guide.openGenerate']
  }
  if (live.locked_verified || provider.wipe_confirmed) return ['hsm.pka.guide.closeNow']
  if (!pka.root_connected) return ['hsm.pka.guide.attachRoot']
  if (!pka.pinned_device_chr) return ['hsm.pka.guide.pinDevice']
  if (!live.unlocked) return ['hsm.pka.guide.approve', 'hsm.pka.guide.sas']
  if (!pka.has_root_key) return ['hsm.pka.guide.generate', 'hsm.pka.guide.lockThenClose']
  return ['hsm.pka.guide.operate', 'hsm.pka.guide.lockThenClose']
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result)
      let binary = ''
      for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i])
      resolve(btoa(binary))
    }
    reader.onerror = () => reject(reader.error)
    reader.readAsArrayBuffer(file)
  })
}

export default function PkaCeremonyPanel({
  provider,
  canWriteHsm,
  canContributeHsm,
  onRefresh,
  onLock,
  onClose,
  ocspAckChecked,
  setOcspAckChecked,
}) {
  const { t } = useTranslation()
  const { showSuccess, showError, showPrompt } = useNotification()
  const { copy } = useClipboard()
  const [busy, setBusy] = useState(false)
  const [operations, setOperations] = useState([{ type: 'publish_crl', label: '' }])
  const [maxSignatures, setMaxSignatures] = useState(5)
  const [ttlHours, setTtlHours] = useState(4)
  const [deviceConfirm, setDeviceConfirm] = useState('')

  const pka = provider.pka || {}
  const live = pka.live || null
  const open = !!live
  const custodians = Array.isArray(provider.custodians) ? provider.custodians : []
  const me = custodians.find(c => c.is_me)
  const bridge = provider.bridge || {}
  const hsmStatus = live?.hsm_status || null
  const authenticatedCount = (live?.authenticated || []).length
  const deviceMismatch = !!(live?.device_chr && pka.pinned_device_chr && live.device_chr !== pka.pinned_device_chr)
  const short = (value) => (value ? `${value.slice(0, 16)}…` : '—')

  const run = async (fn, successKey) => {
    setBusy(true)
    try {
      await fn()
      if (successKey) showSuccess(t(successKey))
      await onRefresh()
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setBusy(false)
    }
  }

  const handleEnroll = async (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (file.size > 8192) {
      showError(t('hsm.pka.enrollTooLarge'))
      return
    }
    await run(async () => {
      const exportB64 = await readFileAsBase64(file)
      await hsmService.enrollKeyholder(provider.id, exportB64)
    }, 'hsm.pka.enrolled')
  }

  const handleDownloadBundle = () => run(async () => {
    const blob = await hsmService.downloadRegistrationBundle(provider.id)
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ucm-provider-${provider.id}-keyholders.zip`
    link.click()
    URL.revokeObjectURL(url)
  })

  const updateOperation = (index, field, value) => {
    setOperations(prev => prev.map((op, i) => (i === index ? { ...op, [field]: value } : op)))
  }

  const handleBegin = () => {
    const planned = operations
      .map(op => ({ ...op, label: (op.label || '').trim() }))
      .filter(op => op.label)
      .map(op => (op.ca_id ? { ...op, ca_id: Number(op.ca_id) } : { type: op.type, label: op.label }))
    if (!planned.length) {
      showError(t('hsm.pka.manifestEmpty'))
      return
    }
    return run(() => hsmService.beginCeremony(provider.id, {
      operations: planned,
      max_signatures: Number(maxSignatures) || 1,
      ttl_hours: Number(ttlHours) || 4,
    }), 'hsm.ceremony.windowOpened')
  }

  const handlePin = () => {
    if (deviceConfirm.trim() !== live?.device_chr) {
      showError(t('hsm.pka.pinMismatch'))
      return
    }
    return run(() => hsmService.pinRootDevice(provider.id, deviceConfirm.trim()), 'hsm.pka.pinned')
  }

  const handleGenerate = async () => {
    const typed = await showPrompt(t('hsm.pka.generatePrompt'), {
      title: t('hsm.pka.generateTitle'),
      placeholder: 'GENERATE',
      confirmText: t('hsm.pka.generate'),
    })
    if (typed == null) return
    if (typed !== 'GENERATE') {
      showError(t('hsm.pka.generateMismatch'))
      return
    }
    await run(() => hsmService.generatePkaRootKey(provider.id, typed), 'hsm.pka.generated')
  }

  const agentCommand = `python3 ucm_keyholder.py --url ${window.location.origin} --provider ${provider.id} approve`
  const rootCommand = pka.root_ram_client_url ? `ram-client ${pka.root_ram_client_url}` : ''

  return (
    <CompactSection title={t('hsm.ceremony.title')}>
      <div className="space-y-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={bridge.reachable ? 'success' : 'danger'} size="sm" icon={bridge.reachable ? CheckCircle : XCircle}>
            {bridge.reachable ? t('hsm.ceremony.bridgeUp') : t('hsm.ceremony.bridgeDown')}
          </Badge>
          <Badge variant={open ? 'success' : 'secondary'} size="sm" icon={open ? CheckCircle : Lock}>
            {open ? t('hsm.pka.windowOpen') : t('hsm.ceremony.offline')}
          </Badge>
          {open && (
            <Badge variant={pka.root_connected ? 'success' : 'secondary'} size="sm">
              {pka.root_connected ? t('hsm.pka.rootConnected') : t('hsm.pka.rootWaiting')}
            </Badge>
          )}
          {open && (
            <Badge variant={live.unlocked ? 'warning' : 'secondary'} size="sm" icon={live.unlocked ? LockOpen : Lock}>
              {t('hsm.pka.quorum', { count: authenticatedCount, required: provider.threshold_n })}
            </Badge>
          )}
          {open && (
            <Badge variant="secondary" size="sm">
              {t('hsm.pka.budget', { used: live.signatures_used, max: live.max_signatures })}
            </Badge>
          )}
          {pka.has_root_key && (
            <Badge variant="purple" size="sm" icon={Key}>{t('hsm.pka.hasRootKey')}</Badge>
          )}
          {open && provider.crl_stale && (
            <Badge variant="warning" size="sm" icon={Warning}>{t('hsm.ceremony.crlStale')}</Badge>
          )}
          {open && live.locked_verified && (
            <Badge variant="success" size="sm" icon={ShieldCheck}>{t('hsm.pka.locked')}</Badge>
          )}
        </div>

        {!bridge.reachable && bridge.error && (
          <p className="text-2xs text-text-tertiary break-all">{bridge.error}</p>
        )}
        {(deviceMismatch || live?.device_error || live?.config_error) && (
          <div className="p-2.5 rounded-lg bg-status-danger-op10 border border-status-danger-op30 text-status-danger space-y-1">
            {deviceMismatch && <p>{t('hsm.pka.deviceMismatch', { device: live.device_chr, pinned: pka.pinned_device_chr })}</p>}
            {live?.device_error && !deviceMismatch && <p>{live.device_error}</p>}
            {live?.config_error && <p>{t('hsm.pka.configMismatch', { detail: live.config_error })}</p>}
          </div>
        )}

        <div>
          <p className="text-text-primary mb-1 font-medium">{t('hsm.ceremony.whatNext')}</p>
          <ol className="list-decimal pl-4 space-y-1 text-text-secondary">
            {pkaGuideKeys(provider).map(key => (
              <li key={key}>{t(key, { n: provider.threshold_n, m: provider.total_m })}</li>
            ))}
          </ol>
        </div>

        {open && live.device_chr && (
          <div className="grid grid-cols-1 gap-1">
            <p>
              <span className="text-text-tertiary">{t('hsm.pka.device')}: </span>
              <span className="font-mono">{live.device_chr}</span>
              {pka.pinned_device_chr && !deviceMismatch && (
                <span className="text-status-success"> · {t('hsm.pka.pinnedLabel')}</span>
              )}
            </p>
            {pka.sas && (
              <p className="text-base">
                <span className="text-text-tertiary text-xs">{t('hsm.pka.sas')}: </span>
                <span className="font-mono font-semibold tracking-widest" data-testid="pka-sas">{pka.sas}</span>
              </p>
            )}
            {live.manifest_sha256 && (
              <p className="break-all">
                <span className="text-text-tertiary">{t('hsm.pka.manifestHash')}: </span>
                <span className="font-mono text-2xs">{live.manifest_sha256}</span>
              </p>
            )}
            {hsmStatus && (
              <p className="text-text-tertiary">
                {t('hsm.pka.deviceStatus', {
                  total: hsmStatus.total, missing: hsmStatus.missing,
                  required: hsmStatus.required, authenticated: hsmStatus.authenticated,
                })}
              </p>
            )}
          </div>
        )}

        {open && pka.manifest && (
          <div>
            <p className="text-text-tertiary mb-1 font-medium">
              {t('hsm.pka.planned', { expires: pka.manifest.expires_at })}
            </p>
            <ul className="list-disc pl-4 space-y-0.5 text-text-secondary">
              {(pka.manifest.operations || []).map((op, index) => (
                <li key={`${op.type}-${index}`}>
                  {t(`hsm.pka.op.${op.type}`)}: {op.label}{op.ca_id != null ? ` (CA ${op.ca_id})` : ''}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div>
          <p className="text-text-primary mb-1 font-medium">{t('hsm.pka.keyholders')}</p>
          <div className="space-y-1.5">
            {custodians.map(c => (
              <div key={c.id} className="flex flex-wrap items-center gap-2 p-2 rounded-lg bg-tertiary-op50">
                <span className="font-medium">{c.name}</span>
                <span className="text-text-tertiary">#{c.share_index}</span>
                <Badge variant={c.enrolled ? 'success' : 'secondary'} size="sm">
                  {c.enrolled ? t('hsm.pka.enrolledBadge') : t('hsm.pka.notEnrolled')}
                </Badge>
                {c.enrolled && (
                  <span className="font-mono text-2xs text-text-secondary" title={c.key_fingerprint}>
                    {short(c.key_fingerprint)}
                  </span>
                )}
                {open && c.approved && <Badge variant="cyan" size="sm">{t('hsm.pka.approved')}</Badge>}
                {open && c.authenticated && <Badge variant="success" size="sm">{t('hsm.pka.authenticated')}</Badge>}
                {c.is_me && canContributeHsm && !pka.keyholders_locked && !open && (
                  <label className="ml-auto cursor-pointer text-accent-primary">
                    <input type="file" accept=".pka,application/octet-stream" className="hidden" onChange={handleEnroll} disabled={busy} />
                    {c.enrolled ? t('hsm.pka.reEnroll') : t('hsm.pka.enroll')}
                  </label>
                )}
              </div>
            ))}
          </div>
        </div>

        {me && open && !me.authenticated && (
          <div className="space-y-1">
            <p className="text-text-secondary">{t('hsm.pka.agentHint')}</p>
            <div className="flex items-start gap-2">
              <code className="font-mono text-2xs break-all bg-tertiary-op50 p-1.5 rounded flex-1">{agentCommand}</code>
              <Button type="button" size="sm" variant="secondary" onClick={() => { copy(agentCommand); showSuccess(t('common.copied')) }} aria-label={t('common.copy')}>
                <Copy size={12} />
              </Button>
            </div>
          </div>
        )}

        {canWriteHsm && !open && (
          <div className="space-y-2">
            {custodians.length > 0 && custodians.every(c => c.enrolled) && (
              <Button type="button" size="sm" variant="secondary" onClick={handleDownloadBundle} disabled={busy}>
                <DownloadSimple size={14} />
                {t('hsm.pka.downloadBundle')}
              </Button>
            )}
            <p className="text-text-primary font-medium">{t('hsm.pka.manifestTitle')}</p>
            <p className="text-2xs text-text-tertiary">{t('hsm.pka.manifestHint')}</p>
            {operations.map((op, index) => (
              <div key={index} className="grid grid-cols-[10rem_1fr_5rem_auto] gap-2 items-end">
                <Select
                  value={op.type}
                  onChange={value => updateOperation(index, 'type', value)}
                  options={PKA_OPERATION_TYPES.map(type => ({ value: type, label: t(`hsm.pka.op.${type}`) }))}
                />
                <Input value={op.label} placeholder={t('hsm.pka.labelPlaceholder')} onChange={e => updateOperation(index, 'label', e.target.value)} />
                <Input value={op.ca_id || ''} placeholder="CA id" onChange={e => updateOperation(index, 'ca_id', e.target.value.replace(/\D/g, ''))} />
                <Button type="button" size="sm" variant="secondary" aria-label={t('common.delete')}
                  onClick={() => setOperations(prev => prev.filter((_, i) => i !== index))} disabled={operations.length === 1}>
                  <Trash size={12} />
                </Button>
              </div>
            ))}
            <Button type="button" size="sm" variant="secondary" onClick={() => setOperations(prev => [...prev, { type: 'other', label: '' }])}>
              <Plus size={12} /> {t('hsm.pka.addOperation')}
            </Button>
            <div className="grid grid-cols-2 gap-2">
              <Input label={t('hsm.pka.maxSignatures')} type="number" min={1} max={1000} value={maxSignatures} onChange={e => setMaxSignatures(e.target.value)} />
              <Input label={t('hsm.pka.ttlHours')} type="number" min={1} max={72} value={ttlHours} onChange={e => setTtlHours(e.target.value)} />
            </div>
            <Button type="button" size="sm" onClick={handleBegin} disabled={busy || !bridge.reachable}>
              {t('hsm.ceremony.begin')}
            </Button>
          </div>
        )}

        {canWriteHsm && open && (
          <div className="space-y-2">
            {rootCommand && !pka.root_connected && (
              <div className="space-y-1">
                <p className="text-text-secondary">{t('hsm.pka.rootCommandHint')}</p>
                <div className="flex items-start gap-2">
                  <code className="font-mono text-2xs break-all bg-tertiary-op50 p-1.5 rounded flex-1">{rootCommand}</code>
                  <Button type="button" size="sm" variant="secondary" onClick={() => { copy(rootCommand); showSuccess(t('common.copied')) }} aria-label={t('common.copy')}>
                    <Copy size={12} />
                  </Button>
                </div>
              </div>
            )}
            {live.device_chr && !pka.pinned_device_chr && (
              <div className="grid grid-cols-[1fr_auto] gap-2 items-end">
                <Input
                  label={t('hsm.pka.pinPrompt')}
                  value={deviceConfirm}
                  onChange={e => setDeviceConfirm(e.target.value)}
                  placeholder={t('hsm.pka.pinPlaceholder')}
                />
                <Button type="button" size="sm" onClick={handlePin} disabled={busy}>{t('hsm.pka.pin')}</Button>
              </div>
            )}
            {provider.ocsp_responder_warning && (
              <label className="flex items-start gap-2 cursor-pointer text-text-secondary">
                <input type="checkbox" className="mt-0.5" checked={ocspAckChecked} onChange={e => setOcspAckChecked(e.target.checked)} />
                <span>{t('hsm.ceremony.ocspAcknowledge')}</span>
              </label>
            )}
            <div className="flex flex-wrap gap-2">
              {live.unlocked && !pka.has_root_key && (pka.manifest?.operations || []).some(op => op.type === 'generate_root_key') && (
                <Button type="button" size="sm" onClick={handleGenerate} disabled={busy}>
                  <Key size={14} /> {t('hsm.pka.generate')}
                </Button>
              )}
              <Button type="button" size="sm" variant="danger" onClick={onLock} disabled={busy || provider.wipe_confirmed}>
                <Lock size={14} /> {t('hsm.pka.lock')}
              </Button>
              <Button type="button" size="sm" variant="secondary" onClick={onClose} disabled={busy || !provider.wipe_confirmed}>
                {t('hsm.ceremony.end')}
              </Button>
            </div>
          </div>
        )}

        {(pka.transcripts || []).length > 0 && (
          <div>
            <p className="text-text-primary mb-1 font-medium">{t('hsm.pka.transcripts')}</p>
            <ul className="space-y-1">
              {pka.transcripts.map(item => (
                <li key={item.ceremony_id} className="text-2xs text-text-secondary break-all">
                  <span className="font-mono">{item.closed_at}</span> · {t('hsm.pka.transcriptLine', {
                    entries: item.entries,
                    count: (item.countersigned_by || []).length,
                    total: provider.total_m,
                  })} · <span className="font-mono">{short(item.final_hash)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </CompactSection>
  )
}
