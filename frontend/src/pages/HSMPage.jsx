/**
 * HSM Page - UCM
 * Hardware Security Module management
 * 
 * Migrated to ResponsiveLayout for consistent UX
 */
import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { 
  Key, Plus, Trash, PencilSimple, CheckCircle, XCircle, TestTube,
  Cloud, HardDrive, ArrowsClockwise, Lock, Warning, Copy, Cpu, Users
} from '@phosphor-icons/react'
import { 
  Badge, Button, FormModal, Input, Select, ExperimentalBadge,
  CompactSection, CompactGrid, CompactField, CompactStats, CompactHeader
} from '../components'
import { ResponsiveLayout, ResponsiveDataTable } from '../components/ui/responsive'
import { useNotification, useMobile, useAuth } from '../contexts'
import { usePermission, useClipboard, usePersistedState } from '../hooks'
import { hsmService, usersService } from '../services'
import { ToggleSwitch } from '../components/ui/ToggleSwitch'

const PROVIDER_TYPES = [
  { value: 'pkcs11', label: 'PKCS#11 (Local HSM)', icon: HardDrive },
  { value: 'aws-cloudhsm', label: 'AWS CloudHSM', icon: Cloud },
  { value: 'azure-keyvault', label: 'Azure Key Vault', icon: Cloud },
  { value: 'google-kms', label: 'Google Cloud KMS', icon: Cloud },
  { value: 'openbao', label: 'OpenBao / Vault Transit', icon: Lock },
  { value: 'sc-hsm-cloud', label: 'SmartCard-HSM (remote)', icon: Cpu },
]

const PROVIDER_ICONS = {
  'pkcs11': HardDrive,
  'aws-cloudhsm': Cloud,
  'azure-keyvault': Cloud,
  'google-kms': Cloud,
  'openbao': Lock,
  'sc-hsm-cloud': Cpu,
}

const CEREMONY_POLL_MS = 4000

/** Normalize ceremony_status: 'offline', a connected count, or { state, connected_count }. */
export function parseCeremonyStatus(provider) {
  const cs = provider?.ceremony_status
  if (cs == null || cs === 'offline') {
    return { open: false, connected_count: 0 }
  }
  if (typeof cs === 'number') {
    return { open: true, connected_count: cs }
  }
  if (typeof cs === 'object') {
    const state = cs.state || cs.status
    const connected = cs.connected_count ?? cs.connected ?? 0
    return { open: state !== 'offline', connected_count: connected }
  }
  if (cs === 'open') {
    return { open: true, connected_count: provider.connected_count || 0 }
  }
  return { open: false, connected_count: 0 }
}

export function buildRamClientCommand(ramClientUrl) {
  if (!ramClientUrl) return ''
  return `ram-client ${ramClientUrl}`
}

const ACCESS_STEPS = ['waiting', 'session', 'card', 'readable']
const ACCESS_RANK = { waiting: 0, session: 1, card: 2, readable: 3 }

export function accessStepReached(access, step) {
  return (ACCESS_RANK[access] ?? 0) >= (ACCESS_RANK[step] ?? 0)
}

export default function HSMPage() {
  const { t } = useTranslation()
  const { canWrite, canDelete, hasPermission } = usePermission()
  const { user } = useAuth()
  const { copy } = useClipboard()
  const [providers, setProviders] = useState([])
  const [keys, setKeys] = useState([])
  const [selectedProvider, setSelectedProvider] = useState(null)
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [modalMode, setModalMode] = useState('create')
  const [showKeyModal, setShowKeyModal] = useState(false)
  const [testing, setTesting] = useState(false)
  const [ceremonyBusy, setCeremonyBusy] = useState(false)
  const [tokenPins, setTokenPins] = useState({})
  const [ocspAckChecked, setOcspAckChecked] = useState(false)
  const [filterType, setFilterType] = usePersistedState('ucm-filter-hsm-type', [])
  const [filterStatus, setFilterStatus] = usePersistedState('ucm-filter-hsm-status', [])
  const [hsmStatus, setHsmStatus] = useState(null)
  const { showSuccess, showError, showConfirm, showPrompt } = useNotification()
  const { isMobile } = useMobile()
  const pollRef = useRef(null)
  const canContributeHsm = hasPermission('contribute:hsm')
  const canWriteHsm = canWrite('hsm')

  useEffect(() => {
    loadData()
    loadHsmStatus()
  }, [])

  useEffect(() => {
    if (selectedProvider) {
      loadKeys(selectedProvider.id)
    }
  }, [selectedProvider?.id])

  // Poll SmartCard-HSM detail while that provider is selected so a down
  // bridge is visible before anyone opens a signing window.
  const isScHsmSelected = selectedProvider?.provider_type === 'sc-hsm-cloud'
  useEffect(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
    if (!selectedProvider || !isScHsmSelected) return undefined
    const providerId = selectedProvider.id
    pollRef.current = setInterval(() => {
      refreshProviderDetail(providerId)
    }, CEREMONY_POLL_MS)
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
  }, [selectedProvider?.id, isScHsmSelected])

  useEffect(() => {
    setOcspAckChecked(false)
  }, [selectedProvider?.id, selectedProvider?.ocsp_responder_warning])

  const loadData = async () => {
    try {
      const response = await hsmService.getProviders()
      setProviders(response.data || [])
    } catch (error) {
      showError(t('messages.errors.loadFailed.hsmProviders'))
    } finally {
      setLoading(false)
    }
  }

  const loadHsmStatus = async () => {
    try {
      const response = await hsmService.getStatus()
      setHsmStatus(response.data)
    } catch (error) {
      // Non-critical — HSM may not be configured
    }
  }

  const loadKeys = async (providerId) => {
    try {
      const response = await hsmService.getKeys(providerId)
      setKeys(response.data || [])
    } catch { /* non-critical */ }
  }

  const refreshProviderDetail = async (providerId) => {
    try {
      const response = await hsmService.getProvider(providerId)
      setSelectedProvider(prev => (prev?.id === providerId ? response.data : prev))
      return response.data
    } catch {
      return null
    }
  }

  const handleSelectProvider = async (provider) => {
    setSelectedProvider(provider)
    if (provider?.provider_type === 'sc-hsm-cloud') {
      await refreshProviderDetail(provider.id)
    }
  }

  const handleApplyFilterPreset = useCallback((filters) => {
    if (filters.enabled) setFilterStatus(Array.isArray(filters.enabled) ? filters.enabled : [filters.enabled])
    else setFilterStatus([])
    if (filters.provider_type) setFilterType(Array.isArray(filters.provider_type) ? filters.provider_type : [filters.provider_type])
    else setFilterType([])
  }, [])

  const handleCreate = () => {
    setSelectedProvider(null)
    setModalMode('create')
    setShowModal(true)
  }

  const handleEdit = async (provider) => {
    try {
      // Fetch full provider details (config is excluded from list endpoint).
      // Without this, the edit modal would default to PKCS#11 and show the
      // wrong form for remote providers like OpenBao.
      const response = await hsmService.getProvider(provider.id)
      setSelectedProvider(response.data)
      setModalMode('edit')
      setShowModal(true)
    } catch (error) {
      showError(error.message || t('messages.errors.loadFailed.hsmProviders'))
    }
  }

  const handleDelete = async (provider) => {
    const confirmed = await showConfirm(t('messages.confirm.hsm.deleteProvider', { name: provider.name }), { variant: 'danger', confirmText: t('common.delete') })
    if (!confirmed) return
    try {
      await hsmService.deleteProvider(provider.id)
      showSuccess(t('messages.success.delete.provider'))
      loadData()
      setSelectedProvider(null)
    } catch (error) {
      showError(error.message || t('messages.errors.deleteFailed.provider'))
    }
  }

  const handleTest = async (provider) => {
    setTesting(true)
    try {
      const response = await hsmService.testProvider(provider.id)
      if (response.data?.success) {
        showSuccess(response.data.message || t('messages.success.hsm.connectionOk'))
        loadData()
      } else {
        showError(response.data?.message || t('messages.errors.hsm.testFailed'))
      }
    } catch (error) {
      showError(error.message || t('messages.errors.hsm.testFailed'))
    } finally {
      setTesting(false)
    }
  }

  const handleSave = async (formData) => {
    try {
      if (modalMode === 'create') {
        await hsmService.createProvider(formData)
        showSuccess(t('messages.success.create.provider'))
      } else {
        await hsmService.updateProvider(selectedProvider.id, formData)
        showSuccess(t('messages.success.update.provider'))
      }
      setShowModal(false)
      loadData()
    } catch (error) {
      showError(error.message || t('messages.errors.createFailed.provider'))
    }
  }

  const handleGenerateKey = async (keyData) => {
    try {
      await hsmService.addKey(selectedProvider.id, keyData)
      showSuccess(t('messages.success.create.key'))
      setShowKeyModal(false)
      loadKeys(selectedProvider.id)
    } catch (error) {
      showError(error.message || t('messages.errors.createFailed.generic'))
    }
  }

  const handleDeleteKey = async (key) => {
    const confirmed = await showConfirm(t('messages.confirm.hsm.deleteKey', { name: key.label }), { variant: 'danger', confirmText: t('common.delete') })
    if (!confirmed) return
    try {
      await hsmService.deleteKey(key.id)
      showSuccess(t('messages.success.delete.key'))
      loadKeys(selectedProvider.id)
    } catch (error) {
      showError(error.message || t('messages.errors.deleteFailed.key'))
    }
  }

  const handleBeginCeremony = async (provider) => {
    setCeremonyBusy(true)
    try {
      await hsmService.beginCeremony(provider.id)
      showSuccess(t('hsm.ceremony.windowOpened'))
      await refreshProviderDetail(provider.id)
      loadData()
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const setTokenPin = (custodianId, field, value) => {
    setTokenPins((prev) => ({
      ...prev,
      [custodianId]: { ...(prev[custodianId] || {}), [field]: value },
    }))
  }

  const handleInspectToken = async (provider, custodian) => {
    setCeremonyBusy(true)
    try {
      await hsmService.inspectToken(provider.id, custodian.id)
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handlePrepareToken = async (provider, custodian) => {
    const state = custodian.card_state || 'unknown'
    const typed = await showPrompt(
      t('hsm.ceremony.preparePrompt', { state: t(`hsm.ceremony.tokenState.${state}`) }),
      {
        title: t('hsm.ceremony.prepareTitle'),
        placeholder: 'DELETE',
        confirmText: t('hsm.ceremony.prepare'),
      },
    )
    if (typed == null) return
    if (typed !== 'DELETE') {
      showError(t('hsm.ceremony.prepareMismatch'))
      return
    }
    const pins = tokenPins[custodian.id] || {}
    if (state === 'uninitialized' && (!pins.so_pin || !pins.user_pin)) {
      showError(t('hsm.ceremony.preparePinsRequired'))
      return
    }
    setCeremonyBusy(true)
    try {
      await hsmService.prepareToken(provider.id, custodian.id, {
        confirm: 'DELETE',
        so_pin: pins.so_pin || '',
        user_pin: pins.user_pin || '',
      })
      setTokenPins((prev) => {
        const next = { ...prev }
        delete next[custodian.id]
        return next
      })
      showSuccess(t('hsm.ceremony.prepareDone'))
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handleReinitializeToken = async (provider, custodian) => {
    const pins = tokenPins[custodian.id] || {}
    const nOfM = (provider.device_scheme || 'shares') === 'shares'
    if (!pins.so_pin || !pins.user_pin) {
      showError(t('hsm.ceremony.reinitPinsRequired'))
      return
    }
    const typed = await showPrompt(
      nOfM
        ? t('hsm.ceremony.reinitPrompt', { n: provider.threshold_n, m: provider.total_m })
        : t('hsm.ceremony.reinitPromptOther', { scheme: t(`hsm.scHsmCloudConfig.cardUse.${provider.device_scheme}`) }),
      {
        title: t('hsm.ceremony.reinitTitle'),
        placeholder: 'DELETE',
        confirmText: t('hsm.ceremony.reinitialize'),
      },
    )
    if (typed == null) return
    if (typed !== 'DELETE') {
      showError(t('hsm.ceremony.reinitMismatch'))
      return
    }
    setCeremonyBusy(true)
    try {
      await hsmService.prepareToken(provider.id, custodian.id, {
        confirm: 'DELETE',
        so_pin: pins.so_pin,
        user_pin: pins.user_pin,
        reinitialize: true,
      })
      setTokenPins((prev) => {
        const next = { ...prev }
        delete next[custodian.id]
        return next
      })
      showSuccess(t('hsm.ceremony.reinitDone'))
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handleCreateRootKey = async (provider, custodian) => {
    const typed = await showPrompt(t('hsm.ceremony.createPrompt', {
      name: custodian.username || custodian.name || `#${custodian.share_index}`,
    }), {
      title: t('hsm.ceremony.createTitle'),
      placeholder: 'DELETE',
      confirmText: t('hsm.ceremony.create'),
    })
    if (typed == null) return
    if (typed !== 'DELETE') {
      showError(t('hsm.ceremony.createMismatch'))
      return
    }
    const userPin = (tokenPins[custodian.id] || {}).user_pin || ''
    if (!userPin) {
      showError(t('hsm.ceremony.assemblyPinRequired'))
      return
    }
    setCeremonyBusy(true)
    try {
      await hsmService.createRootKey(provider.id, custodian.share_index, userPin)
      setTokenPins((prev) => ({
        ...prev,
        [custodian.id]: { ...(prev[custodian.id] || {}), user_pin: '' },
      }))
      showSuccess(t('hsm.ceremony.createDone'))
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handleSetAssemblySlot = async (provider, custodian) => {
    const userPin = (tokenPins[custodian.id] || {}).user_pin || ''
    if (!userPin) {
      showError(t('hsm.ceremony.assemblyPinRequired'))
      return
    }
    setCeremonyBusy(true)
    try {
      await hsmService.setAssemblySlot(provider.id, custodian.share_index, userPin)
      setTokenPins((prev) => ({
        ...prev,
        [custodian.id]: { ...(prev[custodian.id] || {}), user_pin: '' },
      }))
      showSuccess(t('hsm.ceremony.assemblySet'))
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handleRollRootKey = async (provider) => {
    const confirmed = await showConfirm(t('hsm.ceremony.rollConfirm'), {
      variant: 'danger',
      confirmText: t('hsm.ceremony.roll'),
    })
    if (!confirmed) return
    const assembly = (provider.custodians || []).find(
      (c) => provider.assembly_slot != null && Number(provider.assembly_slot) === Number(c.share_index),
    )
    const userPin = assembly ? ((tokenPins[assembly.id] || {}).user_pin || '') : ''
    setCeremonyBusy(true)
    try {
      await hsmService.rollRootKey(provider.id, userPin)
      showSuccess(t('hsm.ceremony.rollDone'))
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handleWipeAssembly = async (provider) => {
    if (provider.crl_stale) {
      showError(t('hsm.ceremony.wipeBlockedCrl'))
      return
    }
    if (provider.ocsp_responder_warning && !ocspAckChecked) {
      showError(t('hsm.ceremony.ocspAckRequired'))
      return
    }
    const confirmed = await showConfirm(t('hsm.ceremony.wipeConfirm'), {
      variant: 'danger',
      confirmText: t('hsm.ceremony.wipe'),
    })
    if (!confirmed) return
    setCeremonyBusy(true)
    try {
      if (provider.ocsp_responder_warning) {
        await hsmService.acknowledgeOcspWarning(provider.id)
      }
      await hsmService.wipeAssembly(provider.id)
      showSuccess(t('hsm.ceremony.wipeDone'))
      await refreshProviderDetail(provider.id)
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  const handleEndCeremony = async (provider) => {
    if (!provider.wipe_confirmed) {
      showError(t('hsm.ceremony.endRequiresWipe'))
      return
    }
    setCeremonyBusy(true)
    try {
      await hsmService.endCeremony(provider.id)
      showSuccess(t('hsm.ceremony.windowClosed'))
      setOcspAckChecked(false)
      await refreshProviderDetail(provider.id)
      loadData()
    } catch (error) {
      showError(error.message || t('hsm.ceremony.actionFailed'))
    } finally {
      setCeremonyBusy(false)
    }
  }

  // Table columns with icon-bg classes
  const columns = [
    {
      key: 'name',
      header: t('common.providerName'),
      priority: 1,
      sortable: true,
      render: (val, row) => {
        const Icon = PROVIDER_ICONS[row.provider_type] || Lock
        return (
          <div className="flex items-center gap-2">
            <div className={`w-6 h-6 rounded-lg flex items-center justify-center shrink-0 ${
              row.enabled ? 'icon-bg-violet' : 'icon-bg-gray'
            }`}>
              <Icon size={14} weight="duotone" />
            </div>
            <span className="font-medium truncate">{val}</span>
          </div>
        )
      },
      mobileRender: (val, row) => {
        const Icon = PROVIDER_ICONS[row.provider_type] || Lock
        return (
          <div className="flex items-center justify-between gap-2 w-full">
            <div className="flex items-center gap-2 min-w-0 flex-1">
              <div className={`w-6 h-6 rounded-lg flex items-center justify-center shrink-0 ${
                row.enabled ? 'icon-bg-violet' : 'icon-bg-gray'
              }`}>
                <Icon size={14} weight="duotone" />
              </div>
              <span className="font-medium truncate">{val}</span>
            </div>
            <Badge variant={row.enabled ? 'success' : 'secondary'} size="sm" dot pulse={row.enabled}>
              {row.enabled ? t('common.enabled') : t('common.disabled')}
            </Badge>
          </div>
        )
      }
    },
    {
      key: 'provider_type',
      header: t('common.type'),
      priority: 2,
      sortable: true,
      hideOnMobile: true,
      render: (val) => {
        const type = PROVIDER_TYPES.find(t => t.value === val)
        const isCloud = val !== 'pkcs11'
        return (
          <Badge variant={isCloud ? 'cyan' : 'secondary'} size="sm" icon={isCloud ? Cloud : HardDrive}>
            {type?.label.split(' ')[0] || val}
          </Badge>
        )
      },
      mobileRender: (val) => {
        const type = PROVIDER_TYPES.find(t => t.value === val)
        const isCloud = val !== 'pkcs11'
        return (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-text-tertiary">{t('common.type')}:</span>
            <span className="text-text-secondary">{type?.label.split(' ')[0] || val}</span>
          </div>
        )
      }
    },
    {
      key: 'enabled',
      header: t('common.status'),
      priority: 1,
      sortable: true,
      hideOnMobile: true,
      render: (val) => (
        <Badge variant={val ? 'success' : 'secondary'} size="sm" dot pulse={val}>
          {val ? t('common.enabled') : t('common.disabled')}
        </Badge>
      )
    },
    {
      key: 'key_count',
      header: t('hsm.stats.keys'),
      priority: 2,
      hideOnMobile: true,
      render: (val) => (
        <Badge variant={val > 0 ? 'purple' : 'secondary'} size="sm" icon={Key}>
          {val || 0}
        </Badge>
      )
    }
  ]

  const rowActions = (row) => [
    { label: t('common.test'), icon: TestTube, onClick: () => handleTest(row) },
    ...(canWrite('hsm') ? [{ label: t('common.edit'), icon: PencilSimple, onClick: () => handleEdit(row) }] : []),
    ...(canDelete('hsm') ? [{ label: t('common.delete'), icon: Trash, variant: 'danger', onClick: () => handleDelete(row) }] : [])
  ]

  const stats = useMemo(() => {
    const enabledCount = providers.filter(p => p.enabled).length
    const disabledCount = providers.filter(p => !p.enabled).length
    const totalKeys = providers.reduce((acc, p) => acc + (p.key_count || 0), 0)
    const cloudCount = providers.filter(p => p.provider_type !== 'pkcs11').length
    return [
      { label: t('hsm.stats.providers'), value: providers.length, icon: Lock, variant: 'primary' },
      { label: t('common.enabled'), value: enabledCount, icon: CheckCircle, variant: 'success' },
      { label: t('common.disabled'), value: disabledCount, icon: XCircle, variant: 'neutral' },
      { label: t('hsm.stats.keys'), value: totalKeys, icon: Key, variant: 'purple' },
      { label: t('hsm.stats.cloud'), value: cloudCount, icon: Cloud, variant: 'cyan' },
    ]
  }, [providers, t])

  const filteredProviders = useMemo(() => {
    let result = providers
    if (filterType.length > 0) {
      result = result.filter(p => filterType.includes(p.provider_type))
    }
    if (filterStatus.length > 0) {
      result = result.filter(p => {
        const status = p.enabled ? 'enabled' : 'disabled'
        return filterStatus.includes(status)
      })
    }
    return result
  }, [providers, filterType, filterStatus])

  // Help content
  // Help content now provided via FloatingHelpPanel (helpPageKey="hsm")

  // Details panel content
  const renderDetails = (provider) => {
    const Icon = PROVIDER_ICONS[provider.provider_type] || Lock
    const typeLabel = PROVIDER_TYPES.find(t => t.value === provider.provider_type)?.label || provider.provider_type
    const isScHsm = provider.provider_type === 'sc-hsm-cloud'
    const ceremony = isScHsm ? parseCeremonyStatus(provider) : null
    const currentUserId = user?.id
    const custodians = Array.isArray(provider.custodians) ? provider.custodians : []
    const myCustodian = custodians.find(c => c.user_id === currentUserId || c.is_me)
    const statusKey = (status) => {
      if (status === 'connected') return 'hsm.ceremony.statusConnected'
      if (status === 'contributed') return 'hsm.ceremony.statusContributed'
      return 'hsm.ceremony.statusWaiting'
    }
    const statusVariant = (status) => {
      if (status === 'connected') return 'success'
      if (status === 'contributed') return 'purple'
      return 'secondary'
    }
    const bridge = provider.bridge || {}
    const accessLabel = (step) => t(`hsm.ceremony.step.${step}`)

    return (
      <div className="p-3 space-y-3">
        <CompactHeader
          icon={Icon}
          iconClass={provider.enabled ? 'icon-bg-violet' : 'bg-bg-tertiary'}
          title={provider.name}
          subtitle={typeLabel}
          badge={
            <Badge variant={provider.enabled ? 'success' : 'secondary'} size="sm">
              {provider.enabled ? t('common.enabled') : t('common.disabled')}
            </Badge>
          }
        />

        <CompactStats stats={[
          { icon: Key, value: t('hsm.keysInHsm', { count: provider.key_count || 0 }).replace('{{count}} keys in this HSM', `${provider.key_count || 0} keys`) },
          { icon: CheckCircle, value: provider.last_connected_at ? t('common.connected') : t('common.never') },
        ]} />

        <div className="flex gap-2">
          <Button type="button" size="sm" variant="secondary" className="flex-1" onClick={() => handleTest(provider)} disabled={testing}>
            {testing ? <ArrowsClockwise size={14} className="animate-spin" /> : <TestTube size={14} />}
            {testing ? t('common.testing') : t('common.test')}
          </Button>
          {canWriteHsm && (
          <Button type="button" size="sm" variant="secondary" onClick={() => handleEdit(provider)}>
            <PencilSimple size={14} />
          </Button>
          )}
          {canDelete('hsm') && (
          <Button type="button" size="sm" variant="danger" onClick={() => handleDelete(provider)}>
            <Trash size={14} />
          </Button>
          )}
        </div>

        {provider.last_error && (
          <div className="p-3 rounded-lg bg-status-danger-op10 border border-status-danger-op30">
            <div className="flex items-center gap-2 text-status-danger text-xs">
              <Warning size={14} />
              <span className="font-medium">{t('hsm.connectionError')}</span>
            </div>
            <p className="text-2xs text-text-secondary mt-1">{provider.last_error}</p>
          </div>
        )}

        <CompactSection title={t('common.config')}>
          {provider.provider_type === 'pkcs11' && (
            <>
              <CompactGrid>
                <CompactField autoIcon="slotId" label={t('hsm.pkcs11Config.slotId')} value={provider.pkcs11_slot_id ?? 'Auto'} copyable />
                <CompactField autoIcon="token" label={t('hsm.pkcs11Config.token')} value={provider.pkcs11_token_label || '-'} copyable />
              </CompactGrid>
              <div className="mt-2 text-xs">
                <span className="text-text-tertiary block mb-0.5">{t('hsm.pkcs11Config.libraryPath')}:</span>
                <div className="relative group">
                  <p className="font-mono text-2xs text-text-secondary break-all bg-tertiary-op50 p-1.5 rounded pr-7">
                    {provider.pkcs11_library_path || '-'}
                  </p>
                  {provider.pkcs11_library_path && (
                    <button
                      type="button"
                      onClick={() => { copy(provider.pkcs11_library_path); showSuccess(t('common.copied')) }}
                      className="absolute top-1 right-1 opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-bg-tertiary text-text-tertiary hover:text-text-primary transition-all"
                      aria-label={t('common.copy')}
                    >
                      <Copy size={12} />
                    </button>
                  )}
                </div>
              </div>
            </>
          )}
          {provider.provider_type === 'aws-cloudhsm' && (
            <CompactGrid>
              <CompactField autoIcon="clusterId" label={t('hsm.awsConfig.clusterId')} value={provider.aws_cluster_id} mono copyable />
              <CompactField autoIcon="region" label={t('hsm.awsConfig.region')} value={provider.aws_region} copyable />
              <CompactField autoIcon="cryptoUser" label={t('hsm.awsConfig.cryptoUser')} value={provider.aws_crypto_user} copyable />
            </CompactGrid>
          )}
          {provider.provider_type === 'azure-keyvault' && (
            <>
              <div className="text-xs mb-2">
                <span className="text-text-tertiary block mb-0.5">{t('hsm.azureConfig.vaultUrl')}:</span>
                <div className="relative group">
                  <p className="font-mono text-2xs text-text-secondary break-all bg-tertiary-op50 p-1.5 rounded pr-7">
                    {provider.azure_vault_url || '-'}
                  </p>
                  {provider.azure_vault_url && (
                    <button
                      type="button"
                      onClick={() => { copy(provider.azure_vault_url); showSuccess(t('common.copied')) }}
                      className="absolute top-1 right-1 opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-bg-tertiary text-text-tertiary hover:text-text-primary transition-all"
                      aria-label={t('common.copy')}
                    >
                      <Copy size={12} />
                    </button>
                  )}
                </div>
              </div>
              <CompactGrid>
                <CompactField autoIcon="tenant" label={t('hsm.azureConfig.tenant')} value={provider.azure_tenant_id} mono copyable />
                <CompactField autoIcon="client" label={t('hsm.azureConfig.client')} value={provider.azure_client_id} mono copyable />
              </CompactGrid>
            </>
          )}
          {provider.provider_type === 'google-kms' && (
            <CompactGrid>
              <CompactField autoIcon="project" label={t('hsm.gcpConfig.project')} value={provider.gcp_project_id} copyable />
              <CompactField autoIcon="location" label={t('hsm.gcpConfig.location')} value={provider.gcp_location} copyable />
              <CompactField autoIcon="keyRing" label={t('hsm.gcpConfig.keyRing')} value={provider.gcp_keyring} copyable />
            </CompactGrid>
          )}
          {provider.provider_type === 'openbao' && (
            <CompactGrid>
              <CompactField autoIcon="url" label={t('hsm.openbaoConfig.url')} value={provider.openbao_url} copyable />
              <CompactField autoIcon="mountPath" label={t('hsm.openbaoConfig.mountPath')} value={provider.openbao_mount_path || 'transit'} copyable />
              {provider.openbao_namespace && (
                <CompactField autoIcon="namespace" label={t('hsm.openbaoConfig.namespace')} value={provider.openbao_namespace} copyable />
              )}
            </CompactGrid>
          )}
          {isScHsm && (
            <CompactGrid>
              <CompactField autoIcon="token" label={t('hsm.scHsmCloudConfig.tokenLabel')} value={provider.token_label || provider.sc_token_label || '-'} copyable />
              {(provider.device_scheme || 'shares') === 'shares' ? (
                <>
                  <CompactField autoIcon="threshold" label={t('hsm.scHsmCloudConfig.thresholdN')} value={provider.threshold_n ?? '-'} />
                  <CompactField autoIcon="total" label={t('hsm.scHsmCloudConfig.totalM')} value={provider.total_m ?? '-'} />
                </>
              ) : (
                <CompactField
                  autoIcon="scheme"
                  label={t('hsm.scHsmCloudConfig.cardUseLabel')}
                  value={t(`hsm.scHsmCloudConfig.cardUse.${provider.device_scheme}`)}
                />
              )}
            </CompactGrid>
          )}
        </CompactSection>

        {isScHsm && (
          <CompactSection title={t('hsm.ceremony.title')}>
            <div className="space-y-3 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={bridge.reachable ? 'success' : 'danger'} size="sm" icon={bridge.reachable ? CheckCircle : XCircle}>
                  {bridge.reachable ? t('hsm.ceremony.bridgeUp') : t('hsm.ceremony.bridgeDown')}
                </Badge>
                <Badge variant={bridge.vpcd_connected ? 'success' : 'secondary'} size="sm" icon={Cpu}>
                  {bridge.vpcd_connected ? t('hsm.ceremony.readerMounted') : t('hsm.ceremony.readerIdle')}
                </Badge>
                <Badge variant={ceremony.open ? 'success' : 'secondary'} size="sm" icon={ceremony.open ? CheckCircle : Lock}>
                  {ceremony.open
                    ? t('hsm.ceremony.connectedCount', { count: ceremony.connected_count, total: provider.total_m || custodians.length })
                    : t('hsm.ceremony.offline')}
                </Badge>
                {provider.key_assembled && (
                  <Badge variant="success" size="sm" icon={Key}>
                    {t('hsm.ceremony.keyPresent', { fingerprint: provider.key_fingerprint || '—' })}
                  </Badge>
                )}
                {provider.crl_stale ? (
                  <Badge variant="warning" size="sm" icon={Warning}>{t('hsm.ceremony.crlStale')}</Badge>
                ) : ceremony.open ? (
                  <Badge variant="success" size="sm">{t('hsm.ceremony.crlFresh')}</Badge>
                ) : null}
                {provider.wipe_confirmed ? (
                  <Badge variant="success" size="sm">{t('hsm.ceremony.wipeConfirmed')}</Badge>
                ) : ceremony.open ? (
                  <Badge variant="secondary" size="sm">{t('hsm.ceremony.wipePending')}</Badge>
                ) : null}
              </div>
              {provider.ram_public?.origin && (
                <p className="text-text-secondary">
                  {provider.ram_public.mode === 'dedicated'
                    ? t('hsm.ceremony.ramPublicDedicated', {
                      origin: provider.ram_public.origin,
                      port: provider.ram_public.listen_port,
                    })
                    : t('hsm.ceremony.ramPublicDirect', {
                      origin: provider.ram_public.origin,
                      port: provider.ram_public.listen_port,
                    })}
                </p>
              )}
              {!bridge.reachable && bridge.error && (
                <p className="text-2xs text-text-tertiary break-all">{bridge.error}</p>
              )}
              <p className="text-text-secondary">{t('hsm.ceremony.tokenReadyHint')}</p>

              {provider.ocsp_responder_warning && ceremony.open && (
                <div className="p-2.5 rounded-lg border border-yellow-500/30 bg-yellow-500/10 space-y-2">
                  <div className="flex items-start gap-2 text-yellow-700 dark:text-yellow-400">
                    <Warning size={14} className="shrink-0 mt-0.5" weight="bold" />
                    <p className="font-medium">{t('hsm.ceremony.ocspWarning')}</p>
                  </div>
                  {typeof provider.ocsp_responder_warning === 'object' && provider.ocsp_responder_warning.message && (
                    <p className="text-2xs text-text-secondary">{provider.ocsp_responder_warning.message}</p>
                  )}
                  <label className="flex items-start gap-2 cursor-pointer text-text-secondary">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={ocspAckChecked}
                      onChange={(e) => setOcspAckChecked(e.target.checked)}
                    />
                    <span>{t('hsm.ceremony.ocspAcknowledge')}</span>
                  </label>
                </div>
              )}

              <div>
                <p className="text-text-tertiary mb-1 font-medium">{t('hsm.ceremony.operatorActions')}</p>
                <ul className="list-disc pl-4 space-y-0.5 text-text-secondary">
                  <li>{t('hsm.ceremony.actions.publishCrl')}</li>
                  <li>{t('hsm.ceremony.actions.revokeSubordinate')}</li>
                  <li>{t('hsm.ceremony.actions.revokeEndEntity')}</li>
                  <li>{t('hsm.ceremony.actions.issueSubordinate')}</li>
                  <li>{t('hsm.ceremony.actions.renewRoot')}</li>
                  <li>{t('hsm.ceremony.actions.ocspResponder')}</li>
                  <li>{t('hsm.ceremony.actions.rollRootKey')}</li>
                </ul>
              </div>

              {(canWriteHsm || canContributeHsm) && (
                <div className="flex flex-wrap gap-2">
                  {!ceremony.open && canWriteHsm && (
                    <Button type="button" size="sm" onClick={() => handleBeginCeremony(provider)} disabled={ceremonyBusy}>
                      {ceremonyBusy ? <ArrowsClockwise size={14} className="animate-spin" /> : null}
                      {t('hsm.ceremony.begin')}
                    </Button>
                  )}
                  {ceremony.open && canWriteHsm && (
                    <>
                      {provider.key_assembled && (provider.device_scheme || 'shares') === 'shares' && (
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          onClick={() => handleRollRootKey(provider)}
                          disabled={ceremonyBusy || !!provider.wipe_confirmed}
                        >
                          {t('hsm.ceremony.roll')}
                        </Button>
                      )}
                      <Button
                        type="button"
                        size="sm"
                        variant="danger"
                        onClick={() => handleWipeAssembly(provider)}
                        disabled={ceremonyBusy || !!provider.crl_stale || (!!provider.ocsp_responder_warning && !ocspAckChecked) || !!provider.wipe_confirmed}
                        title={provider.crl_stale ? t('hsm.ceremony.wipeBlockedCrl') : undefined}
                      >
                        {t('hsm.ceremony.wipe')}
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="secondary"
                        onClick={() => handleEndCeremony(provider)}
                        disabled={ceremonyBusy || !provider.wipe_confirmed}
                      >
                        {t('hsm.ceremony.end')}
                      </Button>
                    </>
                  )}
                </div>
              )}

              {ceremony.open && (
                <>
                  <div>
                    <p className="text-text-tertiary mb-1.5 font-medium flex items-center gap-1">
                      <Users size={12} /> {t('hsm.ceremony.custodianRoster')}
                    </p>
                    <div className="space-y-2">
                      {custodians.map((c) => {
                        const isAssembly = provider.assembly_slot != null
                          && Number(provider.assembly_slot) === Number(c.share_index)
                        const isMine = c.user_id === currentUserId || c.is_me
                        const showCommand = isMine && (canContributeHsm || canWriteHsm) && c.ram_client_url
                        const command = buildRamClientCommand(c.ram_client_url)
                        return (
                          <div key={`${c.user_id}-${c.share_index}`} className="p-2 rounded bg-tertiary-op50 space-y-1.5">
                            <div className="flex items-center justify-between gap-2">
                              <div className="min-w-0">
                                <p className="font-medium text-text-primary truncate">
                                  {c.username || c.name || t('hsm.scHsmCloudConfig.custodian')} #{c.share_index}
                                  {isMine ? ` (${t('hsm.ceremony.you')})` : ''}
                                </p>
                                <p className="text-2xs text-text-tertiary">
                                  {t('hsm.scHsmCloudConfig.shareIndex')}: {c.share_index}
                                  {isAssembly ? ` · ${t('hsm.ceremony.assemblyDevice')}` : ''}
                                </p>
                              </div>
                              <Badge variant={statusVariant(c.status)} size="sm">
                                {t(statusKey(c.status))}
                              </Badge>
                            </div>
                            <ol className="flex flex-wrap gap-1" aria-label={t('hsm.ceremony.accessSteps')}>
                              {ACCESS_STEPS.map((step) => {
                                const reached = accessStepReached(c.access || 'waiting', step)
                                const current = (c.access || 'waiting') === step
                                return (
                                  <li
                                    key={step}
                                    className={`px-1.5 py-0.5 rounded text-2xs list-none ${
                                      current && reached
                                        ? 'bg-green-500/20 text-green-700 dark:text-green-400 font-medium'
                                        : reached
                                          ? 'text-text-secondary'
                                          : 'text-text-tertiary'
                                    }`}
                                  >
                                    {accessLabel(step)}
                                  </li>
                                )
                              })}
                            </ol>
                            {c.probe_error && (
                              <p className="text-2xs text-red-600 dark:text-red-400">{c.probe_error}</p>
                            )}
                            {!c.probe_error && c.probe_sw === '6A82' && (
                              <p className="text-2xs text-text-secondary">{t('hsm.ceremony.noShareFile')}</p>
                            )}
                            {(c.status === 'connected' || c.status === 'contributed') && (canWriteHsm || isMine) && (
                              <div className="space-y-1.5">
                                {c.card_state && (
                                  <p className={`text-2xs ${c.card_ready ? 'text-green-700 dark:text-green-400' : 'text-text-secondary'}`}>
                                    {t(`hsm.ceremony.tokenState.${c.card_state}`)}
                                  </p>
                                )}
                                <div className="flex flex-wrap gap-2">
                                  <Button
                                    type="button"
                                    size="sm"
                                    variant="secondary"
                                    onClick={() => handleInspectToken(provider, c)}
                                    disabled={ceremonyBusy}
                                  >
                                    {t('hsm.ceremony.checkToken')}
                                  </Button>
                                  {c.card_state && !c.card_ready && (
                                    <Button
                                      type="button"
                                      size="sm"
                                      variant="danger"
                                      onClick={() => handlePrepareToken(provider, c)}
                                      disabled={ceremonyBusy || !!provider.key_assembled}
                                      title={provider.key_assembled ? t('hsm.ceremony.prepareBlockedAssembled') : undefined}
                                    >
                                      {t('hsm.ceremony.prepare')}
                                    </Button>
                                  )}
                                </div>
                                {!provider.key_assembled && (
                                  <div className="space-y-1.5 rounded border border-border-primary p-2">
                                    <p className="text-2xs text-text-secondary">
                                      {(provider.device_scheme || 'shares') === 'shares'
                                        ? t('hsm.ceremony.reinitHint', { n: provider.threshold_n, m: provider.total_m })
                                        : t('hsm.ceremony.reinitHintOther', { scheme: t(`hsm.scHsmCloudConfig.cardUse.${provider.device_scheme}`) })}
                                    </p>
                                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                                      <Input
                                        label={t('hsm.ceremony.soPin')}
                                        type="password"
                                        noAutofill
                                        value={(tokenPins[c.id] || {}).so_pin || ''}
                                        onChange={(e) => setTokenPin(c.id, 'so_pin', e.target.value)}
                                        placeholder="16 hex"
                                      />
                                      <Input
                                        label={t('hsm.ceremony.userPin')}
                                        type="password"
                                        noAutofill
                                        value={(tokenPins[c.id] || {}).user_pin || ''}
                                        onChange={(e) => setTokenPin(c.id, 'user_pin', e.target.value)}
                                      />
                                    </div>
                                    <Button
                                      type="button"
                                      size="sm"
                                      variant="danger"
                                      onClick={() => handleReinitializeToken(provider, c)}
                                      disabled={ceremonyBusy}
                                    >
                                      {t('hsm.ceremony.reinitialize')}
                                    </Button>
                                  </div>
                                )}
                              </div>
                            )}
                            {showCommand && (
                              <div>
                                <span className="text-text-tertiary block mb-0.5">{t('hsm.ceremony.yourCommand')}:</span>
                                <div className="relative group">
                                  <p className="font-mono text-2xs text-text-secondary break-all bg-bg-primary p-1.5 rounded pr-7 border border-border-primary">
                                    {command}
                                  </p>
                                  <button
                                    type="button"
                                    onClick={() => { copy(command); showSuccess(t('common.copied')) }}
                                    className="absolute top-1 right-1 opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-bg-tertiary text-text-tertiary hover:text-text-primary transition-all"
                                    aria-label={t('hsm.ceremony.copyCommand')}
                                  >
                                    <Copy size={12} />
                                  </button>
                                </div>
                              </div>
                            )}
                            {ceremony.open && canWriteHsm && !provider.key_assembled && (provider.device_scheme || 'shares') === 'shares' && (c.status === 'connected' || c.status === 'contributed') && (
                              <Button
                                type="button"
                                size="sm"
                                onClick={() => handleCreateRootKey(provider, c)}
                                disabled={ceremonyBusy}
                              >
                                {t('hsm.ceremony.createHere')}
                              </Button>
                            )}
                            {ceremony.open && canWriteHsm && !isAssembly && (provider.device_scheme || 'shares') === 'shares' && (c.status === 'connected' || c.status === 'contributed') && (
                              <Button
                                type="button"
                                size="sm"
                                variant="secondary"
                                onClick={() => handleSetAssemblySlot(provider, c)}
                                disabled={ceremonyBusy}
                              >
                                {t('hsm.ceremony.setAssembly')}
                              </Button>
                            )}
                          </div>
                        )
                      })}
                      {custodians.length === 0 && (
                        <p className="text-text-tertiary text-center py-2">{t('hsm.scHsmCloudConfig.noCustodians')}</p>
                      )}
                    </div>
                  </div>
                  {myCustodian && !myCustodian.ram_client_url && canContributeHsm && (
                    <p className="text-text-tertiary">{t('hsm.ceremony.noCommand')}</p>
                  )}
                </>
              )}
            </div>
          </CompactSection>
        )}

        {!isScHsm && (
        <CompactSection title={t('hsm.hsmKeys')}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-text-tertiary">{t('hsm.keysInHsm', { count: keys.length })}</span>
            {canWriteHsm && (
            <Button type="button" size="sm" variant="secondary" onClick={() => setShowKeyModal(true)}>
              <Plus size={12} /> {t('common.generate')}
            </Button>
            )}
          </div>
          {keys.length === 0 ? (
            <p className="text-xs text-text-tertiary text-center py-4">{t('hsm.noKeysInHsm')}</p>
          ) : (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {keys.map(key => (
                <div key={key.id} className="flex items-center justify-between p-2 bg-tertiary-op50 rounded text-xs">
                  <div className="flex items-center gap-2 min-w-0">
                    <Key size={14} className="text-text-tertiary flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="font-medium text-text-primary truncate">{key.label}</p>
                      <p className="text-text-tertiary">{key.key_type} {key.key_size}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={key.status === 'active' ? 'success' : 'danger'} size="sm">
                      {key.status}
                    </Badge>
                    {canDelete('hsm') && (
                    <Button type="button" size="sm" variant="ghost" onClick={() => handleDeleteKey(key)} aria-label={t('common.delete')}>
                      <Trash size={12} className="text-status-danger" />
                    </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CompactSection>
        )}
      </div>
    )
  }

  return (
    <>
      {hsmStatus && !hsmStatus.ready && (() => {
        // The PKCS#11 / SoftHSM warning is only relevant when the user is
        // actually trying to use a local PKCS#11 provider. Hide it otherwise:
        // remote providers (OpenBao, Azure Key Vault, AWS CloudHSM, Google KMS,
        // SmartCard-HSM) do not need python-pkcs11 or SoftHSM on the UCM host.
        const usesLocalPkcs11 = providers.some(p => (p.provider_type || p.type) === 'pkcs11')
        if (!usesLocalPkcs11) return null
        return (
        <div className="mx-4 mt-4 mb-0 p-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 flex items-start gap-3">
          <Warning size={20} className="text-yellow-500 shrink-0 mt-0.5" weight="bold" />
          <div className="text-sm">
            <p className="font-medium text-yellow-600 dark:text-yellow-400 mb-1">
              {t('hsm.pkcs11Unavailable')}
            </p>
            <ul className="text-text-secondary space-y-0.5 text-xs">
              {!hsmStatus.pkcs11_installed && <li>• {t('hsm.pkcs11Missing')}</li>}
              {!hsmStatus.softhsm_found && <li>• {t('hsm.softhsmMissing')}</li>}
            </ul>
            {hsmStatus.install_command && (
              <code className="block mt-2 px-2 py-1 rounded bg-bg-tertiary text-xs font-mono">
                {hsmStatus.install_command}
              </code>
            )}
          </div>
        </div>
        )
      })()}
      <ResponsiveLayout
        title={t('common.hsm')}
        subtitle={t('hsm.subtitle', { count: providers.length })}
        icon={Key}
        badge={<ExperimentalBadge />}
        stats={stats}
        helpPageKey="hsm"
        splitView={true}
        splitEmptyContent={
          <div className="h-full flex flex-col items-center justify-center p-6 text-center">
            <div className="w-14 h-14 rounded-xl bg-bg-tertiary flex items-center justify-center mb-3">
              <Lock size={24} className="text-text-tertiary" weight="duotone" />
            </div>
            <p className="text-sm text-text-secondary">{t('hsm.selectProvider')}</p>
          </div>
        }
        slideOverOpen={!!selectedProvider}
        slideOverTitle={selectedProvider?.name || t('hsm.providerDetails')}
        slideOverContent={selectedProvider && renderDetails(selectedProvider)}
        slideOverWidth="lg"
        onSlideOverClose={() => setSelectedProvider(null)}
      >
        <div className="flex flex-col h-full min-h-0">
          <ResponsiveDataTable
            data={filteredProviders}
            columns={columns}
            loading={loading}
            onRowClick={handleSelectProvider}
            selectedId={selectedProvider?.id}
            searchable
            searchPlaceholder={t('common.searchProviders')}
            searchKeys={['name', 'provider_type']}
            toolbarFilters={[
              {
                key: 'enabled',
                label: t('common.status'),
                type: 'multiSelect',
                value: filterStatus,
                onChange: setFilterStatus,
                placeholder: t('common.allStatus'),
                options: [
                  { value: 'true', label: t('common.enabled') },
                  { value: 'false', label: t('common.disabled') }
                ]
              },
              {
                key: 'provider_type',
                label: t('common.type'),
                type: 'multiSelect',
                value: filterType,
                onChange: setFilterType,
                placeholder: t('common.allTypes'),
                options: PROVIDER_TYPES.map(t => ({ value: t.value, label: t.label.split(' ')[0] }))
              }
            ]}
            filterPresetsKey="ucm-hsm-presets"
            densityStorageKey="ucm-hsm-density"
            onApplyFilterPreset={handleApplyFilterPreset}
            toolbarActions={canWrite('hsm') ? (
              isMobile ? (
                <Button type="button" size="lg" onClick={handleCreate} className="w-11 h-11 p-0">
                  <Plus size={22} weight="bold" />
                </Button>
              ) : (
                <Button type="button" size="sm" onClick={handleCreate}>
                  <Plus size={16} /> {t('hsm.newProvider')}
                </Button>
              )
            ) : null}
            emptyIcon={Lock}
            emptyTitle={t('hsm.noHSM')}
            emptyDescription={t('hsm.noHSMDescription')}
            emptyAction={canWrite('hsm') ?
              <Button type="button" onClick={handleCreate}>
                <Plus size={16} /> {t('hsm.newProvider')}
              </Button>
            : null}
          />
        </div>
      </ResponsiveLayout>

      {showModal && (
        <ProviderModal
          provider={modalMode === 'edit' ? selectedProvider : null}
          hsmStatus={hsmStatus}
          onSave={handleSave}
          onClose={() => setShowModal(false)}
        />
      )}

      {showKeyModal && selectedProvider && (
        <KeyModal
          provider={selectedProvider}
          onSave={handleGenerateKey}
          onClose={() => setShowKeyModal(false)}
        />
      )}
    </>
  )
}

export function ProviderModal({ provider, hsmStatus, onSave, onClose }) {
  const { t } = useTranslation()
  const [users, setUsers] = useState([])
  const [formData, setFormData] = useState({
    name: provider?.name || '',
    provider_type: provider?.provider_type || 'pkcs11',
    enabled: provider?.enabled ?? false,
    connection_timeout: provider?.connection_timeout || 30,
    pkcs11_library_path: provider?.pkcs11_library_path || '',
    pkcs11_slot_id: provider?.pkcs11_slot_id ?? '',
    pkcs11_pin: provider?.pkcs11_pin || '',
    pkcs11_token_label: provider?.pkcs11_token_label || '',
    aws_cluster_id: provider?.aws_cluster_id || '',
    aws_region: provider?.aws_region || 'us-east-1',
    aws_access_key: provider?.aws_access_key || '',
    aws_secret_key: '',
    aws_crypto_user: provider?.aws_crypto_user || '',
    aws_crypto_password: provider?.aws_crypto_password || '',
    azure_vault_url: provider?.azure_vault_url || '',
    azure_tenant_id: provider?.azure_tenant_id || '',
    azure_client_id: provider?.azure_client_id || '',
    azure_client_secret: provider?.azure_client_secret || '',
    gcp_project_id: provider?.gcp_project_id || '',
    gcp_location: provider?.gcp_location || 'global',
    gcp_keyring: provider?.gcp_keyring || '',
    gcp_credentials_json: '',
    openbao_url: provider?.openbao_url || '',
    openbao_token: provider?.openbao_token || '',
    openbao_mount_path: provider?.openbao_mount_path || 'transit',
    openbao_namespace: provider?.openbao_namespace || '',
    openbao_tls_skip_verify: provider?.openbao_tls_skip_verify ?? false,
    sc_token_label: provider?.token_label || provider?.sc_token_label || '',
    device_scheme: provider?.device_scheme || 'shares',
    key_domains: provider?.key_domains ?? 1,
    threshold_n: provider?.threshold_n ?? 2,
    total_m: provider?.total_m ?? 3,
    custodians: Array.isArray(provider?.custodians)
      ? provider.custodians.map((c, i) => ({
          user_id: c.user_id ?? '',
          share_index: c.share_index ?? (i + 1),
        }))
      : [],
  })

  useEffect(() => {
    if (formData.provider_type !== 'sc-hsm-cloud') return undefined
    let cancelled = false
    usersService.getAll()
      .then((response) => {
        if (!cancelled) setUsers(response.data || [])
      })
      .catch(() => {
        if (!cancelled) setUsers([])
      })
    return () => { cancelled = true }
  }, [formData.provider_type])

  // Keep custodian rows aligned with total_m (share indices 1..m). Never hold share material.
  useEffect(() => {
    if (formData.provider_type !== 'sc-hsm-cloud') return
    const shares = (formData.device_scheme || 'shares') === 'shares'
    const m = shares ? Math.max(1, Number(formData.total_m) || 1) : 1
    setFormData(prev => {
      const current = prev.custodians || []
      const aligned = Array.from({ length: m }, (_, i) => ({
        user_id: current[i]?.user_id ?? '',
        share_index: i + 1,
      }))
      const same = current.length === aligned.length
        && current.every((c, i) => c.user_id === aligned[i].user_id && c.share_index === aligned[i].share_index)
      if (same) return prev
      return { ...prev, custodians: aligned }
    })
  }, [formData.provider_type, formData.total_m, formData.device_scheme])

  const handleChange = (field, value) => setFormData(prev => ({ ...prev, [field]: value }))

  const handleCustodianUser = (index, userId) => {
    setFormData(prev => {
      const custodians = [...prev.custodians]
      custodians[index] = { ...custodians[index], user_id: userId === '' ? '' : Number(userId) }
      return { ...prev, custodians }
    })
  }

  const userOptions = [
    { value: '', label: t('hsm.scHsmCloudConfig.selectUser') },
    ...users.map(u => ({
      value: String(u.id),
      label: u.username || u.email || String(u.id),
    })),
  ]

  const buildPayload = () => {
    const config = {}
    if (formData.provider_type === 'pkcs11') {
      config.module_path = formData.pkcs11_library_path
      config.token_label = formData.pkcs11_token_label
      config.user_pin = formData.pkcs11_pin
      if (formData.pkcs11_slot_id !== '') config.slot_index = formData.pkcs11_slot_id
    } else if (formData.provider_type === 'aws-cloudhsm') {
      config.module_path = formData.pkcs11_library_path || '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so'
      config.hsm_user = formData.aws_crypto_user
      config.hsm_password = formData.aws_crypto_password
      config.cluster_id = formData.aws_cluster_id
    } else if (formData.provider_type === 'azure-keyvault') {
      config.vault_url = formData.azure_vault_url
      config.tenant_id = formData.azure_tenant_id
      config.client_id = formData.azure_client_id
      config.client_secret = formData.azure_client_secret
    } else if (formData.provider_type === 'google-kms') {
      config.project_id = formData.gcp_project_id
      config.location = formData.gcp_location
      config.key_ring = formData.gcp_keyring
    } else if (formData.provider_type === 'openbao') {
      config.url = formData.openbao_url
      config.token = formData.openbao_token
      config.mount_path = formData.openbao_mount_path || 'transit'
      if (formData.openbao_namespace) config.namespace = formData.openbao_namespace
      config.tls_skip_verify = formData.openbao_tls_skip_verify
    } else if (formData.provider_type === 'sc-hsm-cloud') {
      const scheme = formData.device_scheme || 'shares'
      config.token_label = formData.sc_token_label
      config.device_scheme = scheme
      config.threshold_n = scheme === 'shares' ? (Number(formData.threshold_n) || 1) : 1
      config.total_m = scheme === 'shares' ? (Number(formData.total_m) || 1) : 1
      if (scheme === 'domains') config.key_domains = Number(formData.key_domains) || 1
      config.custodians = (formData.custodians || [])
        .filter(c => c.user_id !== '' && c.user_id != null)
        .map((c, i) => ({
          user_id: Number(c.user_id),
          share_index: Number(c.share_index) || (i + 1),
        }))
      // Share / DKEK material is never collected, stored, or echoed by this form.
    }
    return { name: formData.name, type: formData.provider_type, config }
  }

  return (
    <FormModal
      open={true}
      onClose={onClose}
      title={provider ? t('hsm.editProvider') : t('hsm.newProvider')}
      size="lg"
      onSubmit={() => onSave(buildPayload())}
      submitLabel={provider ? t('common.save') : t('common.create')}
    >
      <div className="grid grid-cols-2 gap-4">
        <Input label={t('common.providerName')} value={formData.name} onChange={e => handleChange('name', e.target.value)} required />
        {!provider && (
          <Select label={t('common.providerType')} value={formData.provider_type} onChange={value => handleChange('provider_type', value)} options={PROVIDER_TYPES} />
        )}
      </div>

      {formData.provider_type === 'pkcs11' && (
        <div className="space-y-4">
          {hsmStatus && !hsmStatus.ready && (
            <div className="p-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 flex items-start gap-3">
              <Warning size={18} className="text-yellow-500 shrink-0 mt-0.5" weight="bold" />
              <div className="text-xs">
                <p className="font-medium text-yellow-600 dark:text-yellow-400 mb-1">
                  {t('hsm.pkcs11Unavailable')}
                </p>
                <ul className="text-text-secondary space-y-0.5">
                  {!hsmStatus.pkcs11_installed && <li>• {t('hsm.pkcs11Missing')}</li>}
                  {!hsmStatus.softhsm_found && <li>• {t('hsm.softhsmMissing')}</li>}
                </ul>
                {hsmStatus.install_command && (
                  <code className="block mt-2 px-2 py-1 rounded bg-bg-tertiary font-mono">
                    {hsmStatus.install_command}
                  </code>
                )}
              </div>
            </div>
          )}
          <Input label={t('hsm.pkcs11Config.libraryPath')} value={formData.pkcs11_library_path} onChange={e => handleChange('pkcs11_library_path', e.target.value)} placeholder={t('hsm.pkcs11Config.libraryPathPlaceholder')} />
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.pkcs11Config.slotId')} type="number" value={formData.pkcs11_slot_id} onChange={e => handleChange('pkcs11_slot_id', e.target.value ? parseInt(e.target.value) : '')} />
            <Input label={t('hsm.pkcs11Config.tokenLabel')} value={formData.pkcs11_token_label} onChange={e => handleChange('pkcs11_token_label', e.target.value)} />
          </div>
          <Input label={t('hsm.pkcs11Config.pin')} type="password" noAutofill value={formData.pkcs11_pin === '***' ? '' : (formData.pkcs11_pin || '')} onChange={e => handleChange('pkcs11_pin', e.target.value)} hasExistingValue={provider?.pkcs11_pin === '***'} />
        </div>
      )}

      {formData.provider_type === 'aws-cloudhsm' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.awsConfig.clusterId')} value={formData.aws_cluster_id} onChange={e => handleChange('aws_cluster_id', e.target.value)} />
            <Input label={t('hsm.awsConfig.region')} value={formData.aws_region} onChange={e => handleChange('aws_region', e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.awsConfig.accessKey')} value={formData.aws_access_key} onChange={e => handleChange('aws_access_key', e.target.value)} />
            <Input label={t('hsm.awsConfig.secretKey')} type="password" noAutofill value={formData.aws_secret_key === '***' ? '' : (formData.aws_secret_key || '')} onChange={e => handleChange('aws_secret_key', e.target.value)} hasExistingValue={provider?.aws_secret_key === '***'} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.awsConfig.cryptoUser')} value={formData.aws_crypto_user} onChange={e => handleChange('aws_crypto_user', e.target.value)} />
            <Input label={t('hsm.awsConfig.cryptoPassword')} type="password" noAutofill value={formData.aws_crypto_password === '***' ? '' : (formData.aws_crypto_password || '')} onChange={e => handleChange('aws_crypto_password', e.target.value)} hasExistingValue={provider?.aws_crypto_password === '***'} />
          </div>
        </div>
      )}

      {formData.provider_type === 'azure-keyvault' && (
        <div className="space-y-4">
          <Input label={t('hsm.azureConfig.vaultUrl')} value={formData.azure_vault_url} onChange={e => handleChange('azure_vault_url', e.target.value)} placeholder={t('hsm.azureConfig.vaultUrlPlaceholder')} />
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.azureConfig.tenantId')} value={formData.azure_tenant_id} onChange={e => handleChange('azure_tenant_id', e.target.value)} />
            <Input label={t('common.clientId')} value={formData.azure_client_id} onChange={e => handleChange('azure_client_id', e.target.value)} />
          </div>
          <Input label={t('common.clientSecret')} type="password" noAutofill value={formData.azure_client_secret === '***' ? '' : (formData.azure_client_secret || '')} onChange={e => handleChange('azure_client_secret', e.target.value)} hasExistingValue={provider?.azure_client_secret === '***'} />
        </div>
      )}

      {formData.provider_type === 'google-kms' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.gcpConfig.projectId')} value={formData.gcp_project_id} onChange={e => handleChange('gcp_project_id', e.target.value)} />
            <Input label={t('hsm.gcpConfig.location')} value={formData.gcp_location} onChange={e => handleChange('gcp_location', e.target.value)} />
          </div>
          <Input label={t('hsm.gcpConfig.keyRing')} value={formData.gcp_keyring} onChange={e => handleChange('gcp_keyring', e.target.value)} />
        </div>
      )}

      {formData.provider_type === 'openbao' && (
        <div className="space-y-4">
          <Input label={t('hsm.openbaoConfig.url')} value={formData.openbao_url} onChange={e => handleChange('openbao_url', e.target.value)} placeholder="https://openbao.example.com:8200" required />
          <Input label={t('hsm.openbaoConfig.token')} type="password" noAutofill value={formData.openbao_token === '***' ? '' : (formData.openbao_token || '')} onChange={e => handleChange('openbao_token', e.target.value)} hasExistingValue={provider?.openbao_token === '***'} />
          <div className="grid grid-cols-2 gap-4">
            <Input label={t('hsm.openbaoConfig.mountPath')} value={formData.openbao_mount_path} onChange={e => handleChange('openbao_mount_path', e.target.value)} placeholder="transit" />
            <Input label={t('hsm.openbaoConfig.namespace')} value={formData.openbao_namespace} onChange={e => handleChange('openbao_namespace', e.target.value)} placeholder={t('common.optional')} />
          </div>
          <ToggleSwitch
            checked={formData.openbao_tls_skip_verify}
            onChange={(val) => handleChange('openbao_tls_skip_verify', val)}
            label={t('hsm.openbaoConfig.tlsSkipVerify')}
          />
        </div>
      )}

      {formData.provider_type === 'sc-hsm-cloud' && (
        <div className="space-y-4">
          <p className="text-xs text-text-secondary">{t('hsm.scHsmCloudConfig.hint')}</p>
          <p className="text-xs text-text-secondary">{t('hsm.scHsmCloudConfig.ramUrlHint')}</p>
          <Input
            label={t('hsm.scHsmCloudConfig.tokenLabel')}
            value={formData.sc_token_label}
            onChange={e => handleChange('sc_token_label', e.target.value)}
            placeholder="UCM-Root"
          />
          <Select
            label={t('hsm.scHsmCloudConfig.cardUseLabel')}
            value={formData.device_scheme || 'shares'}
            onChange={value => handleChange('device_scheme', value)}
            options={[
              { value: 'shares', label: t('hsm.scHsmCloudConfig.cardUse.shares') },
              { value: 'none', label: t('hsm.scHsmCloudConfig.cardUse.none') },
              { value: 'random', label: t('hsm.scHsmCloudConfig.cardUse.random') },
              { value: 'domains', label: t('hsm.scHsmCloudConfig.cardUse.domains') },
            ]}
          />
          {(formData.device_scheme || 'shares') === 'shares' && (
            <p className="text-xs text-text-secondary">{t('hsm.scHsmCloudConfig.sharesHint')}</p>
          )}
          {(formData.device_scheme || 'shares') !== 'shares' && (
            <p className="text-xs text-text-secondary">{t('hsm.scHsmCloudConfig.otherHint')}</p>
          )}
          {formData.device_scheme === 'domains' && (
            <Input
              label={t('hsm.scHsmCloudConfig.domainCount')}
              type="number"
              min={1}
              max={16}
              value={formData.key_domains}
              onChange={e => handleChange('key_domains', e.target.value ? parseInt(e.target.value, 10) : 1)}
            />
          )}
          {(formData.device_scheme || 'shares') === 'shares' && (
          <div className="grid grid-cols-2 gap-4">
            <Input
              label={t('hsm.scHsmCloudConfig.thresholdN')}
              type="number"
              min={1}
              value={formData.threshold_n}
              onChange={e => handleChange('threshold_n', e.target.value ? parseInt(e.target.value, 10) : 1)}
              required
            />
            <Input
              label={t('hsm.scHsmCloudConfig.totalM')}
              type="number"
              min={1}
              value={formData.total_m}
              onChange={e => handleChange('total_m', e.target.value ? parseInt(e.target.value, 10) : 1)}
              required
            />
          </div>
          )}
          <div className="space-y-2">
            <p className="text-sm font-medium text-text-primary">
              {(formData.device_scheme || 'shares') === 'shares'
                ? t('hsm.scHsmCloudConfig.custodians')
                : t('hsm.scHsmCloudConfig.cardHolder')}
            </p>
            <p className="text-2xs text-text-tertiary">
              {(formData.device_scheme || 'shares') === 'shares'
                ? t('hsm.scHsmCloudConfig.custodiansHint')
                : t('hsm.scHsmCloudConfig.cardHolderHint')}
            </p>
            {(formData.custodians || []).map((c, index) => (
              <div key={c.share_index || index} className="grid grid-cols-[4rem_1fr] gap-3 items-end">
                <Input
                  label={t('hsm.scHsmCloudConfig.shareIndex')}
                  value={c.share_index}
                  disabled
                  readOnly
                />
                <Select
                  label={t('hsm.scHsmCloudConfig.assignUser')}
                  value={c.user_id === '' || c.user_id == null ? '' : String(c.user_id)}
                  onChange={value => handleCustodianUser(index, value)}
                  options={userOptions}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      <ToggleSwitch
        checked={formData.enabled}
        onChange={(val) => handleChange('enabled', val)}
        label={t('common.enableProvider')}
      />
    </FormModal>
  )
}

function KeyModal({ provider, onSave, onClose }) {
  const { t } = useTranslation()
  const [formData, setFormData] = useState({
    label: '',
    key_type: 'rsa',
    key_size: '2048',
    purpose: 'signing',
    extractable: false,
  })

  const algorithmOptions = {
    rsa: [{ value: '2048', label: 'RSA-2048' }, { value: '3072', label: 'RSA-3072' }, { value: '4096', label: 'RSA-4096' }],
    ec: [{ value: '256', label: 'EC-P256' }, { value: '384', label: 'EC-P384' }, { value: '521', label: 'EC-P521' }],
    aes: [{ value: '128', label: 'AES-128' }, { value: '256', label: 'AES-256' }],
  }

  const buildAlgorithm = () => {
    const prefix = formData.key_type === 'rsa' ? 'RSA' : formData.key_type === 'ec' ? 'EC-P' : 'AES'
    return `${prefix}${formData.key_type === 'ec' ? '' : '-'}${formData.key_size}`
  }

  const handleSubmit = () => {
    onSave({
      label: formData.label,
      algorithm: buildAlgorithm(),
      purpose: formData.purpose,
      extractable: formData.extractable,
    })
  }

  return (
    <FormModal
      open={true}
      onClose={onClose}
      title={t('hsm.generateHsmKey')}
      size="md"
      onSubmit={handleSubmit}
      submitLabel={t('common.generate')}
    >
      <Input label={t('hsm.keyLabel')} value={formData.label} onChange={e => setFormData({...formData, label: e.target.value})} required placeholder={t('hsm.keyLabelPlaceholder')} />
      <div className="grid grid-cols-2 gap-4">
        <Select label={t('common.keyType')} value={formData.key_type} onChange={value => setFormData({...formData, key_type: value, key_size: value === 'rsa' ? '2048' : value === 'ec' ? '256' : '128'})} options={[{ value: 'rsa', label: 'RSA' }, { value: 'ec', label: 'ECDSA' }, { value: 'aes', label: 'AES' }]} />
        <Select
          label={t('common.keySize')}
          value={formData.key_size}
          onChange={value => setFormData({...formData, key_size: value})}
          options={algorithmOptions[formData.key_type] || algorithmOptions.rsa}
        />
      </div>
      <Select label={t('common.purpose')} value={formData.purpose} onChange={value => setFormData({...formData, purpose: value})} options={[{ value: 'signing', label: t('hsm.purposes.caSigning') }, { value: 'encryption', label: t('common.smtpEncryption') }, { value: 'wrapping', label: t('hsm.purposes.general') }, { value: 'all', label: t('common.all') }]} />
    </FormModal>
  )
}
