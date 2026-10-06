/**
 * HSM Service
 */
import { apiClient, buildQueryString } from './apiClient'

export const hsmService = {
  async getProviders() {
    return apiClient.get('/hsm/providers')
  },

  async getProvider(id) {
    return apiClient.get(`/hsm/providers/${id}`)
  },

  async getStatus() {
    return apiClient.get('/system/hsm-status')
  },

  async getKeys(providerId) {
    return apiClient.get(`/hsm/keys?provider_id=${providerId}`)
  },

  async getSigningKeys({ providerId = null, unused = true } = {}) {
    const params = {}
    if (providerId) params.provider_id = providerId
    if (unused) params.unused = true
    return apiClient.get(`/hsm/keys${buildQueryString(params)}`)
  },

  async deleteProvider(id) {
    return apiClient.delete(`/hsm/providers/${id}`)
  },

  async testProvider(id) {
    return apiClient.post(`/hsm/providers/${id}/test`)
  },

  async createProvider(data) {
    return apiClient.post('/hsm/providers', data)
  },

  async updateProvider(id, data) {
    return apiClient.put(`/hsm/providers/${id}`, data)
  },

  async addKey(providerId, keyData) {
    return apiClient.post(`/hsm/providers/${providerId}/keys`, keyData)
  },

  async deleteKey(id) {
    return apiClient.delete(`/hsm/keys/${id}`)
  },

  async installDependencies() {
    return apiClient.post('/hsm/dependencies/install')
  },

  /** Open an offline-root signing window for SmartCard-HSM (sc-hsm-cloud). */
  async beginCeremony(providerId) {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/begin`)
  },

  /** Read key-domain and share-file status for one connected token. */
  async inspectToken(providerId, custodianId) {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/tokens/${custodianId}/inspect`)
  },

  /**
   * Initialize a blank token, wipe a DKEK and share file, or reinitialize a
   * card that is already in use. `confirm` must be the string DELETE.
   * PINs stay in this request only.
   */
  async prepareToken(providerId, custodianId, {
    confirm,
    so_pin = '',
    user_pin = '',
    reinitialize = false,
  } = {}) {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/tokens/${custodianId}/prepare`, {
      confirm,
      so_pin,
      user_pin,
      reinitialize,
    })
  },

  /** Choose which connected custodian token is the assembly device. */
  async setAssemblySlot(providerId, shareIndex, userPin = '') {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/assembly-slot`, {
      share_index: shareIndex,
      user_pin: userPin,
    })
  },

  /**
   * Acknowledge that the delegated OCSP responder expires before the next
   * planned ceremony. Required before wipe when ocsp_responder_warning is set.
   */
  async acknowledgeOcspWarning(providerId) {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/acknowledge-ocsp`)
  },

  /**
   * Wipe the rebuilt root key from the assembly token. Backend refuses when
   * crl_stale is true (CRL must be regenerated after the latest change first).
   */
  async wipeAssembly(providerId) {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/wipe`)
  },

  /**
   * First root key for this scheme. Writes a share onto every connected token
   * and generates the key on the chosen assembly token. `confirm` must be DELETE.
   */
  async createRootKey(providerId, shareIndex, userPin = '') {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/create-key`, {
      share_index: shareIndex,
      confirm: 'DELETE',
      user_pin: userPin,
    })
  },

  /** Generate a new root key on the assembly token and hand new shares to custodians. */
  async rollRootKey(providerId, userPin = '') {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/roll-key`, {
      user_pin: userPin,
    })
  },

  /** Drop all RAM sessions and close the signing window. */
  async endCeremony(providerId) {
    return apiClient.post(`/hsm/providers/${providerId}/ceremony/end`)
  },
}
