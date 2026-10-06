export default {
  helpContent: {
    title: 'Hardware-Sicherheitsmodule',
    subtitle: 'Externe Schlüsselspeicherung',
    overview: 'Integration mit Hardware-Sicherheitsmodulen für sichere Speicherung privater Schlüssel. Unterstützung für PKCS#11, AWS CloudHSM, Azure Key Vault, Google Cloud KMS, OpenBao/Vault Transit und SmartCard-HSM (remote).',
    sections: [
      {
        title: 'Unterstützte Anbieter',
        definitions: [
          { term: 'PKCS#11', description: 'Industriestandard-HSM-Schnittstelle (Thales, Entrust, SoftHSM)' },
          { term: 'AWS CloudHSM', description: 'Amazon Web Services Cloud-basiertes HSM' },
          { term: 'Azure Key Vault', description: 'Microsoft Azure verwalteter Schlüsselspeicher' },
          { term: 'Google KMS', description: 'Google Cloud Key Management Service' },
          { term: 'OpenBao / Vault Transit', description: 'OpenBao- oder Vault-Transit-Secrets-Engine für Schlüsselverwaltung als Dienst' },
          { term: 'SmartCard-HSM (remote)', description: 'Offline-Root mit Schwellenwert-DKEK-Shares auf USB-SmartCard-HSM-Tokens; ram-client tritt über RAMOverHTTP einem Signaturfenster bei' },
        ]
      },
      {
        title: 'Aktionen',
        items: [
          { label: 'Anbieter hinzufügen', text: 'Verbindung zu einem HSM konfigurieren (Bibliothekspfad, Anmeldedaten, Slot)' },
          { label: 'Verbindung testen', text: 'Überprüfen, ob das HSM erreichbar ist und die Anmeldedaten gültig sind' },
          { label: 'Schlüssel generieren', text: 'Ein neues Schlüsselpaar direkt auf dem HSM erstellen' },
          { label: 'Status', text: 'Verbindungszustand des Anbieters überwachen' },
        ]
      },
      {
        title: 'HSM-gestützte CAs (v2.130+)',
        content: 'Sobald ein Provider konfiguriert ist, können Sie den privaten Schlüssel einer CA bei der Erstellung an diesen HSM binden:',
        items: [
          { label: 'Key-Storage-Toggle', text: 'Im CA-Erstellungsformular Local (in DB verschlüsselt) oder HSM wählen. Provider + Key-Label auswählen' },
          { label: 'Signaturpfad', text: 'Jede Ausstellung, CRL- und OCSP-Signatur dieser CA läuft über den HSM, der Schlüssel verlässt ihn nie' },
          { label: 'Export-Einschränkungen', text: 'PKCS#12-, JKS- und Key-only-Exporte sind für HSM-CAs deaktiviert (nur das öffentliche Zertifikat / die Chain können exportiert werden)' },
          { label: 'CRL & OCSP', text: 'Beide funktionieren transparent mit HSM-CAs (signiert via HSM)' },
          { label: 'Migration', text: 'Bestehende lokale CAs können nach der Erstellung nicht in einen HSM verschoben werden, bei der Erstellung wählen' },
        ]
      },

      {
        title: 'SmartCard-HSM Offline-Root',
        content: 'Anbietertyp sc-hsm-cloud sichert einen Offline-Root mit n-von-m DKEK-Shares auf USB-Tokens. UCM speichert nur den gewrappten Root-Blob und Zeremonie-URLs — niemals Share-Bytes.',
        items: [
          { label: 'Schwelle n / gesamt m', text: 'Konfigurieren, wie viele Shares verbunden sein müssen und wie viele Verwahrer Tokens halten' },
          { label: 'Schlüsselverwahrer-Zuweisung', text: 'Jeden Share-Index einem UCM-Benutzer mit contribute:hsm zuordnen; write:hsm verwaltet die Liste' },
          { label: 'Signaturfenster', text: 'Ein Operator öffnet ein Fenster nur für Root-Aktionen. Protokolle (ACME, SCEP, EST, WSTEP) bleiben verweigert, solange ca.offline gesetzt ist' },
          { label: 'ram-client', text: 'Jeder Verwahrer sieht nur seinen eigenen Einmal-Befehl und den Status: wartend, verbunden oder beigetragen' },
          { label: 'Token prüfen', text: 'Liest den Key-Domain-Status und ob die Share-Datei CF01 existiert. SW=6A82 heißt: die Karte hat geantwortet und hat noch keine Share-Datei' },
          { label: 'Gerät neu initialisieren', text: 'Wie „Initialize device“ in der CardContact-Shell. Löscht alle Schlüssel und Dateien und setzt genau ein Schema: DKEK-Shares (für diese Zeremonie), zufälliges DKEK, kein DKEK oder Key-Domains. Die SO-PIN ist der aktuelle Initialisierungscode. DELETE eingeben. Schreibt keine Shares' },
          { label: 'Token vorbereiten', text: 'Löscht Share-Datei und Key Domain auf einer Karte, die bereits eine Key-Share-Domain hat. DELETE eingeben' },
          { label: 'Root-Schlüssel erzeugen', text: 'Erste Zeremonie. Alle Verwahrer müssen verbunden sein. Erzeugt den Schlüssel, schreibt auf jeden Token eine Share und speichert den gewrappten Root. DELETE eingeben' },
          { label: 'Assembly-Gerät', text: 'Späteres Fenster. Liest vorhandene Share-Dateien. Jede Schwelle anwesender Share-Inhaber kann aufbauen; der letzte Assembly-Token muss nicht da sein. Bei n-von-n blockiert ein fehlender Token' },
          { label: 'CRL vor Wipe', text: 'Wipe ist blockiert, bis die CRL nach der letzten Änderung regeneriert wurde; Wipe muss vor dem Schließen bestätigt werden' },
          { label: 'OCSP-Responder', text: 'Läuft der delegierte Responder vor der nächsten Zeremonie ab, erfordert das Schließen eine ausdrückliche Bestätigung — kein stilles Schließen' },
        ]
      },

    ],
    tips: [
      'Verwenden Sie SoftHSM zum Testen, bevor Sie mit einem physischen HSM bereitstellen',
      'Auf einem HSM generierte Schlüssel verlassen niemals die Hardware: sie können nicht exportiert werden',
      'Testen Sie die Verbindung, bevor Sie einen HSM-Anbieter für die CA-Signierung verwenden',
      'Für langlebige Root-CAs in Produktion HSM-gestützte Schlüsselablage bevorzugen',
    ],
    warnings: [
      'Falsche HSM-Anbieter-Konfiguration kann die Zertifikatssignierung verhindern',
      'Der Verlust des Zugangs zum HSM bedeutet den Verlust der dort gespeicherten Schlüssel',
    ],
  },
  helpGuides: {
    title: 'Hardware-Sicherheitsmodule',
    content: `
## Übersicht

Hardware-Sicherheitsmodule (HSMs) bieten manipulationssichere Speicherung für kryptografische Schlüssel. Private Schlüssel, die auf einem HSM gespeichert sind, verlassen niemals die Hardware und bieten so das höchste Maß an Schlüsselschutz.

## Unterstützte Anbieter

### PKCS#11
Die Industriestandard-HSM-Schnittstelle. Unterstützte Geräte:
- **Thales Luna** / **SafeNet**
- **Entrust nShield**
- **SoftHSM** (softwarebasiert, zum Testen)
- Jedes PKCS#11-kompatible Gerät

> 💡 **Docker**: SoftHSM ist im Docker-Image vorinstalliert. Beim ersten Start wird automatisch ein Standard-Token initialisiert und als \`SoftHSM-Default\`-Anbieter registriert, sofort einsatzbereit.

Konfiguration:
- **Bibliothekspfad**: Pfad zur PKCS#11-Shared-Library (.so/.dll)
- **Slot**: HSM-Slotnummer
- **PIN**: Benutzer-PIN zur Authentifizierung

### AWS CloudHSM
Amazon Web Services Cloud-basiertes HSM:
- **Cluster-ID**: CloudHSM-Cluster-Kennung
- **Region**: AWS-Region
- **Anmeldedaten**: AWS-Zugriffsschlüssel und -Geheimnis

### Azure Key Vault
Microsoft Azure verwalteter Schlüsselspeicher:
- **Vault-URL**: Azure Key Vault-Endpunkt
- **Mandanten-ID**: Azure AD-Mandant
- **Client-ID/Geheimnis**: Dienstprinzipal-Anmeldedaten

### Google Cloud KMS
Google Cloud Key Management Service:
- **Projekt**: GCP-Projekt-ID
- **Standort**: KMS-Schlüsselring-Standort
- **Schlüsselring**: Name des Schlüsselrings
- **Anmeldedaten**: Dienstkonto-JSON-Schlüssel

### OpenBao / Vault Transit
OpenBao- oder HashiCorp Vault Transit Secrets Engine. Schlüssel werden remote über die Transit-API verwaltet: keine PKCS#11-Bibliothek erforderlich.

Konfiguration:
- **URL**: Serveradresse (z.B. \`https://openbao.example.com:8200\`)
- **Token**: Authentifizierungstoken
- **Mount-Pfad**: Transit-Engine-Mountpoint (Standard: \`transit\`)
- **Namespace**: Optionaler Namespace für Multi-Tenant-Setups
- **TLS-Überprüfung überspringen**: TLS-Zertifikatsprüfung überspringen (für selbstsignierte Zertifikate)

Unterstützte Schlüsseltypen:
- RSA 2048, 3072, 4096
- ECDSA P-256, P-384, P-521
- AES-256-GCM (symmetrisch)

> 💡 OpenBao ist ein Community-Fork von HashiCorp Vault. UCM funktioniert mit beiden.


### SmartCard-HSM (remote)
Offline-Root mit USB-SmartCard-HSM-Tokens (\`sc-hsm-cloud\`). Unterschiedlich von AWS CloudHSM.

- **Schwelle n / gesamt m**: Wie viele Shares verbunden sein müssen und wie viele Verwahrer Tokens halten
- **Schlüsselverwahrer**: Jeder Share-Index gehört zu einem UCM-Benutzer (\`contribute:hsm\` tritt bei; \`write:hsm\` verwaltet die Liste)
- **Signaturfenster**: Operator öffnet ein Fenster für Root-Aktionen (CRL, Widerruf, untergeordnete CA, OCSP-Responder, Root-Rekey). Protokolle bleiben verweigert; \`ca.offline\` bleibt gesetzt
- **ram-client**: Jeder Verwahrer führt einen nur ihm gezeigten Einmal-Befehl aus; Status wartend, verbunden oder beigetragen. ram-client nicht als Dauer-Dienst betreiben
- **Bereit**: Für DKEK-Shares initialisiert, leere Key Domain, keine Datei \`CF01\`. **Token prüfen** liest das. \`SW=6A82\` heißt, die Share-Datei fehlt noch
- **Gerät neu initialisieren**: Wie CardContact „Initialize device“. Löscht alle Schlüssel und Dateien und setzt ein Schema (für UCM: DKEK-Shares). SO-PIN ist der aktuelle Initialisierungscode. \`DELETE\` eingeben. \`SW=6982\` ist die falsche SO-PIN, \`SW=6A80\` abgelehnte Initialisierungsdaten, \`SW=6D00\` heißt: keine Key-Share-Domain
- **Root-Schlüssel erzeugen**: Erste Zeremonie, alle \`m\` Tokens verbunden. Schreibt die erste Share. **Assembly-Gerät** liest nur Shares, die schon auf den Tokens liegen. Beim nächsten Fenster kann jede anwesende Schwelle aufbauen; n-von-n braucht jeden Token
- **Assembly-Gerät**: Ein verbundener Token baut den Root-Schlüssel für das Fenster neu auf; UCM sieht weder Klartext-Schlüssel noch Share-Bytes
- **CRL vor Wipe**: Wipe ist blockiert, bis die CRL nach der letzten Änderung regeneriert wurde; Wipe muss vor dem Schließen bestätigt werden
- **OCSP-Warnung**: Läuft der delegierte Responder vor der nächsten Zeremonie ab, erfordert das Schließen eine ausdrückliche Bestätigung

## Anbieter verwalten

### Anbieter hinzufügen
1. Klicken Sie auf **Anbieter hinzufügen**
2. Wählen Sie den **Anbietertyp**
3. Geben Sie die Verbindungsdetails ein
4. Klicken Sie auf **Verbindung testen** zur Überprüfung
5. Klicken Sie auf **Speichern**

### Verbindung testen
Testen Sie die Verbindung immer nach dem Erstellen oder Ändern eines Anbieters. UCM überprüft, ob es mit dem HSM kommunizieren und sich authentifizieren kann.

### Anbieterstatus
Jeder Anbieter zeigt einen Verbindungsstatusindikator:
- **Verbunden**: HSM ist erreichbar und authentifiziert
- **Getrennt**: HSM nicht erreichbar
- **Fehler**: Authentifizierungs- oder Konfigurationsproblem

## Schlüsselverwaltung

### Schlüssel generieren
1. Wählen Sie einen verbundenen Anbieter
2. Klicken Sie auf **Schlüssel generieren**
3. Wählen Sie den Algorithmus (RSA 2048/4096, ECDSA P-256/P-384)
4. Geben Sie ein Schlüssel-Label/Alias ein
5. Klicken Sie auf **Generieren**

Der Schlüssel wird direkt auf dem HSM erstellt. UCM speichert nur eine Referenz.

### HSM-Schlüssel verwenden
Wählen Sie beim Erstellen einer CA einen HSM-Anbieter und -Schlüssel anstatt einen Software-Schlüssel zu generieren. Die Signierungsvorgänge der CA werden auf dem HSM ausgeführt.

> ⚠ Auf einem HSM generierte Schlüssel können nicht exportiert werden. Wenn Sie den Zugang zum HSM verlieren, verlieren Sie die Schlüssel.

> 💡 Verwenden Sie SoftHSM für Entwicklung und Tests, bevor Sie mit physischen HSMs bereitstellen.
`
  }
}
