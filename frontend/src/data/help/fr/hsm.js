export default {
  helpContent: {
    title: 'Modules de sécurité matériels',
    subtitle: 'Stockage de clés externe',
    overview: 'Intégrez des modules de sécurité matériels pour le stockage sécurisé des clés privées. Prend en charge PKCS#11, AWS CloudHSM, Azure Key Vault, Google Cloud KMS, OpenBao/Vault Transit et SmartCard-HSM (distant).',
    sections: [
      {
        title: 'Fournisseurs pris en charge',
        definitions: [
          { term: 'PKCS#11', description: 'Interface HSM standard de l\'industrie (Thales, Entrust, SoftHSM)' },
          { term: 'AWS CloudHSM', description: 'HSM basé sur le cloud Amazon Web Services' },
          { term: 'Azure Key Vault', description: 'Stockage de clés géré Microsoft Azure' },
          { term: 'Google KMS', description: 'Service de gestion des clés Google Cloud' },
          { term: 'OpenBao / Vault Transit', description: 'Moteur de secrets Transit OpenBao ou HashiCorp Vault pour la gestion de clés en chiffrement-as-a-service' },
          { term: 'SmartCard-HSM (distant)', description: 'Racine hors ligne avec parts DKEK à seuil sur jetons USB SmartCard-HSM ; ram-client rejoint une fenêtre de signature via RAMOverHTTP' },
        ]
      },
      {
        title: 'Actions',
        items: [
          { label: 'Ajouter un fournisseur', text: 'Configurer la connexion à un HSM (chemin de bibliothèque, identifiants, slot)' },
          { label: 'Tester la connexion', text: 'Vérifier que le HSM est joignable et que les identifiants sont valides' },
          { label: 'Générer une clé', text: 'Créer une nouvelle paire de clés directement sur le HSM' },
          { label: 'Statut', text: 'Surveiller la santé de la connexion du fournisseur' },
        ]
      },
      {
        title: 'CA adossées à HSM (v2.130+)',
        content: 'Une fois un fournisseur HSM configuré, vous pouvez épingler la clé privée d\'une CA à ce HSM dès sa création :',
        items: [
          { label: 'Bascule Stockage de clé', text: 'Sur le formulaire de création de CA, choisir Local (chiffré en DB) ou HSM. Sélectionner le fournisseur + label de clé' },
          { label: 'Chemin de signature', text: 'Chaque émission, signature de CRL et signature OCSP de cette CA passe par le HSM, la clé ne sort jamais' },
          { label: 'Restrictions d\'export', text: 'L\'export PKCS#12, JKS et clé seule est désactivé pour les CA HSM (seul le certificat public / la chaîne peut être exporté)' },
          { label: 'CRL & OCSP', text: 'Les deux fonctionnent de manière transparente avec les CA HSM (signés via HSM)' },
          { label: 'Migration', text: 'Les CA locales existantes ne peuvent pas être déplacées vers un HSM après création, choisir à la création' },
        ]
      },

      {
        title: 'Racine hors ligne SmartCard-HSM',
        content: 'Le type de fournisseur sc-hsm-cloud sécurise une racine hors ligne avec des parts DKEK n sur m sur jetons USB. UCM ne stocke que le blob enveloppé et les URL de cérémonie — jamais les octets de part.',
        items: [
          { label: 'Seuil n / total m', text: 'Configurer combien de parts doivent se connecter et combien de dépositaires détiennent des jetons' },
          { label: 'Affectation des dépositaires', text: 'Associer chaque index de part à un utilisateur UCM avec contribute:hsm ; write:hsm gère la liste' },
          { label: 'Fenêtre de signature', text: 'Un opérateur ouvre une fenêtre pour les actions racine uniquement. Les protocoles (ACME, SCEP, EST, WSTEP) restent refusés tant que ca.offline est défini' },
          { label: 'ram-client', text: 'Chaque dépositaire ne voit que sa propre commande ponctuelle et le statut : en attente, connecté ou contribué' },
          { label: 'Vérifier le jeton', text: 'Lit l’état du domaine de clés et la présence du fichier de part CF01. SW=6A82 signifie que la carte a répondu et n’a pas encore ce fichier' },
          { label: 'Réinitialiser l’appareil', text: 'Identique à Initialize device de CardContact. Efface toutes les clés et fichiers et fixe un schéma : parts DKEK (à utiliser ici), DKEK aléatoire, pas de DKEK, ou domaines de clés. Le SO-PIN est le code d’initialisation actuel. Saisir DELETE. N’écrit pas de parts' },
          { label: 'Préparer le jeton', text: 'Supprime le fichier de part et le domaine sur une carte qui a déjà un domaine de parts. Saisir DELETE' },
          { label: 'Créer la clé racine', text: 'Première cérémonie. Tous les dépositaires doivent être connectés. Génère la clé, écrit une part sur chaque jeton et stocke la racine enveloppée. Saisir DELETE' },
          { label: "Appareil d'assemblage", text: 'Fenêtre suivante. Lit les parts déjà présentes. Tout seuil de détenteurs présents peut assembler ; le jeton utilisé la fois précédente n’est pas obligatoire. n sur n est bloqué si un jeton manque' },
          { label: "CRL avant effacement", text: "L'effacement est bloqué jusqu'à la régénération de la CRL après le dernier changement ; l'effacement doit être confirmé avant la fermeture" },
          { label: 'Répondeur OCSP', text: "Si le répondeur délégué expire avant la prochaine cérémonie, la fermeture exige un accusé de réception explicite — pas une fermeture silencieuse" },
        ]
      },

    ],
    tips: [
      'Utilisez SoftHSM pour les tests avant de déployer avec un HSM physique',
      'Les clés générées sur un HSM ne quittent jamais le matériel : elles ne peuvent pas être exportées',
      'Testez la connexion avant d\'utiliser un fournisseur HSM pour la signature de CA',
      'Pour les CA racines à longue durée de vie en production, préférez le stockage de clé adossé à HSM',
    ],
    warnings: [
      'Une mauvaise configuration du fournisseur HSM peut empêcher la signature de certificats',
      'Perdre l\'accès au HSM signifie perdre l\'accès aux clés qui y sont stockées',
    ],
  },
  helpGuides: {
    title: 'Modules de sécurité matériels',
    content: `
## Vue d'ensemble

Les modules de sécurité matériels (HSM) fournissent un stockage inviolable pour les clés cryptographiques. Les clés privées stockées sur un HSM ne quittent jamais le matériel, offrant le plus haut niveau de protection des clés.

## Fournisseurs pris en charge

### PKCS#11
L'interface HSM standard de l'industrie. Appareils pris en charge :
- **Thales Luna** / **SafeNet**
- **Entrust nShield**
- **SoftHSM** (logiciel, pour les tests)
- Tout appareil compatible PKCS#11

> 💡 **Docker** : SoftHSM est pré-installé dans l'image Docker. Au premier démarrage, un jeton par défaut est auto-initialisé et enregistré comme fournisseur \`SoftHSM-Default\` : prêt à l'emploi immédiatement.

Configuration :
- **Chemin de la bibliothèque** : Chemin vers la bibliothèque partagée PKCS#11 (.so/.dll)
- **Slot** : Numéro de slot HSM
- **PIN** : PIN utilisateur pour l'authentification

### AWS CloudHSM
HSM basé sur le cloud Amazon Web Services :
- **ID du cluster** : Identifiant du cluster CloudHSM
- **Région** : Région AWS
- **Identifiants** : Clé d'accès et secret AWS

### Azure Key Vault
Stockage de clés géré Microsoft Azure :
- **URL du coffre** : Point de terminaison Azure Key Vault
- **ID du locataire** : Locataire Azure AD
- **ID client/Secret** : Identifiants du principal de service

### Google Cloud KMS
Service de gestion des clés Google Cloud :
- **Projet** : ID du projet GCP
- **Emplacement** : Emplacement de l'anneau de clés KMS
- **Anneau de clés** : Nom de l'anneau de clés
- **Identifiants** : Clé JSON du compte de service

### OpenBao / Vault Transit
Moteur de secrets Transit OpenBao ou HashiCorp Vault. Les clés sont gérées à distance via l'API Transit : aucune bibliothèque PKCS#11 requise.

Configuration :
- **URL** : Adresse du serveur (ex. \`https://openbao.example.com:8200\`)
- **Token** : Jeton d'authentification
- **Chemin de montage** : Point de montage du moteur Transit (par défaut : \`transit\`)
- **Espace de noms** : Espace de noms optionnel pour les configurations multi-locataires
- **Ignorer la vérification TLS** : Ignorer la vérification du certificat TLS (pour les certificats auto-signés)

Types de clés pris en charge :
- RSA 2048, 3072, 4096
- ECDSA P-256, P-384, P-521
- AES-256-GCM (symétrique)

> 💡 OpenBao est un fork communautaire de HashiCorp Vault. UCM fonctionne avec les deux.

> 💡 Pour le développement, lancez OpenBao en mode dev : \`docker run -d -p 8200:8200 -e BAO_DEV_ROOT_TOKEN_ID=test-token quay.io/openbao/openbao:latest server -dev\`


### SmartCard-HSM (distant)
Racine hors ligne adossée à des jetons USB SmartCard-HSM (\`sc-hsm-cloud\`). Distinct d'AWS CloudHSM.

- **Seuil n / total m** : Combien de parts doivent se connecter et combien de dépositaires détiennent des jetons
- **Dépositaires** : Chaque index de part est associé à un utilisateur UCM (\`contribute:hsm\` rejoint ; \`write:hsm\` gère la liste)
- **Fenêtre de signature** : L'opérateur ouvre une fenêtre pour les actions racine. Les protocoles restent refusés ; \`ca.offline\` reste défini
- **ram-client** : Chaque dépositaire exécute une commande ponctuelle qui lui est montrée uniquement ; statut en attente, connecté ou contribué
- **Prêt** : Initialisé pour des parts DKEK, domaine vide, pas de fichier \`CF01\`. **Vérifier le jeton** le lit. \`SW=6A82\` signifie que le fichier de part n’est pas encore là
- **Réinitialiser l’appareil** : Identique à Initialize device de CardContact. Efface clés et fichiers et fixe un schéma (pour UCM : parts DKEK). Le SO-PIN est le code actuel. Saisir \`DELETE\`. \`SW=6982\` : SO-PIN incorrect. \`SW=6A80\` : données refusées. \`SW=6D00\` : pas de domaine de parts
- **Créer la clé racine** : Première cérémonie, les \`m\` jetons connectés. Écrit la première part. **Appareil d’assemblage** ne lit que des parts déjà présentes. À la fenêtre suivante, tout seuil présent suffit ; n sur n exige tous les jetons
- **Appareil d'assemblage** : Un jeton connecté reconstruit la clé racine ; UCM ne voit jamais la clé en clair ni les octets de part
- **CRL avant effacement** : L'effacement est bloqué jusqu'à régénération de la CRL ; doit être confirmé avant fermeture
- **Avertissement OCSP** : Si le répondeur délégué expire avant la prochaine cérémonie, la fermeture exige un accusé de réception explicite

## Gérer les fournisseurs

### Ajouter un fournisseur
1. Cliquez sur **Ajouter un fournisseur**
2. Sélectionnez le **type de fournisseur**
3. Entrez les détails de connexion
4. Cliquez sur **Tester la connexion** pour vérifier
5. Cliquez sur **Enregistrer**

### Tester la connexion
Testez toujours la connexion après avoir créé ou modifié un fournisseur. UCM vérifie qu'il peut communiquer avec le HSM et s'authentifier.

### Statut du fournisseur
Chaque fournisseur affiche un indicateur de statut de connexion :
- **Connecté** : Le HSM est accessible et authentifié
- **Déconnecté** : Impossible de joindre le HSM
- **Erreur** : Problème d'authentification ou de configuration

## Gestion des clés

### Générer des clés
1. Sélectionnez un fournisseur connecté
2. Cliquez sur **Générer une clé**
3. Choisissez l'algorithme (RSA 2048/4096, ECDSA P-256/P-384)
4. Entrez un label/alias pour la clé
5. Cliquez sur **Générer**

La clé est créée directement sur le HSM. UCM ne stocke qu'une référence.

### Utiliser les clés HSM
Lors de la création d'une CA, sélectionnez un fournisseur HSM et une clé au lieu de générer une clé logicielle. Les opérations de signature de la CA sont effectuées sur le HSM.

> ⚠ Les clés générées sur un HSM ne peuvent pas être exportées. Si vous perdez l'accès au HSM, vous perdez les clés.

> 💡 Utilisez SoftHSM pour le développement et les tests avant le déploiement avec des HSM physiques.
`
  }
}
