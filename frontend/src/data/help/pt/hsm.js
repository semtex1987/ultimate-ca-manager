export default {
  helpContent: {
    title: 'Módulos de Segurança de Hardware',
    subtitle: 'Armazenamento externo de chaves',
    overview: 'Integre com Módulos de Segurança de Hardware para armazenamento seguro de chaves privadas. Suporte para PKCS#11, AWS CloudHSM, Azure Key Vault, Google Cloud KMS, OpenBao/Vault Transit e SmartCard-HSM (remoto).',
    sections: [
      {
        title: 'Provedores Suportados',
        definitions: [
          { term: 'PKCS#11', description: 'Interface HSM padrão da indústria (Thales, Entrust, SoftHSM)' },
          { term: 'AWS CloudHSM', description: 'HSM baseado em nuvem da Amazon Web Services' },
          { term: 'Azure Key Vault', description: 'Armazenamento gerenciado de chaves do Microsoft Azure' },
          { term: 'Google KMS', description: 'Google Cloud Key Management Service' },
          { term: 'OpenBao / Vault Transit', description: 'OpenBao ou Vault Transit Secrets Engine para gerenciamento de chaves como serviço' },
          { term: 'SmartCard-HSM (remoto)', description: 'Raiz offline com partilhas DKEK de limiar em tokens USB SmartCard-HSM; ram-client junta-se a uma janela de assinatura via RAMOverHTTP' },
        ]
      },
      {
        title: 'Ações',
        items: [
          { label: 'Adicionar Provedor', text: 'Configurar conexão a um HSM (caminho da biblioteca, credenciais, slot)' },
          { label: 'Testar Conexão', text: 'Verificar se o HSM está acessível e as credenciais são válidas' },
          { label: 'Gerar Chave', text: 'Criar um novo par de chaves diretamente no HSM' },
          { label: 'Status', text: 'Monitorar a saúde da conexão do provedor' },
        ]
      },
      {
        title: 'CAs respaldadas por HSM (v2.130+)',
        content: 'Uma vez configurado um provedor, você pode fixar a chave privada de uma CA a esse HSM no momento da criação:',
        items: [
          { label: 'Toggle Key Storage', text: 'No formulário de criação de CA, escolher Local (criptografado no DB) ou HSM. Selecionar provedor + rótulo de chave' },
          { label: 'Caminho de assinatura', text: 'Cada emissão, assinatura de CRL e assinatura OCSP dessa CA passa pelo HSM, a chave nunca sai' },
          { label: 'Restrições de exportação', text: 'Exportações PKCS#12, JKS e somente-chave são desabilitadas para CAs HSM (só o certificado público / cadeia podem ser exportados)' },
          { label: 'CRL & OCSP', text: 'Ambos funcionam de forma transparente com CAs HSM (assinados via HSM)' },
          { label: 'Migração', text: 'CAs locais existentes não podem ser movidas para um HSM após a criação, escolher na criação' },
        ]
      },

      {
        title: 'Raiz offline SmartCard-HSM',
        content: 'O tipo de fornecedor sc-hsm-cloud protege uma raiz offline com partilhas DKEK n de m em tokens USB. O UCM armazena apenas o blob envolvido e os URL de cerimónia — nunca bytes de partilha.',
        items: [
          { label: 'Limiar n / total m', text: 'Configure quantas partilhas devem ligar-se e quantos custodians têm tokens' },
          { label: 'Atribuição de custodians', text: 'Mapeie cada índice de partilha a um utilizador UCM com contribute:hsm; write:hsm gere a lista' },
          { label: 'Janela de assinatura', text: 'Um operador abre uma janela só para ações de raiz. Os protocolos (ACME, SCEP, EST, WSTEP) continuam recusados enquanto ca.offline estiver definido' },
          { label: 'ram-client', text: 'Cada custodian vê apenas o seu comando de utilização única e o estado: a aguardar, ligado ou contribuído' },
          { label: 'Verificar token', text: 'Lê o estado do domínio de chaves e se existe o ficheiro de partilha CF01. SW=6A82 significa que o cartão respondeu e ainda não tem esse ficheiro' },
          { label: 'Reinicializar dispositivo', text: 'Igual a Initialize device do CardContact. Apaga todas as chaves e ficheiros e define um esquema: partilhas DKEK (use este), DKEK aleatório, sem DKEK ou domínios de chaves. O SO-PIN é o código de inicialização atual. Escreva DELETE. Não escreve partilhas' },
          { label: 'Preparar token', text: 'Apaga o ficheiro de partilha e o domínio num cartão que já tem domínio de partilhas. Escreva DELETE' },
          { label: 'Criar chave de raiz', text: 'Primeira cerimónia. Todos os custodians têm de estar ligados. Gera a chave, escreve uma partilha em cada token e guarda a raiz envolvida. Escreva DELETE' },
          { label: 'Dispositivo de montagem', text: 'Janela seguinte. Lê partilhas que já estão nos tokens. Qualquer limiar de presentes pode montar; o token da vez anterior não tem de estar. n de n não avança se faltar um token' },
          { label: 'CRL antes do apagamento', text: 'O apagamento fica bloqueado até a CRL ser regenerada após a última alteração; o apagamento deve ser confirmado antes de fechar' },
          { label: 'Respondedor OCSP', text: 'Se o respondedor delegado expirar antes da próxima cerimónia, o fecho exige um reconhecimento explícito — não um fecho silencioso' },
        ]
      },

    ],
    tips: [
      'Use SoftHSM para testes antes de implantar com um HSM físico',
      'Chaves geradas em um HSM nunca saem do hardware: elas não podem ser exportadas',
      'Teste a conexão antes de usar um provedor HSM para assinatura de CA',
      'Para CAs raiz de longa duração em produção, prefira o armazenamento de chave respaldado por HSM',
    ],
    warnings: [
      'Configuração incorreta do provedor HSM pode impedir a assinatura de certificados',
      'Perder acesso ao HSM significa perder acesso às chaves armazenadas nele',
    ],
  },
  helpGuides: {
    title: 'Módulos de Segurança de Hardware',
    content: `
## Visão Geral

Módulos de Segurança de Hardware (HSMs) fornecem armazenamento resistente a adulteração para chaves criptográficas. Chaves privadas armazenadas em um HSM nunca saem do hardware, fornecendo o mais alto nível de proteção de chaves.

## Provedores Suportados

### PKCS#11
A interface HSM padrão da indústria. Dispositivos suportados:
- **Thales Luna** / **SafeNet**
- **Entrust nShield**
- **SoftHSM** (baseado em software, para testes)
- Qualquer dispositivo compatível com PKCS#11

> 💡 **Docker**: SoftHSM vem pré-instalado na imagem Docker. Na primeira inicialização, um token padrão é auto-inicializado e registrado como provedor \`SoftHSM-Default\`: pronto para usar imediatamente.

Configuração:
- **Caminho da Biblioteca**: Caminho para a biblioteca compartilhada PKCS#11 (.so/.dll)
- **Slot**: Número do slot HSM
- **PIN**: PIN do usuário para autenticação

### AWS CloudHSM
HSM baseado em nuvem da Amazon Web Services:
- **ID do Cluster**: Identificador do cluster CloudHSM
- **Região**: Região AWS
- **Credenciais**: Chave de acesso e segredo AWS

### Azure Key Vault
Armazenamento gerenciado de chaves do Microsoft Azure:
- **URL do Vault**: Endpoint do Azure Key Vault
- **ID do Tenant**: Tenant do Azure AD
- **ID/Segredo do Cliente**: Credenciais do service principal

### Google Cloud KMS
Google Cloud Key Management Service:
- **Projeto**: ID do projeto GCP
- **Localização**: Localização do key ring KMS
- **Key Ring**: Nome do key ring
- **Credenciais**: Chave JSON da conta de serviço

### OpenBao / Vault Transit
OpenBao ou HashiCorp Vault Transit Secrets Engine. As chaves são gerenciadas remotamente via API Transit: nenhuma biblioteca PKCS#11 necessária.

Configuração:
- **URL**: Endereço do servidor (ex. \`https://openbao.example.com:8200\`)
- **Token**: Token de autenticação
- **Caminho de montagem**: Ponto de montagem do motor Transit (padrão: \`transit\`)
- **Namespace**: Namespace opcional para configurações multi-tenant
- **Ignorar verificação TLS**: Ignorar verificação de certificado TLS (para certificados autoassinados)

Tipos de chave suportados:
- RSA 2048, 3072, 4096
- ECDSA P-256, P-384, P-521
- AES-256-GCM (simétrico)

> 💡 OpenBao é um fork comunitário do HashiCorp Vault. O UCM funciona com ambos.

## Gerenciando Provedores

### Adicionando um Provedor
1. Clique em **Adicionar Provedor**
2. Selecione o **tipo de provedor**
3. Insira os detalhes de conexão
4. Clique em **Testar Conexão** para verificar
5. Clique em **Salvar**

### Testando Conexão
Sempre teste a conexão após criar ou modificar um provedor. O UCM verifica se pode se comunicar com o HSM e autenticar.

### Status do Provedor
Cada provedor mostra um indicador de status de conexão:
- **Conectado**: HSM está acessível e autenticado
- **Desconectado**: Não é possível alcançar o HSM
- **Erro**: Problema de autenticação ou configuração

## Gerenciamento de Chaves

### Gerando Chaves
1. Selecione um provedor conectado
2. Clique em **Gerar Chave**
3. Escolha o algoritmo (RSA 2048/4096, ECDSA P-256/P-384)
4. Insira um rótulo/alias para a chave
5. Clique em **Gerar**

A chave é criada diretamente no HSM. O UCM armazena apenas uma referência.

### Usando Chaves HSM
Ao criar uma CA, selecione um provedor HSM e uma chave em vez de gerar uma chave de software. As operações de assinatura da CA são realizadas no HSM.

> ⚠ Chaves geradas em um HSM não podem ser exportadas. Se você perder acesso ao HSM, você perde as chaves.

> 💡 Use SoftHSM para desenvolvimento e testes antes de implantar com HSMs físicos.

### SmartCard-HSM (remoto)
Raiz offline com tokens USB SmartCard-HSM (\`sc-hsm-cloud\`). Distinto do AWS CloudHSM.

- **Limiar n / total m**: Quantas partilhas devem ligar-se e quantos custodians têm tokens
- **Custodians**: Cada índice de partilha mapeia para um utilizador UCM (\`contribute:hsm\` junta-se; \`write:hsm\` gere a lista)
- **Janela de assinatura**: O operador abre uma janela para ações de raiz. Os protocolos continuam recusados; \`ca.offline\` permanece
- **ram-client**: Cada custodian executa um comando de utilização única mostrado só a si; estado a aguardar, ligado ou contribuído
- **Pronto**: Inicializado para partilhas DKEK, domínio vazio, sem ficheiro \`CF01\`. **Verificar token** lê isto. \`SW=6A82\` significa que o ficheiro de partilha ainda não existe
- **Reinicializar dispositivo**: Igual a Initialize device do CardContact. Apaga chaves e ficheiros e define um esquema (para o UCM: partilhas DKEK). O SO-PIN é o código atual. Escreva \`DELETE\`. \`SW=6982\` SO-PIN errado; \`SW=6A80\` dados recusados; \`SW=6D00\` sem domínio de partilhas
- **Criar chave de raiz**: Primeira cerimónia, os \`m\` tokens ligados. Escreve a primeira partilha. **Dispositivo de montagem** só lê partilhas já presentes. Na janela seguinte qualquer limiar presente chega; n de n exige todos
- **Dispositivo de montagem**: Um token ligado reconstrói a chave de raiz; o UCM nunca vê a chave em claro nem bytes de partilha
- **CRL antes do apagamento**: O apagamento fica bloqueado até regenerar a CRL; deve ser confirmado antes de fechar
- **Aviso OCSP**: Se o respondedor delegado expirar antes da próxima cerimónia, o fecho exige reconhecimento explícito
`
  }
}
