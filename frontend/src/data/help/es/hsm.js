export default {
  helpContent: {
    title: 'Módulos de Seguridad de Hardware',
    subtitle: 'Almacenamiento externo de claves',
    overview: 'Integre con Módulos de Seguridad de Hardware para el almacenamiento seguro de claves privadas. Soporte para PKCS#11, AWS CloudHSM, Azure Key Vault, Google Cloud KMS, OpenBao/Vault Transit y SmartCard-HSM (remoto).',
    sections: [
      {
        title: 'Proveedores compatibles',
        definitions: [
          { term: 'PKCS#11', description: 'Interfaz HSM estándar de la industria (Thales, Entrust, SoftHSM)' },
          { term: 'AWS CloudHSM', description: 'HSM basado en la nube de Amazon Web Services' },
          { term: 'Azure Key Vault', description: 'Almacenamiento de claves gestionado de Microsoft Azure' },
          { term: 'Google KMS', description: 'Servicio de gestión de claves de Google Cloud' },
          { term: 'OpenBao / Vault Transit', description: 'Motor de secretos Transit de OpenBao o Vault para gestión de claves como servicio' },
          { term: 'SmartCard-HSM (remoto)', description: 'Raíz sin conexión con participaciones DKEK de umbral en tokens USB SmartCard-HSM; ram-client se une a una ventana de firma por RAMOverHTTP' },
        ]
      },
      {
        title: 'Acciones',
        items: [
          { label: 'Agregar proveedor', text: 'Configurar la conexión a un HSM (ruta de biblioteca, credenciales, slot)' },
          { label: 'Probar conexión', text: 'Verificar que el HSM es accesible y las credenciales son válidas' },
          { label: 'Generar clave', text: 'Crear un nuevo par de claves directamente en el HSM' },
          { label: 'Estado', text: 'Monitorear el estado de conexión del proveedor' },
        ]
      },
      {
        title: 'CA respaldadas por HSM (v2.130+)',
        content: 'Una vez configurado un proveedor, puede fijar la clave privada de una CA a ese HSM en el momento de creación:',
        items: [
          { label: 'Conmutador Key Storage', text: 'En el formulario de creación de CA, elegir Local (cifrado en DB) o HSM. Seleccionar proveedor + etiqueta de clave' },
          { label: 'Ruta de firma', text: 'Cada emisión, firma de CRL y firma OCSP de esa CA pasa por el HSM, la clave nunca sale' },
          { label: 'Restricciones de exportación', text: 'PKCS#12, JKS y exportaciones de solo clave están deshabilitadas para CA HSM (solo el certificado público / cadena pueden exportarse)' },
          { label: 'CRL y OCSP', text: 'Ambos funcionan de forma transparente con CA HSM (firmados vía HSM)' },
          { label: 'Migración', text: 'Las CA locales existentes no pueden moverse a un HSM tras la creación, elegir en la creación' },
        ]
      },

      {
        title: 'Raíz offline SmartCard-HSM',
        content: 'El tipo de proveedor sc-hsm-cloud respalda una raíz offline con participaciones DKEK n de m en tokens USB. UCM solo almacena el blob envuelto y las URL de ceremonia — nunca bytes de participación.',
        items: [
          { label: 'Umbral n / total m', text: 'Configure cuántas participaciones deben conectarse y cuántos custodios tienen tokens' },
          { label: 'Asignación de custodios', text: 'Asigne cada índice de participación a un usuario UCM con contribute:hsm; write:hsm gestiona la lista' },
          { label: 'Ventana de firma', text: 'Un operador abre una ventana solo para acciones de raíz. Los protocolos (ACME, SCEP, EST, WSTEP) siguen denegados mientras ca.offline esté activo' },
          { label: 'ram-client', text: 'Cada custodio ve solo su propio comando de un solo uso y el estado: en espera, conectado o aportado' },
          { label: 'Comprobar token', text: 'Lee el estado del dominio de claves y si existe el archivo de participación CF01. SW=6A82 significa que la tarjeta respondió y aún no tiene ese archivo' },
          { label: 'Reinicializar dispositivo', text: 'Igual que Initialize device de CardContact. Borra todas las claves y archivos y fija un esquema: participaciones DKEK (úselo aquí), DKEK aleatorio, sin DKEK o dominios de claves. El SO-PIN es el código de inicialización actual. Escriba DELETE. No escribe participaciones' },
          { label: 'Preparar token', text: 'Borra el archivo de participación y el dominio en una tarjeta que ya tiene dominio de participaciones. Escriba DELETE' },
          { label: 'Crear clave raíz', text: 'Primera ceremonia. Todos los custodios deben estar conectados. Genera la clave, escribe una participación en cada token y guarda la raíz envuelta. Escriba DELETE' },
          { label: 'Dispositivo de ensamblaje', text: 'Ventana posterior. Lee participaciones que ya están en los tokens. Cualquier umbral de presentes puede ensamblar; el token de la vez anterior no tiene que estar. n de n no puede seguir si falta un token' },
          { label: 'CRL antes del borrado', text: 'El borrado se bloquea hasta regenerar la CRL tras el último cambio; el borrado debe confirmarse antes de cerrar' },
          { label: 'Respondedor OCSP', text: 'Si el respondedor delegado caduca antes de la próxima ceremonia, el cierre requiere un reconocimiento explícito — no un cierre silencioso' },
        ]
      },

    ],
    tips: [
      'Use SoftHSM para pruebas antes de implementar con un HSM físico',
      'Las claves generadas en un HSM nunca salen del hardware, no se pueden exportar',
      'Pruebe la conexión antes de usar un proveedor HSM para la firma de CA',
      'Para CA raíz de larga duración en producción, prefiera el almacenamiento de clave respaldado por HSM',
    ],
    warnings: [
      'Una configuración incorrecta del proveedor HSM puede impedir la firma de certificados',
      'Perder el acceso al HSM significa perder el acceso a las claves almacenadas en él',
    ],
  },
  helpGuides: {
    title: 'Módulos de Seguridad de Hardware',
    content: `
## Descripción general

Los Módulos de Seguridad de Hardware (HSM) proporcionan almacenamiento resistente a manipulaciones para claves criptográficas. Las claves privadas almacenadas en un HSM nunca salen del hardware, proporcionando el nivel más alto de protección de claves.

## Proveedores compatibles

### PKCS#11
La interfaz HSM estándar de la industria. Dispositivos compatibles:
- **Thales Luna** / **SafeNet**
- **Entrust nShield**
- **SoftHSM** (basado en software, para pruebas)
- Cualquier dispositivo compatible con PKCS#11

> 💡 **Docker**: SoftHSM viene preinstalado en la imagen Docker. Al primer inicio, se inicializa automáticamente un token predeterminado y se registra como el proveedor \`SoftHSM-Default\`: listo para usar de inmediato.

Configuración:
- **Ruta de biblioteca**: Ruta a la biblioteca compartida PKCS#11 (.so/.dll)
- **Slot**: Número de slot del HSM
- **PIN**: PIN de usuario para autenticación

### AWS CloudHSM
HSM basado en la nube de Amazon Web Services:
- **ID de clúster**: Identificador del clúster CloudHSM
- **Región**: Región de AWS
- **Credenciales**: Clave de acceso y secreto de AWS

### Azure Key Vault
Almacenamiento de claves gestionado de Microsoft Azure:
- **URL del Vault**: Endpoint de Azure Key Vault
- **ID de tenant**: Tenant de Azure AD
- **ID/Secreto de cliente**: Credenciales del principal de servicio

### Google Cloud KMS
Servicio de gestión de claves de Google Cloud:
- **Proyecto**: ID del proyecto de GCP
- **Ubicación**: Ubicación del anillo de claves KMS
- **Anillo de claves**: Nombre del anillo de claves
- **Credenciales**: Clave JSON de la cuenta de servicio

### OpenBao / Vault Transit
Motor de secretos Transit de OpenBao o HashiCorp Vault. Las claves se gestionan remotamente a través de la API Transit, no se requiere biblioteca PKCS#11.

Configuración:
- **URL**: Dirección del servidor (ej. \`https://openbao.example.com:8200\`)
- **Token**: Token de autenticación
- **Ruta de montaje**: Punto de montaje del motor Transit (predeterminado: \`transit\`)
- **Espacio de nombres**: Espacio de nombres opcional para configuraciones multi-inquilino
- **Omitir verificación TLS**: Omitir verificación de certificado TLS (para certificados autofirmados)

Tipos de claves soportados:
- RSA 2048, 3072, 4096
- ECDSA P-256, P-384, P-521
- AES-256-GCM (simétrico)

> 💡 OpenBao es un fork comunitario de HashiCorp Vault. UCM funciona con ambos.


### SmartCard-HSM (remoto)
Raíz offline respaldada por tokens USB SmartCard-HSM (\`sc-hsm-cloud\`). Distinto de AWS CloudHSM.

- **Umbral n / total m**: Cuántas participaciones deben conectarse y cuántos custodios tienen tokens
- **Custodios**: Cada índice de participación se asigna a un usuario UCM (\`contribute:hsm\` se une; \`write:hsm\` gestiona la lista)
- **Ventana de firma**: El operador abre una ventana para acciones de raíz. Los protocolos siguen denegados; \`ca.offline\` permanece
- **ram-client**: Cada custodio ejecuta un comando de un solo uso mostrado solo a él; estado en espera, conectado o aportado
- **Listo**: Inicializado para participaciones DKEK, dominio vacío, sin archivo \`CF01\`. **Comprobar token** lo lee. \`SW=6A82\` significa que aún no hay archivo de participación
- **Reinicializar dispositivo**: Igual que Initialize device de CardContact. Borra claves y archivos y fija un esquema (para UCM: participaciones DKEK). El SO-PIN es el código actual. Escriba \`DELETE\`. \`SW=6982\` es un SO-PIN incorrecto; \`SW=6A80\` datos rechazados; \`SW=6D00\` indica que no hay dominio de participaciones
- **Crear clave raíz**: Primera ceremonia, los \`m\` tokens conectados. Escribe la primera participación. **Dispositivo de ensamblaje** solo lee participaciones ya presentes. En la ventana siguiente basta cualquier umbral presente; n de n exige todos
- **Dispositivo de ensamblaje**: Un token conectado reconstruye la clave raíz; UCM nunca ve la clave en claro ni bytes de participación
- **CRL antes del borrado**: El borrado se bloquea hasta regenerar la CRL; debe confirmarse antes de cerrar
- **Aviso OCSP**: Si el respondedor delegado caduca antes de la próxima ceremonia, el cierre requiere reconocimiento explícito

## Gestión de proveedores

### Agregar un proveedor
1. Haga clic en **Agregar proveedor**
2. Seleccione el **tipo de proveedor**
3. Ingrese los detalles de conexión
4. Haga clic en **Probar conexión** para verificar
5. Haga clic en **Guardar**

### Probar conexión
Siempre pruebe la conexión después de crear o modificar un proveedor. UCM verifica que puede comunicarse con el HSM y autenticarse.

### Estado del proveedor
Cada proveedor muestra un indicador de estado de conexión:
- **Conectado**: El HSM es accesible y está autenticado
- **Desconectado**: No se puede alcanzar el HSM
- **Error**: Problema de autenticación o configuración

## Gestión de claves

### Generar claves
1. Seleccione un proveedor conectado
2. Haga clic en **Generar clave**
3. Elija el algoritmo (RSA 2048/4096, ECDSA P-256/P-384)
4. Ingrese una etiqueta/alias para la clave
5. Haga clic en **Generar**

La clave se crea directamente en el HSM. UCM almacena solo una referencia.

### Uso de claves HSM
Al crear una CA, seleccione un proveedor HSM y una clave en lugar de generar una clave por software. Las operaciones de firma de la CA se realizan en el HSM.

> ⚠ Las claves generadas en un HSM no se pueden exportar. Si pierde el acceso al HSM, pierde las claves.

> 💡 Use SoftHSM para desarrollo y pruebas antes de implementar con HSMs físicos.
`
  }
}
