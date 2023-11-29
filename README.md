# Encryption Suite CLI

## Descripción

**Encryption Suite CLI** es una herramienta de línea de comandos que implementa varias funciones criptográficas, incluyendo hashing, firma y cifrado RSA, así como firma y verificación con criptografía de curvas elípticas. Esta herramienta está diseñada para ser fácil de usar, proporcionando una interfaz clara y opciones por defecto para una experiencia de usuario fluida.

## Requisitos

- Python 3.6 o superior
- Bibliotecas: `cryptography`, `click`, `rich`

## Instalación

Para instalar las dependencias necesarias, ejecuta el siguiente comando:

```bash
pip install -r requirements.txt
```

## Uso

A continuación, se describen los comandos disponibles en la CLI:

### Hash

Genera un resumen (hash) de un mensaje utilizando SHA-256.

```bash
python main.py hash "Tu Mensaje"
```

### Firma RSA

Genera una firma digital RSA de un mensaje.

```bash
python main.py sign-rsa "Tu Mensaje"
```

### Cifrado RSA

Cifra un mensaje utilizando criptografía asimétrica RSA.

```bash
python main.py encrypt-rsa "Tu Mensaje"
```

### Firma EC

Firma un mensaje utilizando criptografía de curvas elípticas. Permite especificar archivos para las claves privada y pública, así como para la firma.

```bash
python main.py sign-ec "Tu Mensaje" --private-key-file "ruta_privada.pem" --public-key-file "ruta_publica.pem" --signature-file "firma.txt"
```

Si no se especifican rutas de archivos, se utilizarán los valores predeterminados (`ec_private_key.pem`, `ec_public_key.pem`, `ec_signature.txt`).

### Verificación EC

Verifica una firma utilizando criptografía de curvas elípticas. Requiere el mensaje original, el archivo de firma y el archivo de clave pública.

```bash
python main.py verify-ec "Tu Mensaje" --signature-file "firma.txt" --public-key-file "ruta_publica.pem"
```

Si no se proporcionan rutas de archivos, se utilizarán los valores predeterminados.
