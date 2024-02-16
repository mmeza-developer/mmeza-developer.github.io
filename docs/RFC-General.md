---
title: Framework OAuth 2.0 
subtitle: En esta publicación sera descrito en forma resumida el Framework OAuth 2.0, el objetivo es identificar sus conceptos generales, como funciona el OAuth 2.0 y las consideraciones de seguridad. Toda la información que veras en esta publicación está basada en el RFC 6749. Los nombres de los roles y parámetros de OAuth están en inglés, la idea es hacer una descripción en español para facilitar la lectura del RFC.
date: 2024-02-09
tags:
    - Pentesting Web
---

# ¿Que es OAuth 2.0?

OAuth 2.0 es un Framework que permite:

- Gestionar los datos de los usuarios y la autorizacion de acceso a estos datos
- Permite a los usuarios autenticarse en aplicaciones nativas o aplicaciones web  de terceros usando el protocolo HTTP.

El Framework OAuth 2.0 define un conjunto de 4 posibles implementaciones o flujos de OAuth, estas son:

- [Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)
- [Implicit Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2)
- [Resource Owner Password Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)
- [Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)

De los flujos mencionados uno son mas seguros que otros. Sin embargo, OAuth no es una bala de plata, si tu sistema tiene otras vulnerabilidades como CSRF, XSS, Open Redirect, o el flujo o protocolo de OAuth es mal implementado, entonces tu sistema es vulnerable

Te preguntaras, ¿qué es un flujo?: Un flujo en OAuth es un conjunto de interacciones entre las distintos "roles" del Framework. Define básicamente quien interactua con quien y como lo hace. Los "roles" mas importantes de OAuth son:

- **Resource Owner**
- **Resource Server**
- **Authorization Server**
- **Client**

Las interacciones de estos roles depende de "parametros" o "tokens" los cuales permiten intercambiar información entre los distintos roles del Framework OAuth, algunos de estos son:

- **Authorization Grant**
- **Access Token**
- **Authorization Code**
- **Implicit Authorization Grant**
- **State**
- **Scope**
- etc

En el presente documento, veremos un Flow o flujo general del Framework OAuth 2.0 y describiremos sus role e interacciones

# ¿Cual es el proposito de OAuth 2.0?

El propósito de OAuth 2.0 es centralizar los datos de los usuarios, restringir el acceso a sus recursos y, además, permitir a otras aplicaciones (o aplicaciones de terceros) autenticar y validar la identidad de los usuarios que ingresan a sus sistemas

# Conceptos importantes

La siguiente lista son los conceptos esenciales para comprender OAuth 2.0

- **Resource:** Consiste en todo tipo de dato que pertenece a un usuario, por ejemplo: nombre, foto de perfil, email, numero de teléfono, dirección, etc.

- **Resource Owner:** Es el usuario dueño de sus datos, este comparte su información con el Resource Server. Además, es el que da autorización a otras aplicaciones  para acceder a sus datos almacenados en el Resource Server.

- **Resource Server:** Es el servidor que almacena los datos de todos los usuarios registrados en sus sistema. Estos datos estan protegidos y solo los usuarios o aplicaciones autorizadas pueden acceder a estos.

- **Client:** Es la aplicación nativa o web que intenta primero autenticar o registrar a un usuario  y, posteriormente acceder a ciertos datos o recursos del mismo.

- **Authorization Server:** Para acceder a los recursos de Resource Server el usuario (Resource Owner) debe autenticarse en el Authorization Server. Si el proceso de autenticación fue exitoso entonces, el Autorization Server emitira un **Access Token**. En resumidas cuentas, es el servidor que da acceso a los recursos del usuario a través del Access Token

- **Authorization Grant:** Es una credencial que representa la autorizacion que da un **Resource Owner** a un **Client** para acceder a sus recursos

- **Access Token:** Token que permite al **Client** el acceso a los recursos de **Resource Owner** almacenados en el **Resource Server**

- **Client Credentials:** Son las credenciales con las que el cliente se autentica con el Authorization Server

## Conceptos Utilizados en otros flujos de OAuth

Flujo Authorization Code Grant:

- **Authorization Code:** El Authorization Code es un  token que es obtenido de la interaccion entre el **Client** y el **Authorization Server**. Este forma parte del flujo **Authorization Code Grant**, De forma muy resumida el proceso para obtener el Authorization Code es siguiente:
	- En vez de solicitar autorizacion al **Resource Server**, el **Client** redirecciona al usuario (Resource Owner) al Authorization Server a través de un navegador web
	- El **Authorization Server** autentica al usuario (**Resource Owner**) este último autoriza al **Client** y luego el **Authorization Server** redirige al usuario a la pagina de cliente a través de un navegador web
	- Finalmente el **Client** envía el **Authorization Code**  al **Authorization Server** para obtener el **Access Token**, que pemitirá al cliente acceder a los recursos del usuario 


# Protocol Flow de OAuth 2.0

El Protocol Flow permite ver las interacciones entre los distintos roles del Framework OAuth 2.0

![](/RFC-General/Pasted_image_20240214134004.png)

- (A) El **Client** solicita autorización al Resource Owner para acceder a sus recursos 

- (B) El **Resource Owner** autoriza al cliente, el cual es reflejado en el **Authorization Grant**, este ultimo es la credenciales que representa la autorizacion del **Resource Owner**

- (C) El **Cliente** envía el **Authorization Grant** al **Authorization Server**

- (D) El **Authorization Server** valida el **Authorization Grant**, si es válido entrega un **Access Token** al cliente

- (E) El **Client** envía el **Access Token** al **Resource Server** para solicitar el acceso a uno o varios recursos del usuario (**Resource Owner**)

- (F) El **Resource Server** valida el Access Token, si es válido, entonces entrega los recursos solicitados

# Consideraciones de seguridad

La siguiente lista es un conjunto de recomendaciones para mantener la seguridad del Framework OAuth 2.0. Estas pueden ser utilizadas tanto para mejorar la seguridad como para explotar la implementacion de OAuth (puede ser útil para alguna metodología de ataque a OAuth ;) ).


## El Cliente Debe:

- Mantener seguras sus credenciales, un cliente puede ser suplantado si no mantiene sus credenciales seguras

## Autentication Server debe:

- Identificar al cliente mediante sus credenciales.
- Mantener las credenciales del cliente seguras
- No debe emitir las credenciales del cliente a aplicaciones nativas con el objetivo de autenticar al cliente
- El Authorization Server puede emitir las credenciales de cliente para aplicaciones nativas instaladas en dispositivos específicos.
- El Authorization server no debe procesar Authorization request que se repiten de forma automatica (sin la interacción del usurio), sin autenticar al cliente o identificar que las request vienen desde un cliente legítimo.

## Suplantacion del Cliente

 - Si el Autorization Server no puede autenticar al cliente debido a su naturaleza, el Authorization Server debe requerir el registrar el Redirection URI para recibir Authorization Responses.
- En caso de no poder autenticar al cliente o Identificarlo, el Authorization Server puede Consultar al Resource Owner.
- El Authorization Server debe explicitamente autenticar al Resource Owner y entregar al resource Owner información sobre el cliente junto con el Request Authorization Scope y Lifetime.
- El Authorization server no debe procesar Authorization request que se repiten de forma automatica (sin la interacción del usuario), sin autenticar al cliente o identificar que las request vienen desde un cliente legítimo.

## Access Token

El Access Token como cualquier atributo de éste, debe ser confidencial tanto en tránsito como en almacenamiento. Solo debe ser compartido con el Authorization Server y el Resource Server.

- El Flujo Grant type, el acccess token puede ser transmitido en el fragment de la URI.
- El Authorization Server debe asegurarse que el Access Token no pueda ser generado o adivinado.
- El Cliente debe solicitar un Access Token con el minimo scope
- El Authorization Server debe identificar al cliente para entregar el Access Token.
- El scope entregado al cliente puede ser menor del solicitado
- El Resource Server debe identificar que el Access Token  ha sido emitido por el Authorization Server
- El Access Token debe ser transmitido sobre TLS

## Refresh Token

- El Refresh Token debe ser  confidencial tanto en su transito como en su almacenamiento.
- Debe ser compartido solo entre el Authorization Server y el Cliente
- El Authorization Server debe mantener un enlace entre el Refresh Token y el cliente al que fue emitido.
- El Refresh Token debe ser transmitido sobre TLS
- El Authorization Server debe asegurar una relación  entre el Refresh Token y el cliente
- El Authorization Server debe detectar abusos en Refresh Token. Por ejemplo el Authorization Server puede emitir regularmente nuevos Access Token para el cliente e invalidar los antiguos, pero deben seguir almacenados en el Authorization Server por si existe alguna solicitud no autorizada.
- El Authorization Server debe asegurarse que el Refresh Token no pueda ser generado o adivinado.

## Authorization Codes

El Authorization Code es una bearer Credential que verifica que el Resource Owner da acceso a un recurso solicitado por un cliente 

- La transmision del authorization Code debe ser mediante un canal seguro.
- El cliente debe requerir el uso de TLS en su Redirection URI
- Ya que el Authorization Code es transmitido vía user-aget (browser), este puede ser revelado por el historial de navegación o por el Header HTTP Referer.
- El Authorization Code debe ser de vida corta
- El Authorization Code debe ser de un solo uso
- El caso de multiples intentos de acceso con un Authorization Code el Authorization Server debe restringir todos los Access Token asociados al Authorization Code comprometido.
- El  Authorization Server  debe asegurarse que el Authorization Code fue imitido por un cliente no autenticado

## Authorization Code Redirection URI Manipulation

Cuando el cliente solicita un Auhtorization Grant en el Flujo Authorization Grant Type, este puede enviar parámetro llamado "redirect_uri" junto con el Authorization Code. 

- Un atacante puede manipular el parámetro "redirect_uri" y redirigir el tráfico a un servidor bajo su control

El proceso de ataque es el siguiente:

- Un atacante puede crear una cuenta en un cliente legitimo e iniciar un flujo. 
- Cuando el atacante es enviado al Authorization Server para obtener el Grant Access, el atacante puede modificar el "redirect_uri" con una URI bajo el control del atacante 
- El atacante puede entregar esta URI manipulada a un usuario legitimo para que el cliente tenga acceso a sus recursos. 
- Luego de que que el Authorization endpoint valide la request, confíe en el cliente y la request sea autorizada, el Resource Owner será redirigido a la URI bajo el control del atacante. 
- El atacante completa el Flujo de Authorization enviando el Authorization Code al cliente usando la URI original. El cliente intercambia el Authorization Code y el Access Token y enlaza estos con la cuenta del atacante, el cual ahora tiene acceso a los recursos del la victima.

## Resource Owner Password Credentials

A menudo el Resource Owner Credentials es utilizado para sistemas legacy o migraciones. Esto reduce la posibilidad de almacenas las credenciales en el cliente, y al mismo tiempo elimina la posibilidad de exponer las credenciales al cliente.

El flujo es el siguiente:

![](/RFC-General/Pasted_image_20220802180007.png)

- El cliente puede abusar de las credenciales del Resource Owner.
- El cliente puede exponer las credenciales del Resource Owner.
- Como el Resource Owner no tiene control sobre el proceso de autorización, el Cliente puede obtener Access Tokens con un scope más amplio de lo normal
- El Authorization Server debe considerar el scope y el lifetime del Access Token para este tipo de clientes. 


## Request Confidentiality

Los campos : Access Token, Refresh Token, Resource Owner Passwords y Client Credentials no deben ser transmitidos de forma clara
El campo : Authorization code no debería ser transmitido en forma clara

Los campos state y scope no deben incluir información sensible del Resource Owner, ya que estos pueden ser transmitidos de forma insegura o almancenados de forma insegura.


## Cross-Site Request Foregery

### CSRF contra Cliente

CSRF en Oauth consiste en atacar la "redirection_uri" del cliente, permitiendo a un atacante ingresar su propio Authorization Code o Access Token esto puede provocar que el Cliente use el Access Token del atacante más que el de la victima (Guardar la información de la cuenta de la victima en un Protected Resource controlado por el atacante).

El cliente debe implementar métodos de protección en el parámetro de "redirection_uri". Este método consiste en agregar un parámetro state con valor como una cookie de sesión. El cliente debe usar el parámetro state al Authorization Server siempre que se haga un Authorization Request.

Una vez el Resource Owner aprueba el acceso al recurso, el Authoriaztion Server redirige al usuario de vuelta al cliente con el parámetro state. Este valor permitirá al cliente validar la request con el state previo.

El valor del parámetro State debe cumplir lo siguiente:

- No debe ser fácil adivinar su valor
- Debe ser conocido por el cliente y el user-agent (browser)
- Debe ser accesible solo por el cliente y el user-agent (browser), por ejemplo, protegido por el Same Origin Policy

### CSRF contra Authorization Server

Un ataque CSRF contra el Authorization Server puede provocar que un atacante obtenga autorización para un cliente malicioso sin el consentimiento del Resource Owner 

## Code Injection and Input Validation

Si los parámetros de entrada del sistema no son validados correctamente puede causar multiples vulnerabilidades, como exposición de información, ejecución remota de comandos, modificación de la lógica de la aplicación, ataques de denegación de servicios,etc.

El Authorization Server debe sanitizar todos los paŕametros de entrada al sistema, en particular los siguientes parámetros:

- state
- redirect_uri

## Open Redirectors

El Authorization Server, Authorization Endpoint y el Client Redirection Endpoint pueden ser configurado de forma impropia y provocar una vulnerabilidad open redirect.

La vulnerabilidad Open Redirect consiste en la manipulación de un parámetro para redirigir el user-agent (browser) a una URL indicada. Open direcct puede ser usada para Ataques de Phishing, o hacer que un end-user visite sitios maliciosos.

También si el Authoriazation Server permite al cliente registrar parte de la redirection_url, un atacante puede usar este como un open redirect que será operado por el cliente para construir una URL que pasará la validación del  Authorization Server pero que enviara un Authorization Code o Access Token al endpoint que está abajo el control del atacante.


## Misuse Of Access Token To impersonate Resource Owner in Implicit

![](/RFC-General/Pasted_image_20220802192348.png)

# Fuentes


- [OAuth RFC](https://datatracker.ietf.org/doc/html/rfc6749#section-10)