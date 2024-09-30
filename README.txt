Este proyecto está diseñado para detectar actividades maliciosas en la red, como escaneos de puertos, ataques de fuerza bruta, inyecciones SQL, y más. Utiliza la biblioteca Scapy para la captura de paquetes y un servidor Flask para mostrar los resultados en una interfaz web.

Estructura del Proyecto
El proyecto contiene los siguientes archivos:

newIDSpython.py: Script principal que detecta actividades maliciosas en la red.
app.py: Servidor web Flask que muestra los logs de detección desde la base de datos.
main.py: Archivo que ejecuta los scripts app.py y newIDSpython.py de forma concurrente.

Requisitos:
-Python 3.x
Bibliotecas:
-Flask
-scapy
-sqlite3
-Acceso a la red para la captura de paquetes.
-Modifica el archivo "Auth_Panel_Config.txt" con el path del panel de autenticación en la primera linea. Por defecto este tomará la raíz del servidor "/"

Para ejecutar el proyecto, simplemente ejecuta main.py. Esto iniciará ambos scripts:

python main.py

Una vez que los scripts estén en ejecución, puedes acceder a la interfaz web abriendo un navegador y dirigiéndote a: 

http://<tu_dirección_ip>:5000/

Reemplaza <tu_dirección_ip> con la dirección IP de la máquina donde se está ejecutando el servidor Flask.

Tambien he adjuntado el archivo ejecutable "IDS.exe" para que lo puedas usar sin instalar dependencias en equipos Windows.

Funcionalidades:
Detección de Actividades:
-Escaneos de puertos: Detecta intentos de escaneo de puertos en puertos comunes.
-Conexiones SSH: Registra el inicio y finalización de conexiones SSH, así como posibles ataques de fuerza bruta.
-Inyecciones SQL: Monitorea patrones de inyección SQL en solicitudes HTTP.
-Fuerza bruta en panel de autenticación: Detecta intentos fallidos en la autenticación.
-Escaneo de ARP Ping y ARP spoofing

Base de Datos:
Los logs de detección se almacenan en una base de datos SQLite (results.db) y se muestran en la interfaz web.