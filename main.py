import threading
import subprocess

# Función para ejecutar un script
def run_script(script_name):
    subprocess.run(['python', script_name])

# Hilos para ejecutar los scripts
thread1 = threading.Thread(target=run_script, args=('app.py',))
thread2 = threading.Thread(target=run_script, args=('newIDSpython.py',))

# Iniciar los hilos
thread1.start()
thread2.start()

# Esperar a que ambos hilos terminen
thread1.join()
thread2.join()
print("Ambos scripts han terminado.")
