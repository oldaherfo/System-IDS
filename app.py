from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

# Función para conectarse a la base de datos
def get_db_connection():
    conn = sqlite3.connect('results.db')
    conn.row_factory = sqlite3.Row  # Para que los resultados se comporten como diccionarios
    return conn

# Ruta para mostrar los resultados
@app.route('/')
def index():
    conn = get_db_connection()
    log = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').fetchall()
    conn.close()
    return render_template('index.html', log=log)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
