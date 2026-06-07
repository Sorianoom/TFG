# Guía rápida para lanzar la web del TFG

## 1. Objetivo

Esta guía explica cómo lanzar la web interactiva del TFG desde el ordenador local y acceder a ella desde cualquier ordenador mediante una URL temporal de Cloudflare Tunnel.

La web se ejecuta en local, pero se expone temporalmente a internet mediante una URL segura `https://...trycloudflare.com`.

La arquitectura usada es:

```text
FastAPI backend → puerto 8000
React frontend compilado → servido por FastAPI
Cloudflare Tunnel → URL pública temporal
```

Esto permite usar una sola URL para toda la web:

```text
https://xxxxx.trycloudflare.com
```

Desde esa URL se accede a:

* la web visual;
* las páginas de ataques;
* el simulador de ataques sintéticos;
* el chat IA ON con NotebookLM;
* la ejecución del clasificador v5;
* la API en `/api/...`.

---

## 2. Requisitos previos

Antes de lanzar la web, deben estar instalados:

* Python y entorno virtual del proyecto.
* Node.js / npm.
* Git, solo si se quiere guardar cambios.
* Cloudflared.
* NotebookLM configurado si se quiere usar el modo IA ON.

Rutas importantes del proyecto:

```text
Proyecto:
D:\homeMario\Home

Frontend:
D:\homeMario\Home\web\frontend

Backend:
D:\homeMario\Home\web\backend

Cloudflared:
C:\Program Files (x86)\cloudflared\cloudflared.exe
```

---

## 3. Compilar el frontend

Antes de lanzar la web en modo URL única, hay que compilar el frontend React.

Abrir PowerShell y ejecutar:

```powershell
$env:Path += ";C:\Program Files\nodejs"

cd D:\homeMario\Home\web\frontend

npm run build
```

Esto genera la carpeta:

```text
D:\homeMario\Home\web\frontend\dist
```

Esa carpeta es la que sirve FastAPI cuando se entra en la web.

Si `npm` no se reconoce, ejecutar:

```powershell
cd D:\homeMario\Home\web\frontend

& "C:\Program Files\nodejs\npm.cmd" run build
```

---

## 4. Lanzar el backend

Abrir una nueva PowerShell.

Activar el entorno virtual si hace falta:

```powershell
cd D:\homeMario\Home

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

.\venv\Scripts\Activate.ps1
```

Después lanzar el backend:

```powershell
cd D:\homeMario\Home\web\backend

uvicorn main:app --reload
```

Debe aparecer algo parecido a:

```text
Uvicorn running on http://127.0.0.1:8000
```

Comprobar localmente:

```text
http://127.0.0.1:8000
```

Debe cargar la web.

También se puede comprobar la API:

```text
http://127.0.0.1:8000/api/health
```

Debe devolver un JSON con `status: ok`.

---

## 5. Activar usuario y contraseña

Para proteger la web con usuario y contraseña, lanzar el backend con estas variables antes de `uvicorn`:

```powershell
$env:WEB_AUTH_ENABLED="true"
$env:WEB_AUTH_USER="sori"
$env:WEB_AUTH_PASSWORD="PON_AQUI_LA_CONTRASEÑA"

cd D:\homeMario\Home\web\backend

uvicorn main:app --reload
```

Al entrar en la web, el navegador pedirá usuario y contraseña.

Importante:

* No guardar la contraseña en el código.
* No subir `.env` a GitHub.
* No compartir la contraseña públicamente.

---

## 6. Crear la URL pública con Cloudflare Tunnel

Con el backend funcionando en `http://127.0.0.1:8000`, abrir otra PowerShell y ejecutar:

```powershell
& "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8000
```

Esperar hasta que aparezca algo como:

```text
Your quick Tunnel has been created!
https://xxxxx.trycloudflare.com
```

Esa URL es la dirección pública temporal de la web.

Ejemplo:

```text
https://xxxxx.trycloudflare.com
```

Mientras la terminal de `cloudflared` esté abierta, la web será accesible desde cualquier ordenador.

---

## 7. Terminales que deben quedar abiertas

Para que la web funcione desde internet, deben quedar abiertas dos terminales:

```text
1. Backend FastAPI:
   uvicorn main:app --reload

2. Cloudflare Tunnel:
   cloudflared tunnel --url http://127.0.0.1:8000
```

Si se cierra una de esas dos terminales, la URL dejará de funcionar.

---

## 8. Prueba recomendada antes de la presentación

Antes de la defensa, comprobar:

1. Abrir la URL de Cloudflare desde el ordenador local.
2. Abrir la URL desde el móvil usando datos móviles.
3. Abrir la URL desde otro ordenador si es posible.
4. Entrar en un ataque, por ejemplo `SSH Scan`.
5. Activar modo IA ON.
6. Probar el chat flotante.
7. Generar una simulación sintética.
8. Descargar el CSV generado.
9. Subir el CSV en “Probar clasificador v5”.
10. Comprobar que aparece:

    * predicción;
    * familia;
    * subtipo;
    * confianza;
    * explicación;
    * acierto si el CSV tiene etiqueta real.

---

## 9. Qué hace cada modo de IA

### IA OFF

El modo IA OFF funciona sin NotebookLM.

Usa:

* explicaciones locales;
* plantillas controladas;
* simulaciones sintéticas generadas por el backend;
* clasificador v5 desde la web.

Es rápido y estable.

### IA ON

El modo IA ON consulta los cuadernos específicos de NotebookLM para cada ataque.

Cada ataque tiene su propio cuaderno:

```text
dos
scan11
scan44
anomaly-udpscan
nerisbotnet
anomaly-sshscan
anomaly-spam
```

En IA ON, la web puede:

* consultar el cuaderno del ataque;
* generar explicaciones más ricas;
* construir simulaciones sintéticas basadas en los patrones del cuaderno;
* responder dudas desde el chat flotante.

NotebookLM no genera libremente el CSV. Propone el patrón y rangos aproximados. El backend valida la estructura y genera las filas de forma controlada.

---

## 10. Configuración de NotebookLM

La configuración real está en:

```text
D:\homeMario\Home\web\backend\.env
```

Ese archivo no debe subirse a Git.

Debe contener información como:

```env
NOTEBOOKLM_ENABLED=true
NOTEBOOKLM_AUTH_PATH=C:\Users\mario\.notebooklm\profiles\default\storage_state.json

NOTEBOOKLM_DOS_ID=...
NOTEBOOKLM_SCAN11_ID=...
NOTEBOOKLM_SCAN44_ID=...
NOTEBOOKLM_UDPSCAN_ID=...
NOTEBOOKLM_NERISBOTNET_ID=...
NOTEBOOKLM_SSHSCAN_ID=...
NOTEBOOKLM_SPAM_ID=...
```

Si NotebookLM falla o no está disponible, la web debe seguir funcionando con IA OFF.

---

## 11. Comandos resumidos para el día de la presentación

### Paso 1: compilar frontend

```powershell
$env:Path += ";C:\Program Files\nodejs"

cd D:\homeMario\Home\web\frontend

npm run build
```

### Paso 2: lanzar backend con contraseña

```powershell
cd D:\homeMario\Home

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

.\venv\Scripts\Activate.ps1

$env:WEB_AUTH_ENABLED="true"
$env:WEB_AUTH_USER="sori"
$env:WEB_AUTH_PASSWORD="PON_AQUI_LA_CONTRASEÑA"

cd D:\homeMario\Home\web\backend

uvicorn main:app --reload
```

### Paso 3: lanzar Cloudflare Tunnel

En otra terminal:

```powershell
& "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8000
```

### Paso 4: abrir URL

Copiar la URL que genera Cloudflare:

```text
https://xxxxx.trycloudflare.com
```

Abrirla desde cualquier ordenador.

---

## 12. Problemas comunes

### La URL muestra un JSON con endpoints

Eso significa que FastAPI está mostrando el índice de API en `/`.

Solución:

* comprobar que el frontend está compilado;
* ejecutar `npm run build`;
* reiniciar backend;
* abrir de nuevo `http://127.0.0.1:8000`.

---

### La web no carga

Comprobar que el backend está activo:

```text
http://127.0.0.1:8000/api/health
```

Si no responde, reiniciar:

```powershell
cd D:\homeMario\Home\web\backend

uvicorn main:app --reload
```

---

### Cloudflare dice “Unable to reach the origin service”

Significa que Cloudflare no encuentra el servicio local.

Comprobar:

```text
http://127.0.0.1:8000
```

Si localmente no funciona, Cloudflare tampoco podrá acceder.

---

### npm no se reconoce

Añadir Node al PATH de la terminal:

```powershell
$env:Path += ";C:\Program Files\nodejs"
```

O usar npm por ruta absoluta:

```powershell
& "C:\Program Files\nodejs\npm.cmd" run build
```

---

### git no se reconoce

Añadir Git al PATH:

```powershell
$env:Path += ";C:\Program Files\Git\cmd"
```

O usar Git por ruta absoluta:

```powershell
& "C:\Program Files\Git\cmd\git.exe" status
```

---

### cloudflared no se reconoce

Usar ruta absoluta:

```powershell
& "C:\Program Files (x86)\cloudflared\cloudflared.exe" --version
```

---

## 13. Seguridad

No subir nunca a Git:

```text
web/backend/.env
storage_state.json
.notebooklm/
node_modules/
dist/
data/raw/
data/clean/
```

La URL de Cloudflare es temporal. Cuando se cierre la terminal de `cloudflared`, la URL deja de funcionar.

No compartir la URL ni la contraseña fuera del contexto de la presentación.

---

## 14. Resumen final

Para lanzar la web desde cualquier ordenador:

```text
1. Compilar frontend.
2. Lanzar backend FastAPI.
3. Lanzar Cloudflare Tunnel al puerto 8000.
4. Abrir la URL generada.
5. Mantener abiertas las terminales.
```

La web queda disponible desde una única URL temporal con usuario y contraseña.
