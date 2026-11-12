# Control de accesos Cloudflare (Pages + Functions + D1)

Sistema centralizado de registro de visitas con dos modos por sitio:

- `redirect`: registra la entrada y redirige inmediatamente a la URL HTTPS que hayas autorizado.
- `protected`: sirve los archivos desde Cloudflare Pages, registra cada navegación HTML y exige que también los recursos pasen por el mismo dominio de Pages.

Los visitantes no crean cuenta ni introducen contraseña. El panel de administración sí exige una contraseña privada.

## IMPORTANTE antes de publicar

1. El seguimiento persistente del navegador solo se activa si el visitante acepta el aviso. Si lo rechaza, la visita queda como anónima (sitio, hora y ruta). Esto evita crear un identificador persistente sin consentimiento.
2. Un identificador de navegador no equivale a conocer el nombre real de una persona. Se pierde si se borran las cookies o se cambia de navegador/dispositivo.
3. El administrador debe completar `public/privacidad.html` con su identidad, contacto, finalidad, base jurídica y plazos reales de conservación. No publiques el sistema sin adaptar ese aviso.
4. Para que `protected` impida saltarse el control, desactiva GitHub Pages en el repositorio de origen. Mantén el código en GitHub, pero publícalo desde este proyecto de Cloudflare Pages. Si GitHub Pages sigue activo, seguirá existiendo una URL pública alternativa.
5. Los archivos del videojuego real aún no están incluidos. El directorio de ejemplo `public/sitio/vitrasachase/` contiene una página provisional. Debes copiar allí el contenido completo del repositorio de Vitrasa Chase.

## Estructura

```text
functions/_middleware.js        Middleware de registro y protección
schema.sql                      Tablas D1 + Vitrasa Chase inicial
public/admin/index.html         Panel de administración
public/privacidad.html           Aviso editable y retirada de consentimiento
public/sitio/vitrasachase/       Archivos del videojuego protegido
```

## Despliegue sin instalar programas en el Mac

### 1. Crear el repositorio GitHub

1. Descarga y descomprime este ZIP.
2. En GitHub, crea un repositorio nuevo, por ejemplo `control-accesos`.
3. En el repositorio, pulsa **Add file → Upload files**.
4. Sube el contenido de la carpeta `control-accesos-cloudflare` (no subas la carpeta ZIP como un único archivo).
5. Pulsa **Commit changes**.

### 2. Crear la base de datos D1

1. Abre Cloudflare Dashboard → **Workers & Pages** → **D1 SQL Database**.
2. Crea una base de datos llamada `control-accesos`.
3. Abre la base de datos → **Console**.
4. Copia y ejecuta todo el contenido de `schema.sql`.
5. Comprueba que aparecen las tablas `sites`, `visitors` y `access_logs`. El sitio inicial `vitrasachase` debe aparecer en `sites`.

### 3. Crear el proyecto Pages

1. Cloudflare Dashboard → **Workers & Pages** → **Create application** → **Pages**.
2. Elige **Connect to Git** y autoriza GitHub.
3. Selecciona el repositorio `control-accesos`.
4. Configuración:
   - Production branch: `main`
   - Framework preset: `None`
   - Build command: `cp privacidad.html public/privacidad.html`
   - Build output directory: `public`
   - Root directory: `/` (la raíz del repositorio)
5. Pulsa **Save and Deploy**.

Cloudflare detecta `functions/_middleware.js` en la raíz y lo ejecuta antes de servir los archivos estáticos.

### 4. Vincular D1

1. En el proyecto Pages abre **Settings → Functions → D1 database bindings** (en algunas vistas: Settings → Bindings).
2. Pulsa **Add binding**.
3. Variable name: `DB` (exactamente en mayúsculas).
4. Selecciona la base `control-accesos`.
5. Guarda y vuelve a desplegar el proyecto.

### 5. Crear secretos

En Pages → Settings → Variables and Secrets, añade estos secretos para Production:

- `ADMIN_PASSWORD`: una contraseña larga y única para entrar en `/admin/`.
- `ADMIN_SESSION_SECRET`: una cadena aleatoria larga (mínimo 32 caracteres).
- `IP_HASH_SECRET`: otra cadena aleatoria distinta, mínimo 32 caracteres.

No pongas estos valores en el HTML ni en GitHub. Guarda los cambios y vuelve a desplegar.

### 6. Comprobar

Abre la URL `https://TU-PROYECTO.pages.dev/api/health`. Debe responder `ok: true` y `database: true`.

Después abre `https://TU-PROYECTO.pages.dev/admin/`, inicia sesión y comprueba que aparece Vitrasa Chase. El enlace de acceso será:

```text
https://TU-PROYECTO.pages.dev/go/vitrasachase
```

También admite el formato que pediste, siempre que la URL esté registrada exactamente en D1:

```text
https://TU-PROYECTO.pages.dev/go?web=https%3A%2F%2Flucasmaneirodelatm-dot.github.io%2Fvitrasachase%2F
```

No se permite que `?web=` redirija a cualquier URL arbitraria: solo acepta destinos HTTPS registrados en D1. Esto evita convertir el servicio en un redireccionador abierto que pueda usarse para phishing.

## Añadir el videojuego real

Copia los archivos y carpetas completos del repositorio `vitrasachase` dentro de `public/sitio/vitrasachase/`, reemplazando la página provisional. Mantén las rutas de los recursos relativas al directorio del juego (por ejemplo `./css/...`, `./js/...`, `img/...`). Si el HTML usa rutas absolutas desde la raíz como `/img/...`, cámbialas para que incluyan el prefijo `/sitio/vitrasachase/` o conviértelas a relativas.

Después guarda los cambios en GitHub; Cloudflare Pages hará un nuevo despliegue automáticamente.

Una vez comprobado que el juego funciona en `https://TU-PROYECTO.pages.dev/sitio/vitrasachase/`, desactiva GitHub Pages en el repositorio original: **Settings → Pages → Build and deployment → Source → Deploy from a branch** (cambia a desactivado / elimina la fuente de publicación según la vista disponible). No borres el repositorio: seguirá siendo la fuente del código.

## Cómo funciona el seguimiento

- El primer acceso protegido crea un registro anónimo del sitio, hora y ruta.
- El aviso ofrece aceptar o rechazar el reconocimiento del navegador. Antes de elegir, solo se emplea una cookie técnica de sesión para poder cargar los archivos del sitio protegido; no se usa para reconocer visitas futuras.
- Si acepta, se crea un UUID aleatorio en una cookie propia `ca_vid`; se guardan navegador, SO, tipo de dispositivo, idioma, zona horaria, tamaño de pantalla, país/ciudad aproximados y un HMAC de la IP (nunca la IP original).
- Si rechaza, la visita sigue apareciendo como anónima y no se guarda información del dispositivo.
- Las páginas protegidas exigen cookie para cargar sus archivos estáticos. Las navegaciones HTML registran una nueva entrada.
- El navegador intenta comunicar la salida con `sendBeacon`, pero no todos los cierres o pérdidas de conexión permiten confirmarla. Por eso `exited_at` puede quedar vacío.
- En modo `redirect`, el registro y la redirección son inmediatos. Si el visitante ya había aceptado en ese mismo dominio, se reconoce su navegador; si no, la entrada queda anónima porque no se interrumpe el salto para pedir consentimiento.

## Limitaciones importantes

- No hay identificación real de personas sin login, sin una cuenta externa o sin que el usuario declare su identidad. El sistema reconoce navegadores consentidos, no personas.
- No es una barrera de autenticación contra alguien decidido a compartir cookies o automatizar peticiones. Sin login, el modo protegido controla el canal y registra visitas, pero no distingue con certeza a cada individuo.
- Para que todo el contenido quede protegido, también debes retirar cualquier otra publicación pública del mismo videojuego (GitHub Pages, otro host o copias públicas).
- El registro actual no elimina automáticamente datos antiguos. Configura un plazo de conservación y aplica una limpieza periódica en D1 según tu necesidad y las obligaciones legales.
