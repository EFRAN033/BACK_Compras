import logging
from typing import Dict, Any, List, Optional
import datetime
import spacy
import re
import random
import json
import requests # ¡Importante! Asegúrate de instalar esto: pip install requests

# Importa tu función de conexión a la base de datos desde database.py
# Asegúrate de que 'database.py' y su función 'get_db_connection' estén en el mismo nivel
# o en una ruta accesible.
from database import get_db_connection
import psycopg2
from psycopg2.extras import RealDictCursor

# --- Configuración de Logging ---
# Configurar logging para el chatbot de proveedores. Esto es crucial para la depuración.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Cargar el modelo de lenguaje de SpaCy ---
# SpaCy es una librería poderosa para Procesamiento de Lenguaje Natural (PLN).
# Para una mejor comprensión semántica (con 'doc.similarity'), se recomienda un modelo
# que incluya vectores de palabras, como 'es_core_news_lg'.
# ¡IMPORTANTE!: Este modelo es grande. Debes descargarlo ejecutando en tu terminal
# (con tu entorno virtual activo):
# python -m spacy download es_core_news_lg
try:
    nlp = spacy.load("es_core_news_lg") # Cambiado a 'lg' para mejores vectores de palabras y coherencia
    logger.info("SpaCy modelo 'es_core_news_lg' cargado exitosamente.")
except Exception as e:
    # Este error es crítico para la coherencia. Hazlo más visible.
    logger.error(f"Error al cargar el modelo de SpaCy: {e}. Por favor, asegúrese de haberlo descargado.")
    # Si no puedes cargar el modelo, la aplicación no funcionará correctamente.
    # Podrías salir o manejar la excepción de otra manera.
    # En este caso, continuamos pero con un modelo nulo, lo que causará errores posteriores.
    nlp = None

# --- Configuración del LLM (Modelo de Lenguaje Grande) ---
# Asegúrate de que Ollama esté corriendo en tu sistema y que el modelo esté descargado.
OLLAMA_API_URL = "http://localhost:11434/api/generate"
# --- CAMBIO IMPORTANTE: Usamos Gemma:2b para mejor rendimiento ---
# Asegúrate de haber descargado este modelo: ollama run gemma:2b
MODEL_NAME = "gemma:2b" 
TIMEOUT = 45 # Segundos de espera para la respuesta del LLM

# --- Definición de intenciones con ejemplos ---
# Hemos añadido una nueva intención 'listar_productos' y mejorado los ejemplos
INTENCIONES = {
    "saludo": ["hola", "buenos dias", "buenas tardes", "buenas noches", "que tal"],
    "agradecimiento": ["gracias", "muchas gracias", "te lo agradezco"],
    "despedida": ["adios", "chao", "hasta luego", "nos vemos"],
    # --- ACTUALIZACIÓN AQUÍ: Añadimos más ejemplos para mejor detección ---
    "listar_solicitudes": [
        "informacion de mis pedidos",
        "cuales son mis solicitudes",
        "dime mis pedidos",
        "muestrame mis solicitudes de compra",
        "que solicitudes tengo pendientes",
        "tengo algun pedido?", # <-- ¡CORRECCIÓN! Añadimos esta frase clave
        "hay pedidos nuevos?",
        "revisar mis pedidos",
        "informacion de mi pedido", # <-- ¡CORRECCIÓN! Singular
        "tengo alguna compra?", # <-- ¡CORRECCIÓN! Variante con 'compra'
        "alguna compra tengo o no", # <-- ¡CORRECCIÓN! Frase que falló en el log
        "estado de mis compras", # <-- ¡NUEVO! Frase común
        "quiero saber mis pedidos" # <-- ¡NUEVO! Otra variante
    ],
    "estado_verificacion": [
        "como esta mi verificacion",
        "ya me verificaron",
        "saber estado de verificacion",
        "mi cuenta esta verificada?",
        "estado de mi cuenta",
        "mi estado de cuenta"
    ],
    "ayuda": ["necesito ayuda", "ayudame", "tengo un problema", "no se que hacer"],
    # Intención para listar productos - ¡NUEVA LÓGICA y más ejemplos!
    # --- ACTUALIZACIÓN AQUÍ: Añadimos más ejemplos para mejor detección ---
    "listar_productos": [
        "cuantos productos tengo",
        "cuantos productos tengo publicados",
        "dame la lista de mis productos",
        "mostrar mis productos",
        "que productos he subido",
        "resumen de mis productos",
        "productos subidos",
        "quiero ver mis productos",
        "inventario de productos",
        "ver mis productos",
        "informacion de mis productos",
        "cuantas ofertas tengo?", # Agregamos una variante que menciona "ofertas"
        "cuantos productos tengo?" # Añadimos con signo de interrogación
    ]
}

# --- Definición de entidades (RegEx para IDs) ---
ENTIDADES = {
    "id_solicitud": r"\b(solicitud|pedido)\s*#?\s*(\d+)\b",
    "fecha": r"\b(hoy|ayer|mañana)\b"
}

# --- Plantillas de respuestas predefinidas ---
RESPUESTAS_PREDEFINIDAS = {
    "saludo": "¡Hola! Soy tu asistente de proveedor. ¿En qué puedo ayudarte hoy?",
    "agradecimiento": "De nada, para eso estoy. ¿Hay algo más en lo que pueda ayudarte?",
    "despedida": "¡Hasta luego! Que tengas un excelente día. Si me necesitas, no dudes en preguntar.",
    "estado_verificacion": { --cd
        "verificado": "¡Felicidades! Tu cuenta de proveedor está completamente verificada. Ahora puedes disfrutar de todos los beneficios.",
        "pendiente": "Tu cuenta de proveedor aún está en proceso de verificación. Estamos revisando tus documentos y te notificaremos cuando el proceso se complete. ¡Agradecemos tu paciencia!",
        "no_encontrado": "No pude encontrar el estado de verificación de tu cuenta. Por favor, asegúrate de que tu cuenta esté registrada correctamente."
    },
    "listar_solicitudes": "Aquí tienes tus últimas solicitudes:\n",
    "listar_solicitudes_vacio": "No tienes ninguna solicitud de compra o pedido reciente. ¡Estamos seguros de que pronto recibirás nuevas oportunidades!",
    # --- NUEVA RESPUESTA PREDEFINIDA: Para 0 productos ---
    "listar_productos_vacio": "No tienes ninguna oferta o producto publicado en este momento.",
    "ayuda": "Claro, puedo ayudarte. Por favor, sé más específico. Por ejemplo, ¿necesitas ayuda con tus solicitudes, tus productos o tu cuenta?",
    "desconocido": "Lo siento, no estoy seguro de cómo responder a eso. ¿Puedes reformular tu pregunta o intentar con algo más específico?",
    "error_db": "Lo siento, no pude conectar con la base de datos para obtener esa información. Por favor, inténtalo de nuevo más tarde.",
    "error_llm": "Lo siento, estoy teniendo problemas para generar una respuesta en este momento. Por favor, inténtalo de nuevo en unos momentos."
}

# --- Función para generar respuesta con el LLM (Ollama) ---
def generar_respuesta_con_llm(prompt_para_llm: str, contexto_extra: Optional[str] = None) -> str:
    """
    Genera una respuesta utilizando el modelo de lenguaje de Ollama.
    
    Args:
        prompt_para_llm (str): El prompt principal que se le enviará al modelo.
        contexto_extra (Optional[str]): Información adicional para el RAG.
        
    Returns:
        str: La respuesta generada por el LLM o un mensaje de error.
    """
    # --- PROMPT DE SISTEMA MEJORADO ---
    # Este prompt le da un rol al LLM y lo restringe para evitar alucinaciones.
    # Se añade un contexto de sistema que se aplicará a todas las interacciones del LLM.
    prompt_sistema = (
        "Eres un chatbot de soporte para proveedores de un sistema de compras. "
        "Tu propósito es responder preguntas sobre el estado de las solicitudes de compra, "
        "la verificación de la cuenta y los productos del proveedor. "
        "Sé conciso, amigable y profesional. NO respondas sobre temas fuera del alcance "
        "de tus funciones como proveedor, como inversiones, cultura o temas personales."
        "Basate UNICAMENTE en la información proporcionada y en tu conocimiento general."
    )

    full_prompt = f"Contexto: {contexto_extra}\n\nPregunta: {prompt_para_llm}" if contexto_extra else prompt_para_llm
    
    # Construcción del payload para la API de Ollama
    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False,
        "raw": False, # Desactivamos el modo 'raw' para que use el prompt de sistema
        "system": prompt_sistema # ¡Aquí se pasa el prompt de sistema!
    }
    
    try:
        logger.info(f"Generando respuesta con LLM para prompt: {full_prompt[:100]}...")
        # Hacemos la petición a la API de Ollama con un timeout
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=TIMEOUT)
        response.raise_for_status() # Lanza una excepción para códigos de estado HTTP erróneos
        
        # Parseamos la respuesta JSON
        response_data = response.json()
        respuesta_generada = response_data.get("response", "No pude generar una respuesta.")
        
        logger.info("Respuesta del LLM generada exitosamente (vía Ollama).")
        return respuesta_generada
        
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Error de conexión con Ollama. Asegúrate de que Ollama esté corriendo. {e}")
        return RESPUESTAS_PREDEFINIDAS["error_llm"]
    except requests.exceptions.Timeout:
        logger.error(f"La petición a Ollama ha excedido el tiempo de espera de {TIMEOUT} segundos.")
        return RESPUESTAS_PREDEFINIDAS["error_llm"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error al llamar a la API de Ollama: {e}")
        return RESPUESTAS_PREDEFINIDAS["error_llm"]
    except json.JSONDecodeError:
        logger.error("Error al decodificar la respuesta JSON de Ollama.")
        return RESPUESTAS_PREDEFINIDAS["error_llm"]

# --- Lógica de clasificación de intenciones ---
def clasificar_intencion(texto: str) -> str:
    """
    Clasifica la intención del usuario basándose en similitud semántica con SpaCy y RegEx.
    Prioriza las intenciones que tienen una alta similitud con los ejemplos predefinidos.
    """
    # Si SpaCy no se cargó, no podemos hacer similitud.
    if nlp is None:
        logger.warning("SpaCy no está disponible, la clasificación se basará solo en RegEx.")
        return "desconocido" # o manejarlo de otra forma.

    doc = nlp(texto.lower())
    
    # Intenciones de saludo/despedida/agradecimiento (por RegEx o coincidencia exacta para eficiencia)
    for intent, keywords in INTENCIONES.items():
        if intent in ["saludo", "despedida", "agradecimiento"]:
            for keyword in keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', texto.lower()):
                    return intent

    # Clasificación por similitud semántica para intenciones más complejas
    max_sim = 0.7 # Umbral de similitud
    mejor_intencion = "desconocido"
    
    for intencion, ejemplos in INTENCIONES.items():
        if intencion in ["saludo", "despedida", "agradecimiento"]:
            continue # Ya se manejaron arriba
        
        for ejemplo in ejemplos:
            similitud = doc.similarity(nlp(ejemplo))
            if similitud > max_sim:
                max_sim = similitud
                mejor_intencion = intencion
    
    logger.info(f"Intención detectada: '{mejor_intencion}'")
    return mejor_intencion

# --- Lógica de extracción de entidades ---
def extraer_entidades(texto: str) -> Dict[str, Any]:
    """
    Extrae entidades como IDs de solicitudes usando expresiones regulares.
    """
    entidades = {}
    
    # Extraer ID de solicitud
    match_solicitud = re.search(ENTIDADES["id_solicitud"], texto, re.IGNORECASE)
    if match_solicitud:
        entidades["id_solicitud"] = int(match_solicitud.group(2))
        
    logger.info(f"Entidades extraídas: {entidades}")
    return entidades

# --- Lógica principal del Chatbot ---
def responder_chatbot_proveedor(mensaje: str, email_proveedor: str) -> str:
    """
    Procesa el mensaje del usuario, autentica, clasifica la intención, 
    consulta la DB y genera una respuesta.
    """
    logger.info(f"Mensaje recibido: '{mensaje}' (Email: {email_proveedor})")
    
    # 1. Autenticación (simulada) y obtención de información del proveedor
    # Esta parte asume que ya tienes el email autenticado desde el frontend.
    proveedor_id = None
    proveedor_info = None
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # --- CAMBIO IMPORTANTE AQUÍ: email_contacto en la cláusula WHERE ---
                # Usamos los nombres de columna correctos de tu DB
                cur.execute("SELECT id, estado_verificacion, nombre_completo_contacto FROM proveedores WHERE email_contacto = %s;", (email_proveedor,))
                proveedor_info = cur.fetchone()
                if proveedor_info:
                    proveedor_id = proveedor_info['id']
                    # Usamos el nombre de columna correcto en el log
                    logger.info(f"Chatbot Proveedor (DB): Información de proveedor encontrada para {proveedor_info.get('nombre_completo_contacto')}, con email {email_proveedor}")
                else:
                    return f"Lo siento, no pude encontrar tu cuenta de proveedor. Asegúrate de iniciar sesión con un email válido."
    except psycopg2.Error as e:
        logger.error(f"Error de base de datos al buscar proveedor: {e}")
        return RESPUESTAS_PREDEFINIDAS["error_db"]

    # 2. Clasificación de la intención
    intencion = clasificar_intencion(mensaje)
    
    # 3. Extracción de entidades
    entidades = extraer_entidades(mensaje)

    # 4. Manejo de intenciones y generación de respuesta
    respuesta = RESPUESTAS_PREDEFINIDAS.get(intencion) # Respuesta predefinida si existe

    # 5. Lógica de RAG (Retrieval-Augmented Generation) y respuestas dinámicas
    if intencion == "listar_solicitudes":
        try:
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Limitamos a 5 solicitudes para no sobrecargar el prompt
                    # --- CAMBIO AQUI: Usamos estado_solicitud en lugar de estado ---
                    cur.execute("SELECT id, estado_solicitud, titulo_solicitud, fecha_creacion FROM solicitudes_compra WHERE proveedor_id = %s ORDER BY fecha_creacion DESC LIMIT 5;", (proveedor_id,))
                    solicitudes = cur.fetchall()
                    logger.info(f"Chatbot Proveedor (DB): Se listaron {len(solicitudes)} solicitudes/ofertas para el proveedor {proveedor_id}.")
            
            if solicitudes:
                # Construir el texto contextual para el LLM
                contexto_solicitudes = "\n".join([
                    # --- CAMBIO AQUI: Usamos s['estado_solicitud'] en lugar de s['estado'] ---
                    f"Solicitud ID: {s['id']}, Título: {s['titulo_solicitud']}, Estado: {s['estado_solicitud']}, Fecha: {s['fecha_creacion'].strftime('%Y-%m-%d')}"
                    for s in solicitudes
                ])
                prompt_llm = f"El usuario preguntó por sus solicitudes. Aquí está la información de sus últimas solicitudes: {contexto_solicitudes}. Por favor, crea una respuesta amigable resumiendo esta información."
                respuesta = generar_respuesta_con_llm(prompt_llm)
            else:
                # --- CORRECCIÓN: Usamos la respuesta predefinida para una mejor experiencia de usuario ---
                respuesta = RESPUESTAS_PREDEFINIDAS["listar_solicitudes_vacio"]
        except psycopg2.Error as e:
            logger.error(f"Error de base de datos al listar solicitudes: {e}")
            respuesta = RESPUESTAS_PREDEFINIDAS["error_db"]

    elif intencion == "estado_verificacion":
        # Usamos la información obtenida al inicio
        estado = proveedor_info.get('estado_verificacion')
        if estado in RESPUESTAS_PREDEFINIDAS['estado_verificacion']:
            respuesta = RESPUESTAS_PREDEFINIDAS['estado_verificacion'][estado]
        else:
            respuesta = RESPUESTAS_PREDEFINIDAS['estado_verificacion']['no_encontrado']

    elif intencion == "ayuda":
        # La respuesta ya está definida, pero podríamos usar el LLM para elaborarla más
        prompt_llm = f"El usuario pidió ayuda. Responde de forma amigable y profesional, ofreciendo asistencia para solicitudes, productos o temas de cuenta."
        respuesta = generar_respuesta_con_llm(prompt_llm)
    
    elif intencion == "listar_productos":
        # --- CORRECCIÓN AQUÍ: Usamos la tabla 'ofertas' y la columna 'id_proveedor' ---
        try:
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT COUNT(*) FROM ofertas WHERE id_proveedor = %s;", (proveedor_id,))
                    cantidad_productos = cur.fetchone()['count']
            
            if cantidad_productos > 0:
                # Construir un prompt para el LLM con el dato recuperado
                prompt_llm = f"El proveedor preguntó cuántos productos tiene. La base de datos indica que tiene {cantidad_productos} ofertas publicadas. Crea una respuesta corta y directa para el usuario."
                respuesta = generar_respuesta_con_llm(prompt_llm)
            else:
                # --- CORRECCIÓN: Usamos la respuesta predefinida para 0 ofertas ---
                respuesta = RESPUESTAS_PREDEFINIDAS["listar_productos_vacio"]
        except psycopg2.Error as e:
            logger.error(f"Error de base de datos al contar productos: {e}")
            respuesta = RESPUESTAS_PREDEFINIDAS["error_db"]

    elif intencion == "desconocido":
        # --- PROMPT MEJORADO para intenciones desconocidas ---
        # Evita que el modelo responda con pasos o recetas.
        prompt_llm = (
            f"El usuario preguntó: '{mensaje}'. "
            "No pudiste clasificar su intención. "
            "Responde de manera amigable que no entiendes su pregunta y que debe ser más específico. "
            "Ofrece ejemplos de lo que sí puedes hacer (ej: 'revisar solicitudes', 'estado de verificación', 'ver mis productos'). "
            "NO listes pasos, no actúes como un desarrollador ni ofrezcas opciones genéricas."
        )
        respuesta = generar_respuesta_con_llm(prompt_llm)
        
    logger.info(f"Chatbot response for '{email_proveedor}': '{respuesta}'")
    return respuesta

# --- Función de prueba si se ejecuta el archivo directamente ---
if __name__ == '__main__':
    # Este email debe existir en tu DB para que las pruebas funcionen
    test_email_proveedor = "proveedor@gmail.com" 
    # Este email no debe existir en tu DB
    test_email_proveedor_no_existe = "usuario_no_registrado@example.com"
    
    print("\n--- Iniciando pruebas del chatbot para el proveedor ---")

    # Prueba la conexión a la base de datos antes de empezar
    try:
        with get_db_connection() as conn:
            print("Conexión a la base de datos de prueba exitosa.")
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Intenta obtener una solicitud de ejemplo para la prueba
                cur.execute("SELECT id FROM solicitudes_compra WHERE proveedor_id = (SELECT id FROM proveedores WHERE email_contacto = %s) LIMIT 1;", (test_email_proveedor,))
                solicitudes_ej = cur.fetchone()
    except Exception as e:
        print(f"ERROR: No se pudo conectar a la base de datos o ejecutar la consulta de prueba: {e}")
        solicitudes_ej = None

    # Pruebas con un email registrado
    if test_email_proveedor == "proveedor@gmail.com" and not solicitudes_ej:
        print("NOTA: Las pruebas para listar solicitudes pueden fallar porque no se encontraron solicitudes para el proveedor.")
    
    if solicitudes_ej or test_email_proveedor == "proveedor@gmail.com": # Asumimos que el proveedor existe para las pruebas
        print(f"\n--- Probando respuestas para el email registrado: {test_email_proveedor} ---")
        test_cases_with_email = [
            "Hola, cómo estás?", # Saludo
            "Necesito ver mis pedidos.", # Similitud para listar_solicitudes
            "cuantos productos tengo", # NUEVA PRUEBA: Listar productos (mejorada)
            "dame un resumen de mis productos publicados", # NUEVA PRUEBA: Otra forma de preguntar
            "dime la solicitud 123", # Extracción de entidad y LLM para detalle
            f"Dime todo de la solicitud {solicitudes_ej['id']}" if solicitudes_ej else "Info de una solicitud", # Prueba con ID real si existe
            "Cómo está mi verificación?", # Similitud para estado_verificacion
            "Necesito asistencia", # Similitud para ayuda
            "Simplemente gracias", # Similitud para agradecimiento
            "Chao", # Similitud para despedida
            "Cual es tu proposito?", # Prueba para "acerca_de_bot" con LLM simulado
            # PRUEBA CLAVE: La pregunta que falló y las preguntas fuera de tema
            "cuanto sproductos tengo", # Prueba con la palabra mal escrita para forzar la intención desconocida
            "cual es tu opinion sobre el futbol?", # Pregunta fuera de tema
            "Me ayudas a cambiar mi contraseña?", # Fuera de alcance directo, requiere delegación
        ]

        for user_msg in test_cases_with_email:
            print(f"\nUsuario (Logueado): '{user_msg}', email='{test_email_proveedor}'")
            print(f"Chatbot: {responder_chatbot_proveedor(user_msg, test_email_proveedor)}")
    else:
        print("\nLas pruebas personalizadas para el proveedor no se ejecutaron porque el email de prueba no es válido o no existe en la DB.")

    # Prueba con un email que no existe en la DB
    print(f"\n--- Probando respuestas para email no registrado: {test_email_proveedor_no_existe} ---\n")
    print(f"Usuario: 'Hola', email='{test_email_proveedor_no_existe}'")
    print(f"Chatbot: {responder_chatbot_proveedor('Hola', test_email_proveedor_no_existe)}")
    print("\n--- Pruebas finalizadas ---")