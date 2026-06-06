// Metadatos de presentación del frontend (no son datos del backend).
// Los datos "duros" (descripción, señales, métricas, limitaciones) vienen de
// web/data/attacks.json servido por el backend.

// Orden y posición de las burbujas flotantes en la home.
export const ATTACK_ORDER = [
  "anomaly-udpscan",
  "scan11",
  "scan44",
  "dos",
  "anomaly-sshscan",
  "nerisbotnet",
  "anomaly-spam",
];

// Nombre corto para la burbuja.
export const SHORT_NAME = {
  "dos": "DoS",
  "anomaly-udpscan": "UDP Scan",
  "scan11": "scan11",
  "scan44": "scan44",
  "nerisbotnet": "Nerisbotnet",
  "anomaly-sshscan": "SSH Scan",
  "anomaly-spam": "Spam",
};

// Posición (en %) y profundidad de parallax de cada burbuja en la zona central.
export const FLOAT_POS = {
  "anomaly-udpscan": { left: 16, top: 10, depth: 1.4 },
  "scan11": { left: 70, top: 8, depth: 0.9 },
  "scan44": { left: 84, top: 46, depth: 1.2 },
  "dos": { left: 10, top: 52, depth: 1.0 },
  "anomaly-sshscan": { left: 48, top: 38, depth: 0.5 }, // central, destacado
  "nerisbotnet": { left: 74, top: 78, depth: 1.3 },
  "anomaly-spam": { left: 24, top: 84, depth: 1.1 },
};

// Color por estado (CSS var --ec).
export const ESTADO_META = {
  "fuerte": { label: "Fuerte", color: "#2ea043" },
  "parcial": { label: "Parcial", color: "#d29922" },
  "exploratorio": { label: "Exploratorio", color: "#6e7681" },
  "detectable con contexto largo (v5)": { label: "Contexto largo · v5", color: "#3fb6c4" },
};

export function estadoMeta(estado) {
  return ESTADO_META[estado] || { label: estado, color: "#6e7681" };
}

// "Cómo lo detecta v5" — explicación por ataque (presentación).
export const COMO_DETECTA_V5 = {
  "scan11":
    "El pase 1 (contexto local) detecta la verticalidad y los flujos SYN atómicos; el pase 2 (global por ventana) confirma que un único origen domina el barrido y lo separa de scan44.",
  "scan44":
    "El pase 2 (global por ventana) ve la verticalidad repartida entre varios orígenes sincronizados, sin que domine uno solo, y lo distingue de scan11.",
  "anomaly-udpscan":
    "El pase 1 detecta flujos UDP atómicos de baja entropía y el pase 2 confirma la dispersión hacia muchos destinos y puertos; se excluye el tráfico DNS (puerto 53).",
  "dos":
    "Los pases local y global miden la concentración de volumen hacia un dst_ip:puerto fijo frente a la dispersión propia del escaneo; la frontera concentración/dispersión es la señal clave.",
  "nerisbotnet":
    "El pase global agrupa por buckets temporales y busca varios orígenes con métricas idénticas en el mismo instante (coordinación C2). Los puertos C2 conocidos suman confianza, no son la única regla.",
  "anomaly-sshscan":
    "Con solo contexto local (v3) es indetectable: 0/0. El tercer pase global de la v5 agrega por origen y detecta el fan-out SSH (un src_ip que contacta muchos destinos en el puerto 22). En april.week2: P 0,999 / R 0,907 / F1 0,951. Matiz: en semanas sin sshscan etiquetado, este pase puede marcar escáneres SSH de fondo no etiquetados como background.",
  "anomaly-spam":
    "Aun con los tres pases, el SMTP de spam es casi indistinguible del SMTP legítimo usando solo metadatos de flujo; queda documentado como caso exploratorio (límite estructural).",
};

// Los 3 pases del clasificador v5.
export const PASSES = [
  {
    n: "Pase 1",
    t: "Contexto local",
    d: "Analiza cada traza con su contexto cercano (±30 filas) y detecta patrones básicos: atomicidad, ráfagas, concentración.",
  },
  {
    n: "Pase 2",
    t: "Contexto global por ventana",
    d: "Agrega por ventana: separa scan11/scan44, confirma udp_scan por dispersión y reduce el unknown_attack.",
  },
  {
    n: "Pase 3",
    t: "Fan-out SSH por origen",
    main: true,
    d: "Agrega por origen y detecta anomaly-sshscan por su fan-out al puerto 22, sin IPs ni etiquetas (april.week2: F1 0,951).",
  },
];

// Evolución del clasificador.
export const VERSIONS = [
  { v: "v1", t: "Contextual local", d: "Clasifica trazas por contexto local (±30 filas)." },
  { v: "v2", t: "Jerárquico", d: "Ataque/background → familia → subtipo (con incertidumbre)." },
  { v: "v3", t: "Local + global por ventana", d: "Resuelve scan11/scan44 y eleva udp_scan. Base estable." },
  { v: "v4", t: "Familias débiles", d: "Split de confianza en botnet (experimental, no adoptado)." },
  { v: "v5", t: "Final integrada", d: "Añade el tercer pase global SSH por fan-out. Versión principal.", final: true },
];

// Interpretación breve por ataque para la tabla de resultados.
export const INTERP = {
  "scan11": "Barrido vertical de un origen; robusto y generaliza.",
  "scan44": "Barrido vertical distribuido; subtipo menos estable.",
  "anomaly-udpscan": "Escaneo UDP; recall casi perfecto, sin generalización externa.",
  "dos": "Inundación TCP; se confunde en parte con el escaneo distribuido.",
  "nerisbotnet": "Coordinación de varios equipos; parcial. Niveles de confianza como línea futura.",
  "anomaly-sshscan": "Sondeo SSH lento y disperso; v5 lo recupera mirando el comportamiento global de cada origen.",
  "anomaly-spam": "Correo SMTP de bajo volumen; exploratorio, no resuelto.",
};

// "Qué NO usa" el clasificador (común a todos los ataques).
export const NOT_USED_COMMON = [
  "IPs concretas como regla",
  "la etiqueta real como entrada para detectar",
  "listas negras de direcciones como criterio principal",
  "entrenamiento de Machine Learning",
  "firmas exactas de bytes (mirar el contenido)",
];

// Metadatos técnicos por ataque, escritos para que los entienda cualquier
// profesor de informática (jerga explicada entre paréntesis).
export const TECH = {
  "scan11": {
    plain_explanation:
      "El detector marca scan11 cuando ve una sola máquina que prueba muchos puertos distintos de una misma víctima, uno tras otro, con conexiones muy cortas y repetitivas. Es un escaneo \"vertical\": recorre los puertos (las distintas \"puertas\" de servicios) de un único objetivo.",
    technical_features: [
      { name: "Mismo origen", description: "Casi todo el tráfico sospechoso sale de la misma máquina (misma IP de origen).", why_it_matters: "Un escaneo vertical clásico lo hace un único atacante, así que un origen que domina es una pista fuerte." },
      { name: "Mismo destino", description: "Ese tráfico se dirige a una sola víctima (misma IP de destino).", why_it_matters: "El atacante se centra en una máquina para descubrir qué servicios tiene abiertos." },
      { name: "Muchos puertos distintos", description: "Se contactan muchos puertos diferentes del destino (cada puerto es la entrada a un posible servicio).", why_it_matters: "Probar muchos puertos seguidos es justo lo que hace un escaneo vertical." },
      { name: "Conexiones cortas y repetitivas", description: "Cada intento es un flujo mínimo (un paquete, sin llegar a abrir una conexión real) y todos se parecen mucho.", why_it_matters: "El tráfico normal no repite cientos de veces el mismo gesto mínimo." },
      { name: "Contexto global de la ventana", description: "Se observa el conjunto del intervalo de tiempo analizado (la \"ventana\") para confirmar que un único origen domina.", why_it_matters: "Permite separar scan11 (un origen) de scan44 (varios orígenes)." },
    ],
    detection_steps: [
      "Agrupar el tráfico por pareja origen→destino dentro de la ventana de tiempo analizada.",
      "Contar cuántos puertos distintos del destino contacta ese origen.",
      "Comprobar que las conexiones son mínimas y repetitivas (intentos cortos, casi idénticos).",
      "Mirar el conjunto de la ventana para confirmar que un solo origen es el que domina el escaneo.",
      "Si se cumple todo, marcar esas trazas como scan11.",
    ],
    rule_pseudocode:
`# Escaneo vertical desde un único origen
if same_source and same_target and many_destination_ports:
    if connections_are_short_and_repetitive:
        attack = "scan11"`,
    validation_context:
      "Validado en la semana de diseño (UGR'16, august.week1) y comprobado en datos posteriores: el patrón se mantiene estable. La precisión indica cuántas alertas son correctas; el recall, qué parte del scan11 real se llega a detectar.",
    defense_explanation:
      "scan11 es el caso más claro: un atacante revisando los puertos de una víctima. El detector lo reconoce por la forma del tráfico, sin necesidad de saber qué IP es el atacante.",
  },

  "scan44": {
    plain_explanation:
      "El detector marca scan44 cuando ve varias máquinas distintas colaborando para escanear los puertos de un mismo objetivo, en lugar de una sola. Es como scan11, pero el trabajo se reparte entre varios atacantes.",
    technical_features: [
      { name: "Varios orígenes", description: "El tráfico de escaneo sale de varias máquinas a la vez (varias IPs de origen).", why_it_matters: "Repartir el escaneo entre varios equipos ayuda a pasar más desapercibido; ese reparto es la marca de scan44." },
      { name: "Objetivo común", description: "Todas esas máquinas apuntan al mismo objetivo o a un patrón de objetivos parecido.", why_it_matters: "Indica que actúan coordinadas, no por casualidad." },
      { name: "Muchos puertos destino", description: "Entre todas contactan muchos puertos diferentes del objetivo.", why_it_matters: "Sigue siendo un escaneo vertical (descubrir servicios), solo que distribuido." },
      { name: "Patrón repetitivo", description: "Las conexiones son cortas y muy parecidas entre sí.", why_it_matters: "Es típico de tráfico automatizado, no de un usuario real." },
      { name: "Pase global por ventana", description: "Se analiza la ventana de tiempo completa para ver que ningún origen domina por sí solo.", why_it_matters: "Eso distingue scan44 (repartido) de scan11 (un solo origen)." },
    ],
    detection_steps: [
      "Agrupar el tráfico de la ventana por objetivo y ver qué orígenes participan.",
      "Comprobar que hay varios orígenes contactando muchos puertos del mismo objetivo.",
      "Verificar que las conexiones son cortas y repetitivas.",
      "Confirmar con el pase global que el escaneo está repartido entre varios orígenes y no dominado por uno.",
      "Si encaja, marcar esas trazas como scan44.",
    ],
    rule_pseudocode:
`# Escaneo vertical distribuido (varias máquinas)
if many_sources and same_target and many_destination_ports:
    attack = "scan44"`,
    validation_context:
      "Validado en UGR'16. La parte más delicada es la frontera con scan11: cuando un origen domina mucho la ventana, parte de scan44 puede confundirse con scan11.",
    defense_explanation:
      "scan44 persigue lo mismo que scan11 (descubrir servicios), pero en equipo. El detector los separa mirando si el escaneo lo hace una máquina o varias.",
  },

  "anomaly-udpscan": {
    plain_explanation:
      "El detector marca un escaneo UDP cuando ve una máquina que envía muchísimos mensajes UDP ligeros hacia muchos destinos o servicios, en lugar de mantener conversaciones normales. UDP es un protocolo que manda mensajes sueltos sin abrir antes una conexión (al contrario que TCP), lo que lo hace ideal para sondear rápido.",
    technical_features: [
      { name: "Protocolo UDP", description: "El tráfico usa UDP: envía mensajes sueltos sin establecer una conversación previa.", why_it_matters: "Permite lanzar muchos sondeos muy rápido y baratos, perfecto para escanear." },
      { name: "Muchos destinos o servicios", description: "Un mismo origen contacta gran cantidad de destinos o puertos distintos.", why_it_matters: "Sondear muchos sitios es justo el objetivo de un escaneo." },
      { name: "Flujos ligeros", description: "Cada flujo es muy pequeño, normalmente un solo paquete.", why_it_matters: "No son comunicaciones reales, solo \"toques\" para ver quién responde." },
      { name: "Patrón repetitivo y disperso", description: "Los envíos se parecen mucho entre sí y se reparten por muchos destinos.", why_it_matters: "El tráfico legítimo rara vez tiene esa forma tan uniforme y dispersa." },
      { name: "Se descarta el DNS", description: "Se aparta el tráfico DNS (las consultas de nombres de Internet, que también usan UDP por el puerto 53).", why_it_matters: "Evita confundir consultas normales con un escaneo." },
    ],
    detection_steps: [
      "Quedarse con el tráfico UDP y descartar el DNS normal (puerto 53).",
      "Agrupar por origen y contar cuántos destinos o puertos distintos contacta.",
      "Comprobar que los flujos son mínimos (un paquete) y repetitivos.",
      "Si un origen dispara muchos mensajes ligeros a muchos destinos, marcarlo como escaneo UDP.",
    ],
    rule_pseudocode:
`# Escaneo basado en UDP
if protocol == "UDP" and many_destinations and light_flows:
    attack = "udp_scan"`,
    validation_context:
      "Bien validado en la semana de origen (august.week1). No se pudo evaluar fuera porque este ataque no aparece en las semanas adicionales disponibles; su generalización queda como trabajo futuro.",
    defense_explanation:
      "El escaneo UDP se reconoce por su forma: muchos mensajes pequeños y repetidos hacia muchos destinos. Funciona muy bien donde tenemos datos, aunque aún no se ha podido probar en otras semanas.",
  },

  "dos": {
    plain_explanation:
      "El detector marca un ataque de denegación de servicio cuando ve una gran cantidad de tráfico concentrándose contra un mismo servicio, como si quisiera saturarlo hasta dejarlo sin atender a usuarios legítimos.",
    technical_features: [
      { name: "Muchos flujos al mismo objetivo", description: "Gran número de conexiones dirigidas al mismo destino y puerto (el servicio atacado).", why_it_matters: "Saturar un servicio exige acumular mucho tráfico sobre él." },
      { name: "Concentración temporal", description: "Todo ese tráfico ocurre muy junto en el tiempo.", why_it_matters: "Un ataque de saturación llega en ráfaga, no repartido con calma." },
      { name: "Volumen o repetición elevada", description: "Se repiten muchos flujos parecidos o de alto volumen.", why_it_matters: "Es la señal de que se intenta agotar los recursos del servicio." },
      { name: "Servicio objetivo claro", description: "Hay un destino:puerto fijo que recibe casi todo el tráfico.", why_it_matters: "El ataque tiene una víctima concreta, no se dispersa como un escaneo." },
    ],
    detection_steps: [
      "Agrupar el tráfico por destino y puerto (el servicio) dentro de la ventana.",
      "Medir cuánto tráfico se concentra en ese servicio y en qué intervalo de tiempo.",
      "Comprobar que es concentración (todo hacia un punto) y no dispersión (muchos destinos).",
      "Si el tráfico está muy concentrado contra un servicio, marcarlo como denegación de servicio.",
    ],
    rule_pseudocode:
`# Inundación de un servicio (denegación de servicio)
if many_flows_to_same_target and traffic_concentrated:
    attack = "tcp_flood"`,
    validation_context:
      "Validado en UGR'16. Es una familia parcial: la frontera entre \"concentrar tráfico en un servicio\" (DoS) y \"repartir tráfico entre muchos destinos\" (escaneo distribuido) a veces se solapa y provoca confusiones.",
    defense_explanation:
      "La denegación de servicio se reconoce porque el tráfico se concentra contra una sola víctima. La dificultad está en distinguirla de un escaneo repartido, que visualmente se parece.",
  },

  "nerisbotnet": {
    plain_explanation:
      "El detector busca varios equipos que se comportan casi igual al mismo tiempo, como si los manejara una misma mano. Eso sugiere una red de bots: un conjunto de equipos infectados y controlados a distancia que actúan coordinados.",
    technical_features: [
      { name: "Varios orígenes", description: "Muchas máquinas distintas participan en la actividad.", why_it_matters: "Una red de bots, por definición, son muchos equipos." },
      { name: "Comportamiento repetido", description: "Esas máquinas generan flujos con tamaños y tiempos casi idénticos.", why_it_matters: "Si actúan igual, probablemente las controla el mismo programa." },
      { name: "Servicios o destinos comunes", description: "Tienden a contactar los mismos destinos o servicios.", why_it_matters: "Apunta a un control central que les da las mismas órdenes." },
      { name: "Actividad repartida en el tiempo", description: "La coordinación se ve al observar intervalos de tiempo, no un solo instante.", why_it_matters: "La pista no está en un flujo aislado, sino en el patrón conjunto." },
      { name: "Niveles de confianza alto/bajo", description: "Idea futura: separar los casos muy claros de los dudosos.", why_it_matters: "Permitiría dar alertas más fiables sin perder cobertura." },
    ],
    detection_steps: [
      "Dividir la ventana en pequeños intervalos de tiempo.",
      "En cada intervalo, buscar grupos de orígenes con flujos casi idénticos (mismo tamaño, mismo destino).",
      "Si varios equipos coinciden de forma repetida, tratarlo como comportamiento coordinado.",
      "Algunos servicios típicos de control suman confianza, pero no son la única regla.",
      "Marcar el grupo como actividad de red de bots coordinada.",
    ],
    rule_pseudocode:
`# Actividad coordinada tipo red de bots
if many_sources and repeated_behavior and shared_services:
    attack = "coordinated_botnet"`,
    validation_context:
      "Validado en UGR'16, pero es una familia difícil: la coordinación no siempre se ve con claridad solo con metadatos de red. Si cada equipo actúa por separado, no hay coordinación observable y el ataque se escapa.",
    defense_explanation:
      "Una red de bots se delata cuando muchos equipos hacen lo mismo a la vez. El reto es que NetFlow no siempre muestra esa coordinación, así que es una de las familias más complicadas.",
  },

  "anomaly-sshscan": {
    plain_explanation:
      "El detector marca un escaneo SSH cuando ve un mismo origen que intenta contactar con muchísimos destinos distintos por SSH (el servicio para administrar máquinas a distancia, que normalmente usa el puerto 22). A esa apertura \"en abanico\" de un origen hacia muchos destinos se le llama fan-out.",
    technical_features: [
      { name: "Tráfico hacia el puerto 22", description: "El tráfico va al puerto 22, el que usa SSH (servicio para conectarse y administrar una máquina de forma remota).", why_it_matters: "Un escaneo SSH busca máquinas que tengan ese servicio abierto." },
      { name: "Muchos destinos distintos (fan-out)", description: "Un mismo origen contacta una gran cantidad de destinos diferentes. Eso es el \"fan-out\": una máquina que se abre en abanico hacia muchas otras.", why_it_matters: "Probar muchos destinos es la esencia de un escaneo horizontal." },
      { name: "Muchos intentos SSH", description: "Se acumulan muchos intentos de conexión SSH desde ese origen.", why_it_matters: "Un uso normal de SSH va a unas pocas máquinas conocidas, no a cientos." },
      { name: "Conexiones ligeras o incompletas", description: "Los intentos son breves y muchos no llegan a completar una sesión real.", why_it_matters: "El atacante solo quiere ver quién responde, no trabajar en la máquina." },
      { name: "Patrón global por origen", description: "La clave es mirar todo lo que hace cada origen en conjunto, no flujo a flujo. El ataque es lento y disperso (pocos intentos cada vez para no llamar la atención).", why_it_matters: "Solo se ve sumando la actividad de ese origen; mirando un flujo aislado pasa inadvertido." },
    ],
    detection_steps: [
      "Quedarse con los flujos dirigidos al puerto 22 (SSH).",
      "Agruparlos por máquina de origen.",
      "Contar a cuántos destinos distintos intenta llegar cada origen.",
      "Si un origen intenta contactar con muchísimos destinos por SSH, marcarlo como escaneo horizontal SSH.",
    ],
    rule_pseudocode:
`# Escaneo SSH: un origen que prueba muchos destinos por el puerto 22
ssh_flows = flows where destination_port == 22
grouped   = group ssh_flows by source

if source_contacts_many_ssh_destinations:
    attack = "ssh_horizontal_scan"`,
    validation_context:
      "La versión v3 fallaba porque solo miraba el contexto cercano de cada flujo (demasiado local) y no veía el conjunto: precisión 0, recall 0, F1 0. La v5 añade un tercer pase que agrupa por origen y sí lo detecta. Medido en april.week2: precisión 0,999, recall 0,907 y F1 0,951 (el F1 combina precisión y recall en un único número).",
    defense_explanation:
      "Es el mejor ejemplo del proyecto: con una mirada local el ataque era invisible (0 de detección); al mirar el comportamiento global de cada origen pasa a detectarse casi perfectamente. Demuestra que la clave es el contexto, no conocer IPs concretas.",
  },

  "anomaly-spam": {
    plain_explanation:
      "El detector intenta marcar el spam cuando ve mucho tráfico hacia servicios de correo, pero aquí choca con un límite honesto: mirando solo los metadatos de red (puertos, tamaños y tiempos, sin el contenido del mensaje), el correo basura se parece demasiado al correo normal.",
    technical_features: [
      { name: "Tráfico al puerto 25 (SMTP)", description: "El tráfico va al puerto 25, usado por SMTP (el protocolo para enviar correo).", why_it_matters: "Una campaña de spam envía correo, así que pasa por ahí." },
      { name: "Muchos destinos de correo", description: "Un origen contacta muchos servidores de correo distintos.", why_it_matters: "Enviar a muchos destinatarios es lo propio de una campaña masiva." },
      { name: "Repetición", description: "Los envíos se repiten con tamaños parecidos.", why_it_matters: "El envío automatizado tiende a ser uniforme." },
      { name: "Concentración temporal", description: "Los envíos se agrupan en el tiempo.", why_it_matters: "Las campañas suelen llegar en oleadas." },
    ],
    detection_steps: [
      "Quedarse con el tráfico hacia el puerto 25 (correo SMTP).",
      "Agrupar por origen y ver cuántos servidores de correo contacta.",
      "Buscar repetición y concentración en el tiempo.",
      "Si hay indicios, marcarlo como posible campaña SMTP, pero con baja confianza.",
      "Si no hay evidencia suficiente, no marcar nada: el correo normal se parece demasiado.",
    ],
    rule_pseudocode:
`# Campaña SMTP (caso exploratorio, baja confianza)
if destination_port == 25 and many_mail_destinations:
    possible_attack = "smtp_campaign_low_confidence"
else:
    not_enough_evidence`,
    validation_context:
      "Caso exploratorio y no resuelto: ni siquiera con gran volumen de spam se logra separarlo del correo legítimo, porque NetFlow no contiene el contenido del mensaje (solo metadatos como puertos, tamaños y tiempos).",
    defense_explanation:
      "El spam marca el límite honesto del proyecto: sin ver el contenido del correo, el tráfico de spam y el legítimo son casi iguales. Se deja documentado como caso no resuelto.",
  },
};

// Comparación de modelos ML clásicos (F1 macro), SIN Random Forest en la vista principal.
// F1 macro = media del F1 entre las 8 clases (incluye tráfico normal y blacklist; no incluye SSH Scan),
// medido sobre una muestra equilibrada (~2778 ejemplos por clase). Fuente: ml_baseline_summary.csv.
export const ML_COMPARISON = [
  { name: "KNN", f1: 0.877, note: "vecinos más cercanos" },
  { name: "MLP", f1: 0.803, note: "red neuronal sencilla" },
  { name: "SVM", f1: 0.660, note: "vectores soporte" },
  { name: "Logistic Regression", f1: 0.615, note: "regresión logística" },
];

// F1 por familia de la v5, calculado de los summaries reales (F1 = 2·P·R/(P+R)).
// Cada familia se mide en la semana donde realmente aparece (con suficientes ejemplos):
//   núcleo en august.week1 · SSH Scan en april.week2.
// Fuentes: flow_level_detection_summary_v5_integrated.csv (week1) y
//          generalization_summary_v5_integrated_april_week2.csv (sshscan).
export const V5_FAMILY = [
  { name: "anomaly-udpscan", f1: 0.968, p: 0.938, r: 1.000, dataset: "august.week1" },
  { name: "anomaly-sshscan", f1: 0.951, p: 0.999, r: 0.907, dataset: "april.week2" },
  { name: "scan11", f1: 0.864, p: 0.763, r: 0.997, dataset: "august.week1" },
  { name: "scan44", f1: 0.779, p: 0.762, r: 0.796, dataset: "august.week1" },
  { name: "dos", f1: 0.519, p: 0.554, r: 0.488, dataset: "august.week1" },
  { name: "nerisbotnet", f1: 0.076, p: 0.269, r: 0.044, dataset: "august.week1" },
  { name: "anomaly-spam", f1: 0.000, p: 0.000, r: 0.000, dataset: "august.week1" },
];

// Detección binaria (ataque/normal) de la v5 en week1 — contexto adicional, no es el F1 por familia.
export const V5_BINARY = { f1: 0.957, recall: 0.991, dataset: "august.week1" };
