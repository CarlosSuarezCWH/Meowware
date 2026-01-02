# 🐱 Meowware v1.0 "Tulipán"

**Plataforma Profesional de Auditoría de Seguridad con Inteligencia Artificial**

Meowware es una herramienta avanzada de auditoría de seguridad que combina técnicas de pentesting automatizado con inteligencia artificial para realizar análisis exhaustivos de infraestructura, aplicaciones web y servicios.

## ✨ Características Principales

### 🧠 Inteligencia Artificial Integrada
- **Motor Cognitivo**: Utiliza DeepSeek API para decisiones inteligentes durante la auditoría
- **Análisis Contextual**: Adapta la estrategia de auditoría basándose en tecnologías detectadas
- **Sistema de Hipótesis**: Genera y valida hipótesis de seguridad automáticamente
- **Detección de Anomalías**: Identifica patrones sospechosos y comportamientos inusuales

### 🔍 Reconocimiento Avanzado
- **Detección de Subdominios**: Integración con amass, crt.sh y múltiples fuentes
- **Escaneo de Puertos**: Nmap con detección agresiva de servicios y versiones
- **Detección de Tecnologías**: CMS, frameworks, bases de datos, sistemas operativos
- **Análisis DNS**: Verificación de transferencias de zona, DNSSEC, resolvers abiertos

### 🛡️ Auditoría de Seguridad
- **Vulnerabilidades Web**: SQL Injection, XSS, LFI/RFI, SSRF, y más
- **Análisis SSL/TLS**: TestSSL, SSLScan para configuración de cifrado
- **Escaneo de CMS**: WordPress, Joomla, Drupal con herramientas especializadas
- **Auditoría de APIs**: REST, GraphQL, SOAP
- **Análisis de Headers**: Security headers, CORS, CSP

### 📊 Reportes Profesionales
- **Informe Ejecutivo**: Resumen de alto nivel con impacto de negocio
- **Dashboard Interactivo**: Visualización dinámica de hallazgos y métricas
- **Reporte Técnico**: Detalles completos con evidencia, CVEs y recomendaciones
- **Deduplicación Inteligente**: Consolidación automática de hallazgos similares

### 🎯 Características Avanzadas
- **Sistema de Perfiles**: Perfiles de auditoría por tipo de tecnología
- **WAF Bypass**: Técnicas de evasión automáticas para Cloudflare y otros WAFs
- **Aprendizaje Continuo**: Sistema de aprendizaje basado en escaneos previos
- **Paralelización Inteligente**: Auditoría simultánea de múltiples hosts
- **Validación de Hallazgos**: Clasificación precisa (POTENTIAL, LIKELY, CONFIRMED)

## 🚀 Instalación

### Requisitos Previos

```bash
# Python 3.8 o superior
python3 --version

# Herramientas de seguridad (se instalan automáticamente)
# - nmap
# - nuclei
# - amass
# - wpscan (opcional)
# - sqlmap (opcional)
```

### Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/meowware.git
cd meowware

# Instalar dependencias Python
pip3 install -r requirements.txt

# Instalar herramientas de seguridad
chmod +x install_tools.sh
./install_tools.sh

# Configurar variables de entorno
cp env.example .env
# Editar .env y agregar tu DEEPSEEK_API_KEY
```

### Configuración de DeepSeek API

1. Obtén tu API key de [DeepSeek](https://platform.deepseek.com/)
2. Edita el archivo `.env`:
```bash
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=tu_api_key_aqui
```

## 📖 Uso

### Uso Básico

```bash
# Auditoría básica de un dominio
python3 main.py ejemplo.com

# Modo debug (más verboso)
python3 main.py ejemplo.com --debug

# Especificar profundidad de escaneo
python3 main.py ejemplo.com --depth deep
```

### Ejemplos de Uso

```bash
# Auditoría completa de un dominio
python3 main.py ejemplo.com

# Auditoría con salida detallada
python3 main.py ejemplo.com --debug

# Auditoría de múltiples objetivos (usando archivo)
python3 main.py -f targets.txt
```

## 📁 Estructura del Proyecto

```
meowware/
├── audit_system/
│   ├── core/              # Núcleo del sistema
│   │   ├── ai_client.py   # Cliente de IA (DeepSeek)
│   │   ├── orchestrator.py # Orquestador principal
│   │   └── models.py      # Modelos de datos
│   ├── intelligence/      # Módulos de inteligencia
│   │   ├── anomaly_detector.py
│   │   ├── audit_profiles.py
│   │   └── pattern_learner.py
│   ├── tools/            # Herramientas de auditoría
│   │   ├── nmap_runner.py
│   │   ├── vuln_scanners.py
│   │   └── web_exploitation.py
│   ├── reporting/         # Generación de reportes
│   │   ├── generator.py
│   │   ├── dashboard.py
│   │   └── executive_report.py
│   └── analysis/          # Análisis y correlación
│       ├── risk_scorer.py
│       └── correlation.py
├── main.py                # Punto de entrada
├── requirements.txt       # Dependencias Python
├── install_tools.sh       # Script de instalación
└── README.md             # Este archivo
```

## 🎨 Características Técnicas

### Motor de IA
- **Proveedor**: DeepSeek API (compatible con OpenAI)
- **Caché Inteligente**: Evita llamadas redundantes a la API
- **Fast-Path Decisions**: Decisiones automáticas sin IA cuando es posible
- **Fallback Inteligente**: Sistema basado en reglas cuando la IA no está disponible

### Arquitectura
- **Modular**: Diseño modular y extensible
- **Asíncrono**: Operaciones paralelas para mejor rendimiento
- **Escalable**: Soporta auditorías de múltiples hosts simultáneamente
- **Robusto**: Manejo de errores y recuperación automática

### Seguridad
- **No Destructivo**: Solo realiza pruebas de lectura cuando es posible
- **Rate Limiting**: Respeta límites de velocidad para evitar bloqueos
- **WAF Aware**: Detecta y adapta técnicas para evitar WAFs
- **Throttling Inteligente**: Ajusta velocidad según protección detectada

## 📊 Reportes

Los reportes se generan automáticamente en la carpeta `reports/`:

- **Executive Report**: `executive_report_[ID].html` - Resumen ejecutivo
- **Dashboard**: `dashboard_[ID].html` - Dashboard interactivo
- **Reporte Técnico**: `meowware_report.html` - Reporte completo

## 🔧 Configuración Avanzada

### Variables de Entorno

```bash
# .env
LLM_PROVIDER=deepseek              # Proveedor de IA
DEEPSEEK_API_KEY=tu_key            # API Key de DeepSeek
MAX_ITERATIONS=5                   # Iteraciones máximas por host
DEPTH=medium                       # Profundidad: quick, medium, deep
TIMEOUT=3600                       # Timeout en segundos
```

### Perfiles de Auditoría

Meowware incluye perfiles predefinidos para:
- WordPress
- Joomla/Drupal
- Aplicaciones Web Genéricas
- Servidores de Correo
- Infraestructura (SSH, DB, etc.)

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver `LICENSE` para más detalles.

## 👤 Autor

**Carlos Mancera**

- GitHub: [@tu-usuario](https://github.com/tu-usuario)
- Website: [carlosmancera.com](https://carlosmancera.com)

## 🙏 Agradecimientos

- DeepSeek por la API de IA
- Comunidad de seguridad por las herramientas open-source
- Todos los contribuidores que han ayudado a mejorar Meowware

## ⚠️ Disclaimer

Esta herramienta está diseñada únicamente para auditorías de seguridad autorizadas. El uso no autorizado de esta herramienta es ilegal. El autor no se hace responsable del mal uso de esta herramienta.

## 📈 Roadmap

- [ ] Soporte para más CMS y frameworks
- [ ] Integración con más herramientas de seguridad
- [ ] API REST para integraciones
- [ ] Plugin system para extensiones
- [ ] Integración con CI/CD
- [ ] Notificaciones (Slack, Telegram)
- [ ] Exportación a PDF

---

**Meowware v1.0 "Tulipán"** - Desarrollado con ❤️ por Carlos Mancera
