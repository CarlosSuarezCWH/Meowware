"""
Simple Explainer - Traduce términos técnicos a lenguaje simple
v19.0 - Hace los reportes comprensibles para no técnicos

Meowware - Developed by Carlos Mancera
"""
from typing import Dict, Any, Optional
from ..core.models import Severity


class SimpleExplainer:
    """Traduce términos técnicos a lenguaje simple y claro"""
    
    # Diccionario de términos técnicos a explicaciones simples
    TERMS = {
        "SQL Injection": {
            "simple": "Inyección SQL",
            "explanation": "Es como si alguien pudiera escribir comandos maliciosos en un formulario y hacer que la base de datos los ejecute. Es como darle las llaves de tu casa a un extraño.",
            "analogy": "Imagina que tienes una caja fuerte (base de datos) y alguien puede escribir instrucciones en el teclado que la caja fuerte ejecuta sin verificar quién es. Eso es peligroso.",
            "impact_simple": "Un atacante podría robar, modificar o eliminar toda la información de tu base de datos."
        },
        "XSS": {
            "simple": "Cross-Site Scripting",
            "explanation": "Permite que un atacante inyecte código malicioso en tu sitio web que se ejecuta en el navegador de otros usuarios.",
            "analogy": "Es como si alguien pudiera poner un letrero falso en tu tienda que engaña a tus clientes y les roba información cuando lo leen.",
            "impact_simple": "Los visitantes de tu sitio podrían ser engañados para entregar información personal o ser redirigidos a sitios maliciosos."
        },
        "WAF": {
            "simple": "Firewall de Aplicación Web",
            "explanation": "Es un sistema de seguridad que protege tu sitio web bloqueando ataques comunes antes de que lleguen a tu servidor.",
            "analogy": "Es como un guardia de seguridad en la entrada de un edificio que revisa a todos y bloquea a personas sospechosas.",
            "impact_simple": "Sin WAF, tu sitio está más expuesto a ataques automatizados."
        },
        "CVE": {
            "simple": "Vulnerabilidad Conocida",
            "explanation": "Es un número único que identifica una vulnerabilidad de seguridad conocida públicamente.",
            "analogy": "Es como un número de identificación de un problema de seguridad que todos los expertos conocen.",
            "impact_simple": "Indica que hay un problema de seguridad conocido que necesita ser corregido."
        },
        "SSL/TLS": {
            "simple": "Conexión Segura",
            "explanation": "Es el sistema que encripta la comunicación entre el navegador del usuario y tu servidor.",
            "analogy": "Es como enviar una carta en un sobre cerrado en lugar de una postal. Solo el destinatario puede leerla.",
            "impact_simple": "Sin esto, cualquier persona que intercepte la comunicación puede ver toda la información."
        },
        "WordPress": {
            "simple": "Sistema de Gestión de Contenidos",
            "explanation": "Es una plataforma popular para crear y gestionar sitios web.",
            "analogy": "Es como un sistema operativo para sitios web, pero necesita mantenimiento constante.",
            "impact_simple": "Si no se mantiene actualizado, puede tener vulnerabilidades conocidas."
        },
        "Plugin": {
            "simple": "Extensión o Complemento",
            "explanation": "Son programas pequeños que agregan funcionalidades a tu sitio web.",
            "analogy": "Es como una aplicación que instalas en tu teléfono para agregar nuevas funciones.",
            "impact_simple": "Los plugins desactualizados o mal programados pueden tener agujeros de seguridad."
        },
        "User Enumeration": {
            "simple": "Enumeración de Usuarios",
            "explanation": "Es cuando un atacante puede descubrir los nombres de usuario de tu sitio web.",
            "analogy": "Es como si alguien pudiera ver la lista de empleados de tu empresa sin permiso.",
            "impact_simple": "Con los nombres de usuario, un atacante puede intentar adivinar contraseñas más fácilmente."
        },
        "Exposed": {
            "simple": "Expuesto o Público",
            "explanation": "Significa que algo que debería estar protegido es accesible públicamente en internet.",
            "analogy": "Es como dejar la puerta de tu casa abierta cuando debería estar cerrada con llave.",
            "impact_simple": "Cualquier persona en internet puede acceder a esta información o servicio."
        },
        "Vulnerability": {
            "simple": "Debilidad de Seguridad",
            "explanation": "Es un punto débil en tu sistema que un atacante podría explotar para causar daño.",
            "analogy": "Es como una ventana rota en tu casa que permite que entren ladrones.",
            "impact_simple": "Necesita ser reparada para evitar que alguien la use en tu contra."
        }
    }
    
    @staticmethod
    def explain_term(term: str) -> Dict[str, str]:
        """Obtiene explicación simple de un término técnico"""
        for key, value in SimpleExplainer.TERMS.items():
            if key.lower() in term.lower():
                return value
        return {
            "simple": term,
            "explanation": "Término técnico de seguridad",
            "analogy": "",
            "impact_simple": ""
        }
    
    @staticmethod
    def simplify_description(description: str) -> str:
        """Simplifica una descripción técnica"""
        # Reemplazar términos técnicos comunes
        replacements = {
            "SQL Injection": "Inyección de código malicioso en la base de datos",
            "XSS": "Ejecución de código malicioso en el navegador",
            "WAF": "Sistema de protección",
            "CVE-": "Vulnerabilidad conocida ",
            "SSL/TLS": "Conexión segura",
            "exposed": "expuesto públicamente",
            "vulnerability": "debilidad de seguridad",
            "exploit": "aprovechar",
            "payload": "código malicioso",
            "enumeration": "descubrimiento de información",
            "misconfiguration": "configuración incorrecta",
            "authentication": "verificación de identidad",
            "authorization": "permisos de acceso"
        }
        
        simplified = description
        for tech_term, simple_term in replacements.items():
            simplified = simplified.replace(tech_term, simple_term)
            simplified = simplified.replace(tech_term.lower(), simple_term.lower())
        
        return simplified
    
    @staticmethod
    def get_severity_explanation(severity: Severity) -> Dict[str, str]:
        """Explica qué significa cada nivel de severidad"""
        explanations = {
            Severity.CRITICAL: {
                "simple": "🔴 CRÍTICO - Acción Inmediata Requerida",
                "explanation": "Este problema es extremadamente peligroso y necesita ser corregido de inmediato, preferiblemente hoy mismo.",
                "analogy": "Es como tener una puerta principal abierta con un cartel que dice 'Bienvenidos'. Cualquiera puede entrar.",
                "timeline": "Corregir en las próximas 24-48 horas",
                "business_impact": "Riesgo muy alto de pérdida de datos, interrupción del servicio o acceso no autorizado completo al sistema."
            },
            Severity.HIGH: {
                "simple": "🟠 ALTO - Prioridad Alta",
                "explanation": "Este problema es serio y debe ser corregido pronto, dentro de la próxima semana.",
                "analogy": "Es como tener una ventana rota en tu casa. No es tan urgente como una puerta abierta, pero sigue siendo peligroso.",
                "timeline": "Corregir en los próximos 7 días",
                "business_impact": "Riesgo significativo de acceso no autorizado o pérdida de información sensible."
            },
            Severity.MEDIUM: {
                "simple": "🟡 MEDIO - Atención Recomendada",
                "explanation": "Este problema debe ser corregido, pero no es urgente. Puede esperar hasta el próximo ciclo de actualizaciones.",
                "analogy": "Es como tener una cerradura que funciona pero es un poco débil. Funciona, pero sería mejor mejorarla.",
                "timeline": "Corregir en los próximos 30 días",
                "business_impact": "Riesgo moderado que podría convertirse en un problema mayor si no se atiende."
            },
            Severity.LOW: {
                "simple": "🟢 BAJO - Mejora Recomendada",
                "explanation": "Este es un problema menor que no representa un riesgo inmediato, pero sería bueno corregirlo cuando sea posible.",
                "analogy": "Es como tener una pequeña grieta en una pared. No es peligroso, pero sería mejor repararla.",
                "timeline": "Corregir en los próximos 90 días",
                "business_impact": "Riesgo bajo, principalmente relacionado con mejores prácticas de seguridad."
            },
            Severity.INFO: {
                "simple": "ℹ️ INFORMATIVO - Solo Información",
                "explanation": "Esto no es un problema de seguridad, solo información útil sobre tu sistema.",
                "analogy": "Es como un informe del estado de tu casa. No hay problemas, solo información.",
                "timeline": "No requiere acción",
                "business_impact": "Sin impacto en la seguridad, solo información para referencia."
            }
        }
        
        return explanations.get(severity, explanations[Severity.INFO])
    
    @staticmethod
    def format_finding_for_non_tech(finding_title: str, finding_description: str, 
                                   severity: Severity, recommendation: str) -> Dict[str, Any]:
        """Formatea un finding para que sea comprensible por no técnicos"""
        severity_info = SimpleExplainer.get_severity_explanation(severity)
        
        # Simplificar descripción
        simple_description = SimpleExplainer.simplify_description(finding_description)
        
        # Buscar términos técnicos y agregar explicaciones
        explained_terms = []
        for term in SimpleExplainer.TERMS.keys():
            if term.lower() in finding_title.lower() or term.lower() in finding_description.lower():
                term_info = SimpleExplainer.explain_term(term)
                explained_terms.append({
                    "term": term,
                    "simple": term_info["simple"],
                    "explanation": term_info["explanation"],
                    "analogy": term_info.get("analogy", ""),
                    "impact": term_info.get("impact_simple", "")
                })
        
        return {
            "title_simple": SimpleExplainer.simplify_description(finding_title),
            "description_simple": simple_description,
            "severity_info": severity_info,
            "explained_terms": explained_terms,
            "recommendation_simple": SimpleExplainer.simplify_description(recommendation),
            "what_this_means": f"En términos simples: {severity_info['explanation']}",
            "why_it_matters": severity_info.get("business_impact", ""),
            "when_to_fix": severity_info.get("timeline", "")
        }


