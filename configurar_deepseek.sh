#!/bin/bash
# Script rápido para configurar DeepSeek API en Meowware

echo "🔧 Configuración de DeepSeek API para Meowware"
echo "================================================"
echo ""

# Verificar si ya está configurado
if [ ! -z "$DEEPSEEK_API_KEY" ]; then
    echo "✅ DEEPSEEK_API_KEY ya está configurada en este terminal"
    echo "   Valor: ${DEEPSEEK_API_KEY:0:10}... (oculto)"
    echo ""
    read -p "¿Deseas cambiar la API key? (s/n): " cambiar
    if [ "$cambiar" != "s" ]; then
        echo "Configuración actual mantenida."
        exit 0
    fi
fi

echo "1. Obtén tu API key en: https://platform.deepseek.com/api_keys"
echo ""
read -p "Ingresa tu DeepSeek API Key: " api_key

if [ -z "$api_key" ]; then
    echo "❌ API key vacía. Abortando."
    exit 1
fi

# Configurar variables de entorno para esta sesión
export DEEPSEEK_API_KEY="$api_key"
export LLM_PROVIDER="deepseek"

echo ""
echo "✅ Variables de entorno configuradas para esta sesión:"
echo "   DEEPSEEK_API_KEY=${api_key:0:10}... (oculto)"
echo "   LLM_PROVIDER=deepseek"
echo ""
echo "📝 Para hacerlo permanente, agrega estas líneas a tu ~/.bashrc o ~/.zshrc:"
echo ""
echo "export DEEPSEEK_API_KEY=\"$api_key\""
echo "export LLM_PROVIDER=\"deepseek\""
echo ""
echo "O crea un archivo .env en el directorio del proyecto con:"
echo "DEEPSEEK_API_KEY=$api_key"
echo "LLM_PROVIDER=deepseek"
echo ""
echo "🚀 Ahora puedes ejecutar: python3 main.py ejemplo.com --debug"


