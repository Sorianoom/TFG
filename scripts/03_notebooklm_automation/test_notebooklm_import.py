"""
Prueba mínima para comprobar si notebooklm-py está instalado correctamente.

Uso:
python scripts/03_notebooklm_automation/test_notebooklm_import.py
"""

try:
    import notebooklm
    print("[OK] notebooklm importado correctamente")
    print("[INFO] Módulo:", notebooklm)
except Exception as e:
    print("[ERROR] No se pudo importar notebooklm")
    print(type(e).__name__, str(e))