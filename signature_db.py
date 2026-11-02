"""
signature_db.py

Provides a centralized function to initialize and populate the signature
database used for detecting known attack patterns in packet payloads.
"""

from custom_hashmap import CustomHashMap

def setup_signature_database() -> CustomHashMap:
    """Initializes the signature database with known attack patterns."""
    db = CustomHashMap()
    signatures = {
        "<script>": "XSS", "' OR 1=1 --": "SQL Injection", "DROP TABLE": "SQL Injection",
        "eval(": "Code Injection", "base64_decode": "PHP Code Injection",
        "cmd.exe": "Command Injection", "rm -rf": "Command Injection",
        "../../": "Path Traversal", "union select": "SQL Injection", "alert(": "XSS"
    }
    for signature, attack_type in signatures.items():
        db.insert(signature, attack_type)
    return db