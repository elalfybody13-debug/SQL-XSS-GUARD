import re

class SQLShield:
    def __init__(self):
        
        self.sql_rules = [
            {"name": "Boolean-Based Blind / Tautology", "pattern": r"(?i)('|\"|#|--)\s*(OR|AND)\s+.*=.*", "level": "High"},
            {"name": "Union-Based (In-Band)", "pattern": r"(?i)UNION\s+(ALL\s+)?SELECT", "level": "Critical"},
            {"name": "Time-Based Blind", "pattern": r"(?i)(WAITFOR\s+DELAY|SLEEP\s*\()", "level": "Critical"},
            {"name": "Out-of-Band (OOB) / System Commands", "pattern": r"(?i)(xp_cmdshell|LOAD_FILE|UTL_HTTP|DBMS_PIPE|INTO\s+OUTFILE)", "level": "Critical"},
            {"name": "Stored Procedure Injection", "pattern": r"(?i)(EXEC|EXECUTE)\s+(sp_|xp_)", "level": "High"},
            {"name": "Stacked Queries", "pattern": r";\s*(DROP|DELETE|UPDATE|TRUNCATE|INSERT)", "level": "Critical"},
            {"name": "Error-Based Probing (Comment Injection)", "pattern": r"(--|#|/\*)", "level": "Medium"}
        ]
        
        
        self.xss_rules = [
            {"name": "Basic Script Tag", "pattern": r"(?i)<script.*?>.*?</script.*?>", "level": "Critical"},
            {"name": "Event Handler (onerror/onload)", "pattern": r"(?i)(onerror|onload|onclick|onmouseover)\s*=", "level": "High"},
            {"name": "JavaScript Protocol", "pattern": r"(?i)javascript\s*:", "level": "High"},
            {"name": "HTML Overlay/Iframe", "pattern": r"(?i)<(iframe|object|embed|svg|img)", "level": "Medium"},
            {"name": "Alert/Prompt Injection", "pattern": r"(?i)(alert|prompt|confirm)\s*\(", "level": "High"}
        ]

    def scan(self, user_input):
        detected_threats = []
        clean_input = str(user_input).strip()
        
       
        for rule in self.sql_rules:
            if re.search(rule["pattern"], clean_input):
                detected_threats.append({"type": "SQLi", "attack_type": rule["name"], "risk_level": rule["level"]})
        
      
        for rule in self.xss_rules:
            if re.search(rule["pattern"], clean_input):
                detected_threats.append({"type": "XSS", "attack_type": rule["name"], "risk_level": rule["level"]})
        
        return detected_threats