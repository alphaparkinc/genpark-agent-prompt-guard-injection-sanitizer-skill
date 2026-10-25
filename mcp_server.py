import sys
import json
import re

class PromptGuard:
    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)",
        r"(?i)system\s*:\s*you\s+are\s+now",
        r"(?i)disregard\s+all\s+guidelines",
        r"(?i)jailbreak",
        r"(?i)<script[\s>]",
        r"(?i)drop\s+table\b",
        r"(?i)override\s+system\s+prompt",
        r"(?i)you\s+must\s+now\s+act\s+as",
        r"(?i)DAN\s+mode\b"
    ]

    @classmethod
    def sanitize(cls, text):
        detected = []
        for pat in cls.INJECTION_PATTERNS:
            matches = re.findall(pat, text)
            if matches:
                detected.append(pat)

        is_safe = len(detected) == 0
        cleaned = text
        for pat in cls.INJECTION_PATTERNS:
            cleaned = re.sub(pat, "[BLOCKED_INJECTION]", cleaned)

        return {
            "is_safe": is_safe,
            "detected_threats_count": len(detected),
            "threat_patterns": detected,
            "sanitized_text": cleaned
        }

def handle_rpc(request):
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params", {})

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "sanitize_prompt",
                        "description": "Inspect and sanitize prompt text from injection or jailbreak payloads.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"}
                            },
                            "required": ["text"]
                        }
                    },
                    {
                        "name": "inspect_threats",
                        "description": "Detect whether input contains malicious jailbreak patterns without altering text.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"}
                            },
                            "required": ["text"]
                        }
                    }
                ]
            }
        }

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        text = args.get("text", "")
        res = PromptGuard.sanitize(text)

        if name == "sanitize_prompt":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        elif name == "inspect_threats":
            report = {
                "is_safe": res["is_safe"],
                "threat_count": res["detected_threats_count"],
                "threats": res["threat_patterns"]
            }
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(report)}]}}

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}

if __name__ == "__main__":
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_rpc(req)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}}) + "\n")
            sys.stdout.flush()
