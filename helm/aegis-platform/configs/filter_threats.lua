local has_uuid, uuid = pcall(require, "uuid")
if not has_uuid or not uuid then
    -- Simple UUID generator fallback if the library is not present
    uuid = {
        new = function()
            local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
            return string.gsub(template, "[xy]", function(c)
                local v = (c == "x") and math.random(0, 0xf) or math.random(8, 0xb)
                return string.format("%x", v)
            end)
        end
    }
end

-- Helper to convert string to lowercase for case-insensitive matching
local function to_lower(str)
    if not str then return "" end
    return string.lower(str)
end

-- Helper to URL decode strings (useful for HTTP paths)
local function url_decode(str)
    if not str then return "" end
    str = string.gsub(str, "+", " ")
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return str
end

-- Helper to safely search using Lua patterns
local function pattern_match(text, pattern)
    if not text or not pattern then return false end
    return string.find(text, pattern) ~= nil
end

local function has_unescaped_quote(text)
    if not text then return false end
    for i = 1, #text do
        local c = string.sub(text, i, i)
        if c == '"' or c == "'" then
            if i == 1 or string.sub(text, i - 1, i - 1) ~= "\\" then
                return true
            end
        end
    end
    return false
end

function detect_threats(tag, timestamp, record)
    local raw_payload = ""
    local client_ip = "127.0.0.1"
    local source_service = "NginxGateway"

    if tag == "nginx.access" then
        raw_payload = record["path"] or ""
        client_ip = record["remote"] or "127.0.0.1"
        source_service = "NginxGateway"
    elseif tag == "be.backend" then
        raw_payload = record["log"] or ""
        client_ip = "127.0.0.1"
        source_service = "BankBackend"
    else
        return 0, timestamp, record
    end

    if raw_payload == "" then
        return 0, timestamp, record
    end

    local payload = url_decode(raw_payload)
    local payload_lower = to_lower(payload)
    local threat_detected = false
    local attack_type = ""
    local description = ""

    -- 1. Universal ChatML/Tokens: <|.*?|> (Lua pattern: "<|.-|>")
    if pattern_match(payload, "<|.-|>") then
        threat_detected = true
        attack_type = "CHATML_TOKEN_INJECTION"
        description = "ChatML token boundary wrapper detected in payload."
    
    -- 2. Llama/Mistral Tags: /?INST or similar tags (Lua equivalents for \[/?INST\], \[/?SYS\], <<SYS>>)
    elseif pattern_match(payload_lower, "%[inst%]") or pattern_match(payload_lower, "%[/inst%]") or
           pattern_match(payload_lower, "%[sys%]") or pattern_match(payload_lower, "%[/sys%]") or
           pattern_match(payload_lower, "<<sys>>") then
        threat_detected = true
        attack_type = "LLM_TAG_INJECTION"
        description = "Instruction/System framing tags (Llama/Mistral) detected in payload."
    
    -- 3. XML/System Framing: <system>...</system>, opening <system>, or sys-prompt markers
    elseif pattern_match(payload_lower, "<system[^>]*>.-</system>") or
           pattern_match(payload_lower, "<system[^>]*>") or
           pattern_match(payload_lower, "sys%-prompt") then
        threat_detected = true
        attack_type = "SYSTEM_FRAMING_INJECTION"
        description = "XML-style System framing or system prompts detected in payload."

    -- 4. Instruction Override (Case Insensitive): ignore, forget, override, reset, clear
    elseif pattern_match(payload_lower, "%f[%a]ignore%f[%A]") or 
           pattern_match(payload_lower, "%f[%a]forget%f[%A]") or 
           pattern_match(payload_lower, "%f[%a]override%f[%A]") or 
           pattern_match(payload_lower, "%f[%a]reset%f[%A]") or 
           pattern_match(payload_lower, "%f[%a]clear%f[%A]") then
        threat_detected = true
        attack_type = "INSTRUCTION_OVERRIDE"
        description = "Potential instruction override keywords (ignore/forget/override/reset/clear) detected."

    -- 5. Persona Hijacking (Case Insensitive): "you are now", "act as", "simulate", "roleplay"
    elseif pattern_match(payload_lower, "you%s+are%s+now") or 
           pattern_match(payload_lower, "act%s+as") or 
           pattern_match(payload_lower, "%f[%a]simulate%f[%A]") or 
           pattern_match(payload_lower, "%f[%a]roleplay%f[%A]") then
        threat_detected = true
        attack_type = "PERSONA_HIJACKING"
        description = "Potential persona hijacking instruction patterns ('you are now' / 'act as' / 'simulate') detected."

    -- 6. Output Forcing (Case Insensitive): "output only", "print only", "only respond"
    elseif pattern_match(payload_lower, "output%s+only") or 
           pattern_match(payload_lower, "print%s+only") or 
           pattern_match(payload_lower, "only%s+respond") then
        threat_detected = true
        attack_type = "OUTPUT_FORCING"
        description = "Adversarial output forcing command pattern detected."

    -- 7. System Deactivation (Case Insensitive): threat_detected: false, confidence_score: 0
    elseif pattern_match(payload_lower, "threat_detected%s*:%s*false") or 
           pattern_match(payload_lower, "confidence_score%s*:%s*0") then
        threat_detected = true
        attack_type = "SYSTEM_DEACTIVATION"
        description = "Attempt to bypass system security flags (threat_detected: false / confidence_score: 0) detected."

    -- 8. Markdown Code Blocks: triple-or-more backticks with optional language marker
    elseif pattern_match(payload, "```+%s*[%w_-]*") then
        threat_detected = true
        attack_type = "MARKDOWN_CODE_BLOCK"
        description = "Active markdown script/code block invocation detected."

    -- 9. JSON Escaping: unescaped quotes matching PCRE intent (?<!\\)" or (?<!\\)'
    elseif has_unescaped_quote(payload) then
        threat_detected = true
        attack_type = "JSON_ESCAPING"
        description = "Potential JSON structure escaping sequence detected."

    -- 10. JNDI / Log4j Style: ${jndi:...} or ${[a-z:]+} lookup expressions
    elseif pattern_match(payload_lower, "%${jndi:[a-z0-9]+://.-}") or pattern_match(payload_lower, "%${[a-z:]+}") then
        threat_detected = true
        attack_type = "JNDI_LOG4J_LOOKUP"
        description = "Active JNDI lookup expression or system environment expansion detected."
    end

    if threat_detected then
        -- Format exactly as the Go Consumer's ingestSecurityEvent expects
        -- We will enrich this record with threat indicators so that rewrite_tag filter can match it
        record["threat_detected"] = "true"
        record["eventId"] = uuid.new()
        record["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z")
        record["attackType"] = attack_type
        record["endpoint"] = (tag == "nginx.access") and record["path"] or "/api"
        record["payload"] = payload
        record["status"] = "BLOCKED"
        record["clientIp"] = client_ip
        record["description"] = description
        record["sourceService"] = source_service

        return 1, timestamp, record
    end

    return 0, timestamp, record
end
