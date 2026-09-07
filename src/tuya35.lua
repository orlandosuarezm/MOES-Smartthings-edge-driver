--[[
  tuya35.lua
  Protocolo Tuya LAN v3.5 (framing 0x00006699 + AES-128-GCM + negociación de
  sesión). Reemplaza al viejo tuya.lua (que era para v3.3/ECB) porque el
  termostato MOES BHT-002 real resultó hablar 3.5, no 3.3.

  Basado en el código fuente real de tinytuya (message_helper.py,
  XenonDevice.py, header.py) - no adivinado. Validado byte a byte contra
  una sesión real capturada del termostato (ver notas de validación al
  final del archivo, o el historial de la conversación de desarrollo).

  ESTRUCTURA DEL MENSAJE (todos los campos numéricos big-endian):
    prefix   (4 bytes)  = 0x00006699
    unknown  (2 bytes)  = 0x0000 (siempre cero en lo que enviamos)
    seqno    (4 bytes)  = número de secuencia, incrementa por mensaje
    cmd      (4 bytes)  = comando (ver CMD)
    length   (4 bytes)  = len(iv) + len(ciphertext) + len(tag) = 12+N+16
    iv        (12 bytes) = nonce GCM, aleatorio por mensaje
    ciphertext(N bytes)  = AES-128-GCM del payload (con header de versión
                            "3.5"+12 nulos antepuesto, salvo en comandos de
                            NO_HEADER_CMDS)
    tag       (16 bytes) = tag de autenticación GCM
    suffix    (4 bytes)  = 0x00009966

  El AAD (additional authenticated data) de GCM es siempre los bytes del
  header EXCLUYENDO el prefix: unknown+seqno+cmd+length (14 bytes).
--]]

local gcm = require "gcm"
local sha256 = require "sha256"

local tuya35 = {}

tuya35.CMD = {
    SESS_KEY_NEG_START  = 3,
    SESS_KEY_NEG_RESP   = 4,
    SESS_KEY_NEG_FINISH = 5,
    CONTROL_NEW         = 13,
    HEART_BEAT          = 9,
    DP_QUERY_NEW        = 16,
}

local PREFIX = 0x00006699
local SUFFIX = 0x00009966
local VERSION_HEADER = "3.5" .. string.rep("\0", 12) -- 15 bytes

-- Comandos que NO llevan el header de versión antepuesto al payload
-- (todos los demás sí lo llevan). Tomado de header.NO_PROTOCOL_HEADER_CMDS.
local NO_HEADER_CMDS = {
    [tuya35.CMD.DP_QUERY_NEW] = true,
    [tuya35.CMD.HEART_BEAT] = true,
    [tuya35.CMD.SESS_KEY_NEG_START] = true,
    [tuya35.CMD.SESS_KEY_NEG_RESP] = true,
    [tuya35.CMD.SESS_KEY_NEG_FINISH] = true,
}

local function pack_u32(n)
    return string.char((n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)
end

local function pack_u16(n)
    return string.char((n >> 8) & 0xFF, n & 0xFF)
end

local function unpack_u32(data, offset)
    local b1, b2, b3, b4 = string.byte(data, offset, offset + 3)
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
end

-- No hay CSPRNG en el sandbox de Edge; suficiente para un nonce de sesión
-- con nuestro propio dispositivo en LAN (no es un canal expuesto a un
-- adversario activo). Sembrar con os.time()+os.clock() en el llamador.
local function random_bytes(n)
    local out = {}
    for i = 1, n do out[i] = string.char(math.random(0, 255)) end
    return table.concat(out)
end
tuya35.random_bytes = random_bytes

-- Construye un mensaje wire completo cifrado con `key`.
-- cmd: código YA "override" (ej. 13 o 16, no el original 7/10).
-- payload: string plano (JSON, o los bytes crudos del nonce/hmac durante negociación).
-- iv: opcional, 12 bytes; si se omite se genera aleatorio (siempre debe omitirse
--     en producción; solo se pasa explícito para pruebas contra vectores reales).
function tuya35.build_message(key, seqno, cmd, payload, iv)
    payload = payload or ""
    if not NO_HEADER_CMDS[cmd] then
        payload = VERSION_HEADER .. payload
    end

    iv = iv or random_bytes(12)
    local unknown = pack_u16(0)
    local seqno_b = pack_u32(seqno)
    local cmd_b = pack_u32(cmd)
    local length = #payload + 16 + 12 -- payload cifrado (misma longitud) + tag(16) + iv(12)
    local length_b = pack_u32(length)

    local aad = unknown .. seqno_b .. cmd_b .. length_b
    local header = pack_u32(PREFIX) .. aad

    local ciphertext, tag = gcm.encrypt(key, iv, payload, aad)

    return header .. iv .. ciphertext .. tag .. pack_u32(SUFFIX)
end

-- Parsea un mensaje wire. Devuelve {seqno, cmd, payload=<bytes crudos
-- descifrados, SIN interpretar como JSON>} o nil, err.
function tuya35.parse_message(key, raw)
    if #raw < 18 then return nil, "mensaje demasiado corto" end

    local prefix = unpack_u32(raw, 1)
    if prefix ~= PREFIX then
        return nil, string.format("prefix inesperado: 0x%08X", prefix)
    end

    local seqno = unpack_u32(raw, 7)
    local cmd = unpack_u32(raw, 11)
    local length = unpack_u32(raw, 15)

    local body_start = 19
    if #raw < body_start - 1 + length + 4 then
        return nil, "datos insuficientes para el cuerpo declarado"
    end

    local body = string.sub(raw, body_start, body_start - 1 + length)
    if #body < 28 then return nil, "cuerpo demasiado corto (iv+tag)" end

    local iv = string.sub(body, 1, 12)
    local tag = string.sub(body, #body - 15, #body)
    local ciphertext = string.sub(body, 13, #body - 16)
    local aad = string.sub(raw, 5, 18)

    local plaintext, err = gcm.decrypt(key, iv, ciphertext, tag, aad)
    if not plaintext then
        return nil, "fallo de autenticación GCM: " .. tostring(err)
    end

    -- tinytuya siempre descarta los primeros 4 bytes (retcode) de todo
    -- mensaje 6699 recibido, sin condición (no_retcode=False siempre).
    if #plaintext >= 4 then
        plaintext = string.sub(plaintext, 5)
    end

    return { seqno = seqno, cmd = cmd, payload = plaintext }
end

-- Quita, si está presente, el header de versión "3.5"+12 nulos de un
-- payload de datos ya descifrado (y con el retcode ya quitado por
-- parse_message). Solo aplica a respuestas de comandos de datos.
function tuya35.strip_data_wrappers(payload)
    if string.sub(payload, 1, 3) == "3.5" then
        payload = string.sub(payload, 16)
    end
    return payload
end

-- ===== Negociación de sesión =====
-- session = { real_local_key, local_key, seqno, local_nonce, remote_nonce }

function tuya35.new_session(real_local_key)
    return {
        real_local_key = real_local_key,
        local_key = real_local_key,
        seqno = 1, -- el dispositivo rechaza seqno=0 como primer mensaje; confirmado con captura real
    }
end

-- Paso 1: cliente -> dispositivo. Genera un nonce local y arma el mensaje.
function tuya35.negotiate_step1(session)
    session.local_nonce = random_bytes(16)
    session.remote_nonce = nil
    session.local_key = session.real_local_key

    local msg = tuya35.build_message(session.local_key, session.seqno, tuya35.CMD.SESS_KEY_NEG_START, session.local_nonce)
    session.seqno = session.seqno + 1
    return msg
end

-- Paso 2: procesa la respuesta del dispositivo (remote_nonce + HMAC), valida,
-- y arma el mensaje de paso 3 (finish). Devuelve el mensaje a enviar, o nil+err.
function tuya35.negotiate_step2(session, raw_response)
    local parsed, err = tuya35.parse_message(session.local_key, raw_response)
    if not parsed then return nil, err end
    if parsed.cmd ~= tuya35.CMD.SESS_KEY_NEG_RESP then
        return nil, "comando de respuesta inesperado: " .. tostring(parsed.cmd)
    end

    local payload = parsed.payload
    if #payload < 48 then return nil, "respuesta de negociación demasiado corta" end

    session.remote_nonce = string.sub(payload, 1, 16)
    local hmac_received = string.sub(payload, 17, 48)
    local hmac_expected = sha256.hmac(session.local_key, session.local_nonce)
    if hmac_expected ~= hmac_received then
        return nil, "HMAC inválido en la negociación de sesión (¿local_key incorrecto?)"
    end

    local rkey_hmac = sha256.hmac(session.local_key, session.remote_nonce)
    local msg = tuya35.build_message(session.local_key, session.seqno, tuya35.CMD.SESS_KEY_NEG_FINISH, rkey_hmac)
    session.seqno = session.seqno + 1
    return msg
end

-- Paso 3 (local, sin red): deriva la clave de sesión final a partir del XOR
-- de los nonces, cifrado con la clave real. A partir de aquí session.local_key
-- es la clave de sesión, usada para todos los mensajes de datos.
function tuya35.negotiate_finalize(session)
    local xored = {}
    for i = 1, 16 do
        xored[i] = string.char(string.byte(session.local_nonce, i) ~ string.byte(session.remote_nonce, i))
    end
    xored = table.concat(xored)

    local iv = string.sub(session.local_nonce, 1, 12)
    local ciphertext, _tag = gcm.encrypt(session.real_local_key, iv, xored, "")
    session.local_key = ciphertext -- ciphertext ya son 16 bytes (GCM no agrega padding)
end

return tuya35