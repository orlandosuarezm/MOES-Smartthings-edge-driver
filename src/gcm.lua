--[[
  gcm.lua
  AES-128-GCM (modo contador + GHASH) en Lua puro, siguiendo NIST SP 800-38D.
  Construido sobre las primitivas de bloque de aes128.lua (ya validado con
  el vector oficial FIPS-197).

  Necesario porque el protocolo Tuya 3.4/3.5 cifra todos los mensajes de
  datos (y la negociación de sesión en 3.5) con AES-128-GCM, no con ECB.

  ANTES DE USAR EN PRODUCCIÓN: valida con el vector de prueba oficial
  (ver test_vector() al final). Si obtiene el ciphertext y tag esperados,
  la implementación de GHASH/CTR es correcta.
--]]

local aes128 = require "aes128"

local gcm = {}

-- ===== Aritmética de 128 bits usando dos enteros de 64 bits (hi:lo) =====

local function bytes_to_128(s)
    local hi, lo = 0, 0
    for i = 1, 8 do hi = (hi << 8) | string.byte(s, i) end
    for i = 9, 16 do lo = (lo << 8) | string.byte(s, i) end
    return { hi = hi, lo = lo }
end

local function to_bytes_128(v)
    local out = {}
    for i = 7, 0, -1 do out[#out + 1] = string.char((v.hi >> (i * 8)) & 0xFF) end
    for i = 7, 0, -1 do out[#out + 1] = string.char((v.lo >> (i * 8)) & 0xFF) end
    return table.concat(out)
end

local function xor128(a, b)
    return { hi = a.hi ~ b.hi, lo = a.lo ~ b.lo }
end

local function shr1_128(v)
    local new_lo = (v.lo >> 1) | ((v.hi & 1) << 63)
    local new_hi = v.hi >> 1
    return { hi = new_hi, lo = new_lo }
end

-- Constante de reducción R = 11100001 seguido de 120 ceros
local R128 = { hi = 0xE100000000000000, lo = 0x0000000000000000 }

-- Multiplicación en GF(2^128) para GHASH (NIST SP 800-38D, algoritmo 2.9)
local function gf_mult(X, Y)
    local Z = { hi = 0, lo = 0 }
    local V = { hi = Y.hi, lo = Y.lo }
    for i = 0, 127 do
        local bit
        if i < 64 then
            bit = (X.hi >> (63 - i)) & 1
        else
            bit = (X.lo >> (63 - (i - 64))) & 1
        end
        if bit == 1 then
            Z = xor128(Z, V)
        end
        local lsb = V.lo & 1
        V = shr1_128(V)
        if lsb == 1 then
            V = xor128(V, R128)
        end
    end
    return Z
end

local function xor_bytes(a, b)
    local n = math.min(#a, #b)
    local out = {}
    for i = 1, n do
        out[i] = string.char(string.byte(a, i) ~ string.byte(b, i))
    end
    return table.concat(out)
end

local function pad16(s)
    local rem = #s % 16
    if rem == 0 then return s end
    return s .. string.rep("\0", 16 - rem)
end

local function be64(n)
    local out = {}
    for i = 7, 0, -1 do out[#out + 1] = string.char((n >> (i * 8)) & 0xFF) end
    return table.concat(out)
end

-- GHASH(H, A, C) -> 16 bytes
local function ghash(H128, aad, ciphertext)
    local Y = { hi = 0, lo = 0 }

    local aad_padded = pad16(aad)
    for i = 1, #aad_padded, 16 do
        local block = bytes_to_128(string.sub(aad_padded, i, i + 15))
        Y = gf_mult(xor128(Y, block), H128)
    end

    local ct_padded = pad16(ciphertext)
    for i = 1, #ct_padded, 16 do
        local block = bytes_to_128(string.sub(ct_padded, i, i + 15))
        Y = gf_mult(xor128(Y, block), H128)
    end

    local len_block_bytes = be64(#aad * 8) .. be64(#ciphertext * 8)
    local len_block = bytes_to_128(len_block_bytes)
    Y = gf_mult(xor128(Y, len_block), H128)

    return to_bytes_128(Y)
end

-- Incrementa los últimos 4 bytes de un bloque de 16 bytes como un
-- entero big-endian de 32 bits (con acarreo, módulo 2^32)
local function increment32(block16)
    local prefix = string.sub(block16, 1, 12)
    local b1, b2, b3, b4 = string.byte(block16, 13, 16)
    local ctr = ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4)
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix .. string.char((ctr >> 24) & 0xFF, (ctr >> 16) & 0xFF, (ctr >> 8) & 0xFF, ctr & 0xFF)
end

local function ctr_keystream(expanded_key, j0, length)
    local blocks = {}
    local counter = j0
    local produced = 0
    while produced < length do
        counter = increment32(counter)
        blocks[#blocks + 1] = aes128.encrypt_block_raw(counter, expanded_key)
        produced = produced + 16
    end
    return table.concat(blocks)
end

-- Cifra con AES-128-GCM. iv debe ser de 12 bytes (96 bits, el caso estándar
-- y el único que usa Tuya). Devuelve ciphertext, tag (16 bytes cada uno de
-- longitud igual al plaintext / fija respectivamente).
function gcm.encrypt(key, iv, plaintext, aad)
    aad = aad or ""
    assert(#iv == 12, "GCM: el IV debe ser de 12 bytes")

    local expanded_key = aes128.expand_key(key)
    local H = bytes_to_128(aes128.encrypt_block_raw(string.rep("\0", 16), expanded_key))

    local j0 = iv .. "\0\0\0\1"
    local keystream = ctr_keystream(expanded_key, j0, #plaintext)
    local ciphertext = xor_bytes(plaintext, keystream)

    local s = ghash(H, aad, ciphertext)
    local ek_j0 = aes128.encrypt_block_raw(j0, expanded_key)
    local tag = xor_bytes(s, ek_j0)

    return ciphertext, tag
end

-- Descifra y verifica el tag. Devuelve plaintext, o nil + "tag inválido"
-- si la autenticación falla (clave incorrecta o datos corruptos/manipulados).
function gcm.decrypt(key, iv, ciphertext, tag, aad)
    aad = aad or ""
    assert(#iv == 12, "GCM: el IV debe ser de 12 bytes")

    local expanded_key = aes128.expand_key(key)
    local H = bytes_to_128(aes128.encrypt_block_raw(string.rep("\0", 16), expanded_key))

    local j0 = iv .. "\0\0\0\1"

    local s = ghash(H, aad, ciphertext)
    local ek_j0 = aes128.encrypt_block_raw(j0, expanded_key)
    local expected_tag = xor_bytes(s, ek_j0)

    if expected_tag ~= tag then
        return nil, "tag inválido"
    end

    local keystream = ctr_keystream(expanded_key, j0, #ciphertext)
    local plaintext = xor_bytes(ciphertext, keystream)
    return plaintext
end

-- Vector de prueba oficial (McGrew/Viega, Test Case 2 de la especificación GCM).
-- Corre esto para confirmar que GHASH y el modo contador están bien antes
-- de fiarte de esta implementación con datos reales del termostato.
function gcm.test_vector()
    local key = string.rep("\0", 16)
    local iv = string.rep("\0", 12)
    local plaintext = string.rep("\0", 16)

    local ciphertext, tag = gcm.encrypt(key, iv, plaintext, "")

    local function to_hex(s)
        local hex = {}
        for i = 1, #s do hex[i] = string.format("%02x", string.byte(s, i)) end
        return table.concat(hex)
    end

    local expected_ct = "0388dace60b6a392f328c2b971b2fe78"
    local expected_tag = "ab6e47d42cec13bdf53a67b21257bddf"
    local got_ct = to_hex(ciphertext)
    local got_tag = to_hex(tag)

    local decrypted, err = gcm.decrypt(key, iv, ciphertext, tag, "")

    return {
        ok = (got_ct == expected_ct) and (got_tag == expected_tag) and (decrypted == plaintext),
        expected_ct = expected_ct, got_ct = got_ct,
        expected_tag = expected_tag, got_tag = got_tag,
        roundtrip_ok = (decrypted == plaintext),
    }
end

return gcm
