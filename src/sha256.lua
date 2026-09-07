--[[
  sha256.lua
  SHA-256 y HMAC-SHA256 en Lua puro (sin dependencias nativas).
  Requiere Lua 5.3+ (enteros de 64 bits y operadores bitwise nativos).

  Necesario para la negociación de sesión del protocolo Tuya 3.4/3.5
  (el dispositivo firma los nonces con HMAC-SHA256).
--]]

local sha256 = {}

local K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local MASK32 = 0xFFFFFFFF

local function rrotate(x, n)
    x = x & MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32
end

local function to_bytes_be32(n)
    return string.char((n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)
end

-- Devuelve el hash SHA-256 de `msg` como string binario de 32 bytes
function sha256.digest(msg)
    local h = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}

    local msg_len_bits = #msg * 8
    local padded = msg .. "\128"
    while (#padded % 64) ~= 56 do
        padded = padded .. "\0"
    end
    -- longitud en bits como entero de 64 bits big-endian
    local len_hi = math.floor(msg_len_bits / 0x100000000) & MASK32
    local len_lo = msg_len_bits & MASK32
    padded = padded .. to_bytes_be32(len_hi) .. to_bytes_be32(len_lo)

    for chunk_start = 1, #padded, 64 do
        local w = {}
        for i = 0, 15 do
            local off = chunk_start + i * 4
            local b1, b2, b3, b4 = string.byte(padded, off, off + 3)
            w[i] = ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4) & MASK32
        end
        for i = 16, 63 do
            local w15, w2 = w[i - 15], w[i - 2]
            local s0 = rrotate(w15, 7) ~ rrotate(w15, 18) ~ (w15 >> 3)
            local s1 = rrotate(w2, 17) ~ rrotate(w2, 19) ~ (w2 >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK32
        end

        local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]

        for i = 0, 63 do
            local S1 = rrotate(e, 6) ~ rrotate(e, 11) ~ rrotate(e, 25)
            local ch = (e & f) ~ ((~e & MASK32) & g)
            local temp1 = (hh + S1 + ch + K[i + 1] + w[i]) & MASK32
            local S0 = rrotate(a, 2) ~ rrotate(a, 13) ~ rrotate(a, 22)
            local maj = (a & b) ~ (a & c) ~ (b & c)
            local temp2 = (S0 + maj) & MASK32

            hh = g
            g = f
            f = e
            e = (d + temp1) & MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK32
        end

        h[1] = (h[1] + a) & MASK32
        h[2] = (h[2] + b) & MASK32
        h[3] = (h[3] + c) & MASK32
        h[4] = (h[4] + d) & MASK32
        h[5] = (h[5] + e) & MASK32
        h[6] = (h[6] + f) & MASK32
        h[7] = (h[7] + g) & MASK32
        h[8] = (h[8] + hh) & MASK32
    end

    local out = {}
    for i = 1, 8 do out[i] = to_bytes_be32(h[i]) end
    return table.concat(out)
end

function sha256.hexdigest(msg)
    local hash = sha256.digest(msg)
    local hex = {}
    for i = 1, #hash do hex[i] = string.format("%02x", string.byte(hash, i)) end
    return table.concat(hex)
end

-- HMAC-SHA256(key, message) -> 32 bytes binarios
function sha256.hmac(key, message)
    local block_size = 64
    if #key > block_size then
        key = sha256.digest(key)
    end
    if #key < block_size then
        key = key .. string.rep("\0", block_size - #key)
    end

    local o_key_pad = {}
    local i_key_pad = {}
    for i = 1, block_size do
        local kb = string.byte(key, i)
        o_key_pad[i] = string.char(kb ~ 0x5c)
        i_key_pad[i] = string.char(kb ~ 0x36)
    end
    o_key_pad = table.concat(o_key_pad)
    i_key_pad = table.concat(i_key_pad)

    return sha256.digest(o_key_pad .. sha256.digest(i_key_pad .. message))
end

return sha256
