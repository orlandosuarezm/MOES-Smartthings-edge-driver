local Driver = require "st.driver"
local caps = require "st.capabilities"
local log = require "log"
local cosock = require "cosock"
local socket = require "cosock.socket"
local json = require "st.json"
local tuya35 = require "tuya35"

-- sock:send() en LuaSocket/cosock devuelve el ÍNDICE del último byte enviado
-- (no un booleano), y con TCP puede enviar solo una parte del buffer en una
-- sola llamada. Hay que verificar que se mandó TODO y reintentar el resto.
local function send_all(sock, data)
    local total_len = #data
    local sent_so_far = 0
    while sent_so_far < total_len do
        local last_sent, err = sock:send(data, sent_so_far + 1)
        if not last_sent then
            return nil, err
        end
        sent_so_far = last_sent
    end
    return true
end

math.randomseed(os.time() + math.floor(os.clock() * 1000000))

--[[
  MAPEO DE DPs - confirmado con datos reales del termostato vía protocolo 3.5:
  {"dps":{"1":true,"2":40,"3":59,"4":"1","5":false,"6":false,"102":54,"103":"0","104":true}}
  NOTA: los valores de temperatura son grados literales, SIN dividir entre 10
  (el campo "scale" del export de Tuya no aplica aquí - confirmado con datos reales).
--]]
local DP = {
    POWER           = 1,
    SETPOINT_TARGET = 2,
    CURRENT_TEMP    = 3,
    ECO             = 5,
}

-- ID de custom capability: REEMPLAZA "REPLACE_NAMESPACE" por tu namespace real.
-- Déjalo en false hasta crear la capability y agregarla al profile.
local ENABLE_CUSTOM_CAPS = false
local ECO_CAP_ID = "REPLACE_NAMESPACE.ecoMode"
local ECO_ATTR = "ecoMode"

local POLL_INTERVAL_SECONDS = 30

local function get_conn_info(device)
    local prefs = device.preferences or {}
    return {
        ip = prefs.deviceIp,
        port = tonumber(prefs.devicePort) or 6668,
        device_id = prefs.deviceId,
        local_key = prefs.localKey,
    }
end

-- ===== Mutex simple para serializar el acceso al socket =====
local function acquire_lock(device)
    local waited = 0
    while device:get_field("tuya_busy") and waited < 10 do
        socket.sleep(0.05)
        waited = waited + 0.05
    end
    device:set_field("tuya_busy", true)
end

local function release_lock(device)
    device:set_field("tuya_busy", nil)
end

-- ===== Conexión + negociación de sesión =====

local function close_connection(device)
    local sock = device:get_field("tuya_socket")
    if sock then
        pcall(function() sock:close() end)
    end
    device:set_field("tuya_socket", nil)
    device:set_field("tuya_session", nil)
end

-- Abre TCP y negocia la sesión 3.5 completa (3 pasos). Devuelve true/false.
local function connect_and_negotiate(device)
    local info = get_conn_info(device)
    if not info.ip or not info.device_id or not info.local_key then
        log.warn("Faltan preferencias (IP/deviceId/localKey), no se puede conectar")
        return false
    end

    close_connection(device)

    local sock = socket.tcp()
    sock:settimeout(5)
    local ok, err = sock:connect(info.ip, info.port)
    if not ok then
        log.error("No se pudo conectar a " .. info.ip .. ":" .. info.port .. " - " .. tostring(err))
        device:offline()
        return false
    end

    local session = tuya35.new_session(info.local_key)

    local step1_msg = tuya35.negotiate_step1(session)
    do
        local hex = {}
        for i = 1, #step1_msg do hex[i] = string.format("%02x", string.byte(step1_msg, i)) end
        log.info("DEBUG paso1 longitud=" .. #step1_msg .. " hex=" .. table.concat(hex))
    end
    local send_ok, send_err = send_all(sock, step1_msg)
    if not send_ok then
        log.error("Negociación paso 1 (envío) falló: " .. tostring(send_err))
        sock:close()
        device:offline()
        return false
    end

    local resp, recv_err = sock:receive(2048)
    if not resp then
        log.error("Negociación paso 1 (sin respuesta): " .. tostring(recv_err))
        sock:close()
        device:offline()
        return false
    end

    local step3_msg, neg_err = tuya35.negotiate_step2(session, resp)
    if not step3_msg then
        log.error("Negociación paso 2 falló: " .. tostring(neg_err))
        sock:close()
        device:offline()
        return false
    end

    local send_ok2, send_err2 = send_all(sock, step3_msg)
    if not send_ok2 then
        log.error("Negociación paso 3 (envío) falló: " .. tostring(send_err2))
        sock:close()
        device:offline()
        return false
    end

    tuya35.negotiate_finalize(session)

    device:set_field("tuya_socket", sock)
    device:set_field("tuya_session", session)
    device:online()
    log.info("Sesión Tuya 3.5 negociada con " .. info.ip)
    return true
end

-- Envía un comando de datos (cmd ya "override": CONTROL_NEW=13 o DP_QUERY_NEW=16)
-- y devuelve el payload de datos limpio (JSON string), o nil+err.
-- retry=false evita bucles infinitos de reconexión.
local function send_data_command(device, cmd, json_payload, retry)
    local sock = device:get_field("tuya_socket")
    local session = device:get_field("tuya_session")

    if not sock or not session then
        if retry == false then return nil, "sin conexión" end
        if not connect_and_negotiate(device) then return nil, "no se pudo conectar" end
        sock = device:get_field("tuya_socket")
        session = device:get_field("tuya_session")
    end

    local msg = tuya35.build_message(session.local_key, session.seqno, cmd, json_payload)
    session.seqno = session.seqno + 1

    local ok, err = send_all(sock, msg)
    if not ok then
        log.warn("Envío falló (" .. tostring(err) .. "), reconectando")
        if retry == false then return nil, err end
        if not connect_and_negotiate(device) then return nil, "reconexión falló" end
        return send_data_command(device, cmd, json_payload, false)
    end

    local resp, recv_err = sock:receive(2048)
    if not resp then
        log.warn("Sin respuesta (" .. tostring(recv_err) .. "), reconectando")
        if retry == false then return nil, recv_err end
        if not connect_and_negotiate(device) then return nil, "reconexión falló" end
        return send_data_command(device, cmd, json_payload, false)
    end

    local parsed, parse_err = tuya35.parse_message(session.local_key, resp)
    if not parsed then
        return nil, parse_err
    end

    return tuya35.strip_data_wrappers(parsed.payload)
end

local function apply_dps_to_device(device, dps)
    if dps[tostring(DP.POWER)] ~= nil then
        local on = dps[tostring(DP.POWER)]
        device:emit_event(on and caps.switch.switch.on() or caps.switch.switch.off())
    end

    if dps[tostring(DP.CURRENT_TEMP)] ~= nil then
        device:emit_event(caps.temperatureMeasurement.temperature({
            value = tonumber(dps[tostring(DP.CURRENT_TEMP)]), unit = "C"
        }))
    end

    if dps[tostring(DP.SETPOINT_TARGET)] ~= nil then
        device:emit_event(caps.thermostatHeatingSetpoint.heatingSetpoint({
            value = tonumber(dps[tostring(DP.SETPOINT_TARGET)]), unit = "C"
        }))
    end

    if ENABLE_CUSTOM_CAPS and dps[tostring(DP.ECO)] ~= nil then
        local on = dps[tostring(DP.ECO)]
        device:emit_event(caps[ECO_CAP_ID][ECO_ATTR]({ value = on and "on" or "off" }))
    end
end

local function poll_status(device)
    acquire_lock(device)
    local payload, err = send_data_command(device, tuya35.CMD.DP_QUERY_NEW, "{}")
    release_lock(device)

    if not payload then
        log.warn("poll_status falló: " .. tostring(err))
        return
    end

    local ok, data = pcall(json.decode, payload)
    if not ok or not data or not data.dps then
        log.warn("poll_status: respuesta sin dps: " .. tostring(payload))
        return
    end

    log.info("DPs recibidos: " .. payload)
    apply_dps_to_device(device, data.dps)
end

-- Construye y envía un CONTROL_NEW para fijar un DP. value: boolean o número.
local function send_dp_set(device, dp_id, value)
    local value_str
    if type(value) == "boolean" then
        value_str = value and "true" or "false"
    else
        value_str = tostring(math.floor(value))
    end

    -- Formato exacto que espera un dispositivo 3.5 para CONTROL_NEW
    -- (protocol:5 + data.dps). Sin espacios: el dispositivo no responde si
    -- el JSON lleva espacios.
    local json_payload = string.format(
        '{"protocol":5,"t":%d,"data":{"dps":{"%d":%s}}}',
        os.time(), dp_id, value_str
    )

    acquire_lock(device)
    local payload, err = send_data_command(device, tuya35.CMD.CONTROL_NEW, json_payload)
    release_lock(device)

    if not payload then
        log.warn("send_dp_set (dp " .. dp_id .. ") falló: " .. tostring(err))
        return false
    end
    return true
end

-- ===== Capability handlers =====

local function handle_switch_on(driver, device, command)
    send_dp_set(device, DP.POWER, true)
    device.thread:call_with_delay(1, function() poll_status(device) end)
end

local function handle_switch_off(driver, device, command)
    send_dp_set(device, DP.POWER, false)
    device.thread:call_with_delay(1, function() poll_status(device) end)
end

local function handle_set_heating_setpoint(driver, device, command)
    local temp = command.args.setpoint
    send_dp_set(device, DP.SETPOINT_TARGET, temp)
    -- actualización optimista; se corrige en el próximo poll si el
    -- dispositivo redondeó o rechazó el valor
    device:emit_event(caps.thermostatHeatingSetpoint.heatingSetpoint({ value = temp, unit = "C" }))
end

local function handle_eco_on(driver, device, command)
    send_dp_set(device, DP.ECO, true)
end

local function handle_eco_off(driver, device, command)
    send_dp_set(device, DP.ECO, false)
end

-- ===== Lifecycle handlers =====

local function device_added(driver, device)
    log.info("MOES DEVICE ADDED: " .. tostring(device.id))
end

local function device_init(driver, device)
    log.info("MOES DEVICE INIT: " .. tostring(device.id))
    if connect_and_negotiate(device) then
        poll_status(device)
    end
    device.thread:call_on_schedule(POLL_INTERVAL_SECONDS, function() poll_status(device) end, "moes-poll")
end

local function device_info_changed(driver, device, event, args)
    if args.old_st_store.preferences ~= device.preferences then
        log.info("Preferencias cambiadas, reconectando")
        close_connection(device)
        if connect_and_negotiate(device) then
            poll_status(device)
        end
    end
end

local function handle_discovery(driver, _args, _should_continue)
    local metadata = {
        type = "LAN",
        device_network_id = "moes-bht002-" .. tostring(os.time()),
        label = "Calefaccion MOES",
        profile = "moes-thermostat",
        manufacturer = "MOES",
        model = "BHT-002",
        vendor_provided_label = "Calefaccion",
    }

    local success, err = driver:try_create_device(metadata)
    if success then
        log.info("MOES device creation requested")
    else
        log.error("MOES device creation failed: " .. tostring(err))
    end
end

local driver_capability_handlers = {
    [caps.switch.ID] = {
        [caps.switch.commands.on.NAME] = handle_switch_on,
        [caps.switch.commands.off.NAME] = handle_switch_off,
    },
    [caps.thermostatHeatingSetpoint.ID] = {
        [caps.thermostatHeatingSetpoint.commands.setHeatingSetpoint.NAME] = handle_set_heating_setpoint,
    },
}

if ENABLE_CUSTOM_CAPS then
    driver_capability_handlers[ECO_CAP_ID] = {
        ["on"] = handle_eco_on,
        ["off"] = handle_eco_off,
    }
end

local driver = Driver("MOES Thermostat", {
    discovery = handle_discovery,
    lifecycle_handlers = {
        added = device_added,
        init = device_init,
        infoChanged = device_info_changed,
    },
    capability_handlers = driver_capability_handlers,
})

driver:run()
