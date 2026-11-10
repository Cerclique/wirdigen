-- Driver for the Lua checks (spec §10.4), run by `lua_check.rs` with `lua5.x -e`.
-- The Rust side prepends `local mode, version, name = ...`; the checked source comes on stdin.
-- Exit status: 0 on success, 1 when the source fails the check, 2 on a wrong interpreter.

if _VERSION ~= version then
    io.stderr:write("expected ", version, " but this interpreter is ", _VERSION, "\n")
    os.exit(2)
end

local source = io.read("*a")

local function fail(message)
    io.stderr:write(tostring(message), "\n")
    os.exit(1)
end

if mode == "compile" then
    local _, err = load(source, "=" .. name, "t")
    if err then fail(err) end
    os.exit(0)
end

-- mode == "run": the top level runs with the standard library and inert placeholders for
-- Wireshark's globals, so any other global read raises an error.
local env = {}
for key, value in pairs(_G) do env[key] = value end
env._G = env

-- A value that absorbs indexing, assignment, calls and concatenation, standing in for
-- Wireshark's API without mocking its behaviour (spec §10.1).
local inert = {}
setmetatable(inert, {
    __index = function() return inert end,
    __newindex = function() end,
    __call = function() return inert end,
    __concat = function() return inert end,
    __tostring = function() return "<wireshark placeholder>" end,
})

-- Wireshark's Lua globals a Dissector may touch at load. Extend it when the prelude or the
-- generated code needs another one.
local WIRESHARK_GLOBALS = {
    "Proto", "ProtoField", "ProtoExpert", "Field", "Dissector", "DissectorTable", "Pref",
    "ByteArray", "Tvb", "TvbRange", "TreeItem", "Pinfo", "NSTime", "Int64", "UInt64",
    "base", "ftypes", "expert", "bit", "register_postdissector", "dissect_tcp_pdus",
    "set_plugin_info", "DESEGMENT_ONE_MORE_SEGMENT",
    "ENC_BIG_ENDIAN", "ENC_LITTLE_ENDIAN", "ENC_NA", "ENC_ASCII", "ENC_UTF_8",
}
for _, global in ipairs(WIRESHARK_GLOBALS) do env[global] = inert end
-- The version guard runs at load and parses this, so it gets the supported floor.
env.get_version = function() return "4.4.0" end

setmetatable(env, {
    __index = function(_, key)
        error("read of undefined global `" .. tostring(key) .. "`", 2)
    end,
})

local chunk, err = load(source, "=" .. name, "t", env)
if not chunk then fail(err) end
local ok, run_err = xpcall(chunk, debug.traceback)
if not ok then fail(run_err) end
