-- The Lua runtime shared by every generated Dissector (ADR 0010).
--
-- It is split into chunks. A line `--@chunk <name>` starts one, and an optional
-- `--@requires <name> ...` line right after it declares its dependencies, which
-- must be chunks defined earlier in this file. A Dissector gets only the chunks
-- it uses plus their dependencies, in the order they appear here.
--
-- Everything here must parse under Lua 5.2: no native bitwise operators, no `//`, except
-- inside the strings a chunk compiles with `load` once the version guard has run.
-- Names start with `wd_` so they cannot clash with a mangled user name.

--@chunk version
-- Fails at load on a Wireshark older than 4.4. Always included.
local function wd_check_version()
    local major, minor = string.match(get_version(), "^(%d+)%.(%d+)")
    major, minor = tonumber(major), tonumber(minor)
    if major and minor and (major < 4 or (major == 4 and minor < 4)) then
        error("This Dissector requires Wireshark >= 4.4, found " .. get_version())
    end
end
wd_check_version()

--@chunk malformed
-- Reporting of packets that end too early. Always included.
-- The `_` segment is reserved: no Field path can reach it (spec §3.4.2, §5.2).
local function wd_expert_truncated(filter_name)
    return ProtoExpert.new(
        filter_name .. "._malformed.truncated",
        "Malformed: truncated",
        expert.group.MALFORMED,
        expert.severity.ERROR
    )
end

local function wd_truncated(tree, expert_info, path)
    tree:add_proto_expert_info(expert_info, "Malformed: truncated: " .. path)
end

--@chunk bounds
-- True when `size` bytes are available at `offset`. Written so that a huge `size` from an
-- Expression cannot overflow `offset + size` into a small number.
local function wd_fits(tvb, offset, size)
    return size <= tvb:len() - offset
end

--@chunk terminated
-- The number of bytes from `offset` to the first run of `width` `terminator` bytes, searched
-- in steps of `width` so a 2-byte terminator stays aligned; nil when the packet ends first.
local function wd_terminated(tvb, offset, terminator, width)
    local bytes = tvb:raw(offset)
    local mark = string.rep(string.char(terminator), width)
    for at = 1, #bytes - width + 1, width do
        if string.sub(bytes, at, at + width - 1) == mark then
            return at - 1
        end
    end
    return nil
end

--@chunk fault
-- Stops evaluating an Expression that has no value (spec §4.4). The error is a table that
-- `wd_evaluate` catches, so it never escapes the Dissector as a Lua error.
local function wd_fail(reason)
    error({ wd_fault = reason }, 0)
end

--@chunk arithmetic
-- Expression operators `+ - *` and negation (ADR 0007). Lua 5.3+ integers wrap on overflow,
-- as Expressions do.
local function wd_add(a, b) return a + b end
local function wd_sub(a, b) return a - b end
local function wd_mul(a, b) return a * b end
local function wd_neg(a) return -a end

--@chunk division
--@requires fault
-- C's `/`, truncating toward zero, and `%`, taking the dividend's sign (ADR 0007): Lua's own
-- `//` and `%` floor. They use Lua 5.3 operators, which Lua 5.2 cannot parse, so they are
-- compiled at load: the version guard has already ruled out a Lua older than 5.3. Dividing by
-- zero fails the Expression.
local wd_div, wd_mod
do
    local div, rem = load([[
    local function rem(a, b)
        local r = a % b
        if r ~= 0 and (r ~ a) < 0 then r = r - b end
        return r
    end
    local function div(a, b)
        local q = a // b
        if a % b ~= 0 and (a ~ b) < 0 then q = q + 1 end
        return q
    end
    return div, rem
]], "=wd_division")()
    wd_div = function(a, b)
        if b == 0 then wd_fail("division by zero") end
        return div(a, b)
    end
    wd_mod = function(a, b)
        if b == 0 then wd_fail("division by zero") end
        return rem(a, b)
    end
end

--@chunk bitwise
--@requires fault
-- 64-bit `& | ^ ~ << >>`, with `>>` arithmetic (ADR 0007). Wireshark's `bit` library works on
-- 32 bits, so these use Lua 5.3 operators, compiled at load as in the division chunk. A shift
-- count outside 0..63 fails the Expression.
local wd_band, wd_bor, wd_bxor, wd_bnot, wd_shl, wd_shr
do
    local shl, shr
    wd_band, wd_bor, wd_bxor, wd_bnot, shl, shr = load([[
    return function(a, b) return a & b end,
        function(a, b) return a | b end,
        function(a, b) return a ~ b end,
        function(a) return ~a end,
        function(a, n) return a << n end,
        function(a, n)
            if a >= 0 then return a >> n end
            return ~(~a >> n)
        end
]], "=wd_bitwise")()
    local function count(n)
        if n < 0 or n > 63 then wd_fail("shift by " .. n .. ", outside 0 to 63") end
        return n
    end
    wd_shl = function(a, n) return shl(a, count(n)) end
    wd_shr = function(a, n) return shr(a, count(n)) end
end

--@chunk logic
-- Comparisons and `!` give 1 or 0, as in C; `wd_bool` turns the result of Lua's
-- short-circuiting `and`/`or`, which generated code uses for `&&` and `||`, into 1 or 0.
local function wd_bool(b) if b then return 1 end return 0 end
local function wd_eq(a, b) return wd_bool(a == b) end
local function wd_ne(a, b) return wd_bool(a ~= b) end
local function wd_lt(a, b) return wd_bool(a < b) end
local function wd_le(a, b) return wd_bool(a <= b) end
local function wd_gt(a, b) return wd_bool(a > b) end
local function wd_ge(a, b) return wd_bool(a >= b) end
local function wd_not(a) return wd_bool(a == 0) end

--@chunk invalid
-- Reporting of Expressions with no value when a packet is read (spec §4.4): division by zero,
-- a shift count outside 0..63, a negative size. Like a truncation, it is a "Malformed" error.
local function wd_expert_invalid(filter_name)
    return ProtoExpert.new(
        filter_name .. "._malformed.expression",
        "Malformed: invalid Expression value",
        expert.group.MALFORMED,
        expert.severity.ERROR
    )
end

local function wd_invalid(tree, expert_info, reason, path)
    tree:add_proto_expert_info(expert_info, "Malformed: " .. reason .. ": " .. path)
end

-- The value `compute` returns, or nil and the reason it failed with `wd_fail`. Any other error
-- is a Wirdigen bug, raised again so it is not mistaken for a malformed packet.
local function wd_evaluate(compute)
    local ok, value = pcall(compute)
    if ok then return value end
    if type(value) == "table" and value.wd_fault then return nil, value.wd_fault end
    error(value, 0)
end

--@chunk names
-- The name of a `switch` subject's value (spec §3.9): its label in `names`, a list of
-- `{ low, high, label }`, or else the number.
local function wd_case_name(names, value)
    for _, entry in ipairs(names) do
        if value >= entry[1] and value <= entry[2] then
            return entry[3]
        end
    end
    return tostring(value)
end

--@chunk unmatched
-- Showing what a `switch` with no case for its subject's value, and no `default`, leaves
-- unread (spec §3.9): the rest of the message, raw, with an expert info note. The `_` segment
-- is reserved: no Field path can reach it (spec §3.4.2, §5.2).
local function wd_field_unmatched(filter_name)
    return ProtoField.bytes(filter_name .. "._unmatched", "Unmatched bytes")
end

local function wd_expert_unmatched(filter_name)
    return ProtoExpert.new(
        filter_name .. "._undecoded.unmatched",
        "No case matches the switch value",
        expert.group.UNDECODED,
        expert.severity.NOTE
    )
end

local function wd_unmatched(tree, field, expert_info, tvb, offset, value, path)
    local item = tree:add(field, tvb(offset, tvb:len() - offset))
    item:add_proto_expert_info(expert_info, "No case for " .. value .. ": " .. path)
end

--@chunk unexpected
-- Reporting of a value outside a Field's `expect:` (spec §3.10, §5.3): a warning, after which
-- the dissection goes on. The `_` segment is reserved: no Field path can reach it (spec §3.4.2,
-- §5.2).
local function wd_expert_unexpected(filter_name)
    return ProtoExpert.new(
        filter_name .. "._protocol.unexpected",
        "Unexpected value",
        expert.group.PROTOCOL,
        expert.severity.WARN
    )
end

-- Adds the warning to `item` unless `value` lies in one of `ranges`, the inclusive bounds
-- `{ low, high, low, high, ... }`, which `expected` shows.
local function wd_expect(item, value, ranges, expected, expert_info, path)
    for i = 1, #ranges, 2 do
        if value >= ranges[i] and value <= ranges[i + 1] then return end
    end
    item:add_proto_expert_info(expert_info, "Unexpected value: " .. path .. " (expected " .. expected .. ")")
end

--@chunk handoff
-- Handing a `bytes` Field's bytes to a Wireshark Dissector by name (spec §3.10). The `_`
-- segment is reserved: no Field path can reach it (spec §3.4.2, §5.2).
local function wd_expert_dissector(filter_name)
    return ProtoExpert.new(
        filter_name .. "._undecoded.dissector",
        "Unknown Dissector",
        expert.group.UNDECODED,
        expert.severity.WARN
    )
end

-- The Dissectors found by name, or false for a name Wireshark does not know. Each is looked up
-- when a packet first needs it, once every Dissector is registered.
local wd_dissectors = {}

-- Passes the bytes of `range` to the Dissector named `name`, whose layer goes into `tree`. An
-- unknown name adds a warning to `tree` instead, even when there are no bytes to pass. An error
-- in the Dissector is shown in its own layer by Wireshark, and never escapes as a Lua error. The
-- Protocol column keeps this Dissector's short name (spec §5.5).
local function wd_handoff(name, range, pinfo, tree, expert_info, path)
    local dissector = wd_dissectors[name]
    if dissector == nil then
        local found, value = pcall(Dissector.get, name)
        dissector = found and value or false
        wd_dissectors[name] = dissector
    end
    if not dissector then
        tree:add_proto_expert_info(expert_info, "Unknown Dissector " .. name .. ": " .. path)
        return
    end
    if range:len() > 0 then
        local protocol = tostring(pinfo.cols.protocol)
        pcall(dissector.call, dissector, range:tvb(), pinfo, tree)
        pinfo.cols.protocol = protocol
    end
end

--@chunk framing
--@requires invalid
-- Framing (spec §3.13). Under TCP, the Messages of a segment are dissected one after another,
-- each in a tvb of its own, so that `_offset` and `_remaining` count from its start.
-- `message_length(tvb, offset)` computes the length of the Message at `offset` from its
-- `header` bytes; `dissect_message(tvb, pinfo, tree, malformed)` dissects one Message, or shows
-- it as malformed for the reason `malformed`.
--
-- A Message running past the segment asks TCP for more data from its start: the bytes missing
-- once its header gives its length, one more segment (`DESEGMENT_ONE_MORE_SEGMENT`) before.
-- When TCP cannot reassemble (its preference is off), the rest of the segment is dissected as
-- one Message, which then reports itself truncated. A length with no value, negative or below
-- the header shows the rest of the segment as one malformed Message.
--
-- `pinfo.port_type` of a TCP packet: `PT_TCP` in Wireshark's `port_type` enum.
local wd_port_type_tcp = 2

local function wd_framed(tvb, pinfo, tree, header, message_length, dissect_message)
    local offset, total = 0, tvb:len()
    while offset < total do
        local available = total - offset
        local length, fault
        if available >= header then
            length, fault = wd_evaluate(function() return message_length(tvb, offset) end)
            local malformed
            if not length then
                malformed = fault
            elseif length < 0 then
                malformed = "length " .. length .. " is negative"
            elseif length < header then
                malformed = "length " .. length .. " is below the " .. header .. "-byte header"
            end
            if malformed then
                dissect_message(tvb(offset):tvb(), pinfo, tree, malformed)
                return total
            end
        end
        if not length or length > available then
            if pinfo.can_desegment > 0 then
                local missing = DESEGMENT_ONE_MORE_SEGMENT
                if length and length - available < missing then
                    missing = length - available
                end
                pinfo.desegment_offset = offset
                pinfo.desegment_len = missing
                return total
            end
            length = available
        end
        dissect_message(tvb(offset, length):tvb(), pinfo, tree)
        offset = offset + length
    end
    return total
end

--@chunk ports
-- Registering on the ports of the range preferences (spec §3.12). `ports` lists a
-- `{ preference, dissector table }` pair per transport with declared ports. The Dissector is
-- added on the preference's ports at load, and moved when a preference changes: removed from
-- the old ports, added on the new ones.
local function wd_register_ports(proto, ports)
    local registered = {}
    local function apply()
        for _, transport in ipairs(ports) do
            local preference, table_name = transport[1], transport[2]
            local wanted = proto.prefs[preference]
            if wanted ~= registered[preference] then
                local dissectors = DissectorTable.get(table_name)
                if registered[preference] then
                    dissectors:remove(registered[preference], proto)
                end
                dissectors:add(wanted, proto)
                registered[preference] = wanted
            end
        end
    end
    apply()
    proto.prefs_changed = apply
end

--@chunk info
-- The Info column (spec §3.14). The last value the field extractor `field` found in the packet,
-- or nil when its Field was not read.
local function wd_info_found(field)
    local found = { field() }
    return found[#found]
end

-- What Wireshark displays for the value `field` extracts, or "" when its Field was not read.
local function wd_info_display(field)
    local info = wd_info_found(field)
    return info and info.display or ""
end

--@chunk info_label
--@requires info
-- The label in `names`, a list of `{ low, high, label }`, of the value `field` extracts, or else
-- the number; "" when its Field was not read. A 64-bit value comes as a UInt64 or an Int64,
-- looked up as an Expression reads it, its 64 bits as a signed integer, and shown as Wireshark
-- shows it.
local function wd_info_label(field, names)
    local info = wd_info_found(field)
    if not info then return "" end
    local key = info.value
    if type(key) == "userdata" then
        key = tonumber(key:tohex(), 16)
    end
    for _, entry in ipairs(names) do
        if key >= entry[1] and key <= entry[2] then
            return entry[3]
        end
    end
    return tostring(info.value)
end

--@chunk info_cases
-- The case names of the `switch` Fields the Info column shows, by path, read in the packet
-- being dissected (spec §3.14). The Dissector empties it before each packet.
local wd_info_cases = {}
