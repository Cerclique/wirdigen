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
-- True when `size` bytes are available at `offset`.
local function wd_fits(tvb, offset, size)
    return offset + size <= tvb:len()
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

--@chunk arithmetic
-- Expression operators `+ - *` and negation (ADR 0007). Lua 5.3+ integers wrap on overflow,
-- as Expressions do.
local function wd_add(a, b) return a + b end
local function wd_sub(a, b) return a - b end
local function wd_mul(a, b) return a * b end
local function wd_neg(a) return -a end

--@chunk division
-- C's `/`, truncating toward zero, and `%`, taking the dividend's sign (ADR 0007): Lua's own
-- `//` and `%` floor. They use Lua 5.3 operators, which Lua 5.2 cannot parse, so they are
-- compiled at load: the version guard has already ruled out a Lua older than 5.3.
local wd_div, wd_mod = load([[
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

--@chunk bitwise
-- 64-bit `& | ^ ~ << >>`, with `>>` arithmetic (ADR 0007). Wireshark's `bit` library works on
-- 32 bits, so these use Lua 5.3 operators, compiled at load as in the division chunk.
local wd_band, wd_bor, wd_bxor, wd_bnot, wd_shl, wd_shr = load([[
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
