-- The Lua runtime shared by every generated Dissector (ADR 0010).
--
-- It is split into chunks. A line `--@chunk <name>` starts one, and an optional
-- `--@requires <name> ...` line right after it declares its dependencies, which
-- must be chunks defined earlier in this file. A Dissector gets only the chunks
-- it uses plus their dependencies, in the order they appear here.
--
-- Everything here must parse under Lua 5.2: no native bitwise operators, no `//`.
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
