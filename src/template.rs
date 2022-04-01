const DISSECTOR_TEMPLATE: &str = r#"
--[[
    Author: %PROJECT_NAME%
    Language: Lua
    Date: %DATE%
    Description: Wireshark Dissector for %DISSECTOR_NAME%
]]--

%DISSECTOR_NAME% = Proto("%DISSECTOR_NAME%", "%DISSECTOR_NAME% Protocol")

-- Fields Declaration Section
%FIELDS_DECLARATION%

%DISSECTOR_NAME%.fields = {
    %FIELDS_LIST%
}

-- Dissector Callback Declaration
function %DISSECTOR_NAME%.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- Adds dissector name to protocol column
    pinfo.cols.protocol = %DISSECTOR_NAME%.name
    
    -- Creates the subtree
    local subtree = tree:add(%DISSECTOR_NAME%, buffer(),"%DISSECTOR_NAME% Protocol Data")

    -- Local Variables Declaration
    %LOCAL_VAR_DECLARATION%

    -- Adds Variables to the subtree
    %SUBTREE_POPULATION%
end

local %PROTOCOL%_port = DissectorTable.get("%PROTOCOL%.port")
%PORTS%
"#;
