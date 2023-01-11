--[[
    Author: %PROJECT_NAME%
    Date: %DATE%
    Description: Wireshark Dissector for "%DISSECTOR_NAME%"
]]--

local %DISSECTOR_NAME% = Proto("%DISSECTOR_NAME%", "%DISSECTOR_NAME% Protocol")

-- ValueString Declaration Section
%VALUESTRING_DECLARATION%

-- Fields Declaration Section
%FIELDS_DECLARATION%

%DISSECTOR_NAME%.fields = {
    %FIELDS_LIST%
}

-- Dissector Callback Declaration
function %DISSECTOR_NAME%.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    -- Adds dissector name to protocol column
    pinfo.cols.protocol = %DISSECTOR_NAME%.name
    
    -- Creates the subtree
    local subtree = tree:add(%DISSECTOR_NAME%, buffer(),"%DISSECTOR_NAME% Protocol Data")

    -- Adds Variables to the subtree
    %SUBTREE_POPULATION%
end

local %PROTOCOL%_port = DissectorTable.get("%PROTOCOL%.port")
%PORTS%