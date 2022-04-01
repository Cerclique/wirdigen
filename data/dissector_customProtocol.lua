
--[[
    Author: TODO
    Language: Lua
    Date: 2022-04-01 23:10:41
    Description: Wireshark Dissector for customProtocol
]]--

customProtocol = Proto("customProtocol", "customProtocol Protocol")

-- Fields Declaration Section
item_one_field=Protofield.uint8("item_one.item_one_field", "item one description", base.DEC)
item_two_field=Protofield.uint32("item_two.item_two_field", "item two description", base.DEC)
item_three_field=Protofield.uint16("item_three.item_three_field", "item three description", base.HEX)

customProtocol.fields = {
    item_one_field,
	item_two_field,
	item_three_field,
}

-- Dissector Callback Declaration
function customProtocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- Adds dissector name to protocol column
    pinfo.cols.protocol = customProtocol.name
    
    -- Creates the subtree
    local subtree = tree:add(customProtocol, buffer(),"customProtocol Protocol Data")

    -- Local Variables Declaration
    localitem_one_field = buffer(0, 1)
	localitem_two_field = buffer(1, 4)
	localitem_three_field = buffer(5, 2)

    -- Adds Variables to the subtree
    subtree:add(item_one_field, item_one)
	subtree:add(item_two_field, item_two)
	subtree:add(item_three_field, item_three)
	
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(60001, customProtocol)
udp_port:add(60002, customProtocol)

