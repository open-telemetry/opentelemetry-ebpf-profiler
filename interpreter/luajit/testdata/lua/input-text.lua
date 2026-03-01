local ffi = require("ffi")
local _M = {}
ffi.cdef[[
  long random();
]]

local text = ""

function _M.gen()
  if #text > 0 then
    return text
  end
  for i=0,2000 do
    text = text .. tostring(ffi.C.random())
  end
  return text
end

return _M