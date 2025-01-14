local cjson = require 'cjson.safe'
local d = require '512KB'

local function call()
    local ok,res,err = pcall(cjson.decode,d.data)
    pcall(cjson.encode, res)
end

return  {call = call}