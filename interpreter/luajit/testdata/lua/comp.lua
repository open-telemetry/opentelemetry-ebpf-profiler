local _M = {}
local lzw = require("lualzw")

function _M.comp(input)
    local comp_data = lzw.compress(input)
    decomp_data = lzw.decompress(comp_data)
    if input ~= decomp_data then
        error("Error: input != decomp_data")
    end
    return comp_data
end

-- run if outside nginx
if not package.loaded["ngx"] then
  print(_M.comp("asdfqwerasdfzcvxpoiulkhasdfasdfkajeofiwjdajfj"))
end

return _M
