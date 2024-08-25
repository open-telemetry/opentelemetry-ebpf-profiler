local _M = {}
local lzw = require("lualzw")

local function compress_file(data)
    return lzw.compress(data)
end

function _M.comp(input)
    return compress_file(input)
end

-- run if outside nginx
if not package.loaded["ngx"] then
  print(_M.comp("asdfqwerasdfzcvxpoiulkhasdfasdfkajeofiwjdajfj"))
end

return _M
