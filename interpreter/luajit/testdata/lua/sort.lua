local _M = {}
local ffi = require "ffi"

ffi.cdef[[
  long random();
  void qsort(void *base, size_t nel, size_t width, int (*compar)(const long *, const long *));
  int tolower(int);
]]

function compare(a, b)
    -- consume some cpu to get make sure compare gets sampled
    for i=0,1000000 do
        local x = i * i
    end
    ngx.say(debug.traceback())
    return a[0] - b[0]
end

local callback = ffi.cast("int (*)(const long *, const long *)", compare)

function _M.sort(n)
    local arr = ffi.new("long[?]", n)
    for i=0,n-1 do
        arr[i] = ffi.C.random()
    end
    ffi.C.qsort(arr, n, ffi.sizeof("long"), callback)
    for i=0,n-1 do
        print(arr[i])
    end
end


if not package.loaded["ngx"] then
    _M.sort(20)
end

return _M
