local _M = {}

local Fibonacci = {}
function Fibonacci.naive(n)
  local function inner(m)
    if m < 2 then
      return m
    end
    return inner(m-1) +
            inner(m-2)
  end
  return inner(n)
end

function _M.calc(range)
  return "Fib(" .. tostring(range) .. ") = " .. tostring(Fibonacci.naive(range))
end

-- run if outside nginx
if not package.loaded["ngx"] then
  print(_M.calc(20))
end

return _M
