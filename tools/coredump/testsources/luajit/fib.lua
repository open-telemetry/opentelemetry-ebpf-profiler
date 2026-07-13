-- Naive recursive Fibonacci function
function fib(n)
    if n <= 1 then
        return n
    else
        return fib(n - 1) + fib(n - 2)
    end
end


-- Repeatedly compute and print the 40th Fibonacci number
for i=1,9999 do
    local result = fib(40)
    print(result)
end
