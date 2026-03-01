local _M = {}
function _M.run_duration(d, f)
    local start = ngx.now()
    while ngx.now() < start + d do
        f()
        ngx.update_time()
    end
end
return _M
