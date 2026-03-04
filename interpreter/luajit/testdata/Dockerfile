FROM openresty/openresty:1.25.3.2-bullseye

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

EXPOSE 8080

CMD ["openresty", "-g", "daemon off;"]
