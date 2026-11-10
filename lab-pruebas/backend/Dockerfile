FROM nginx:1.27-alpine
RUN apk add --no-cache curl openssl
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
