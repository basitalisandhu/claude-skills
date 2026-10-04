# CORS configuration snippets

Replace the origins with the exact allowlist. Keep the policy in one layer.

## Express (`cors` package)

```js
import cors from "cors";
const allowlist = new Set(["https://app.example.com", "https://admin.example.com"]);
app.use(cors({
  origin: (origin, cb) => cb(null, allowlist.has(origin) ? origin : false),
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
  exposedHeaders: ["X-Request-Id", "Link"],
  maxAge: 3600,
}));
```

The callback with `false` sends no `Access-Control-Allow-Origin`; `origin: true` would reflect (do not use).

## FastAPI / Starlette

```python
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com", "https://admin.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Request-Id"],
    expose_headers=["X-Request-Id", "Link"],
    max_age=3600,
)
```

`allow_origin_regex` must be anchored: `r"^https://[a-z0-9-]+\.example\.com$"`.

## Django (`django-cors-headers`)

```python
CORS_ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
CORS_ALLOW_HEADERS = ["content-type", "authorization", "x-request-id"]
CORS_EXPOSE_HEADERS = ["x-request-id", "link"]
CORS_PREFLIGHT_MAX_AGE = 3600
# never: CORS_ALLOW_ALL_ORIGINS = True together with credentials
```

Put `corsheaders.middleware.CorsMiddleware` before `CommonMiddleware` and any auth middleware.

## Spring Boot

```java
@Bean
CorsConfigurationSource corsConfigurationSource() {
    var config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://app.example.com", "https://admin.example.com"));
    config.setAllowCredentials(true);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("Content-Type", "Authorization", "X-Request-Id"));
    config.setExposedHeaders(List.of("X-Request-Id", "Link"));
    config.setMaxAge(3600L);
    var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

`setAllowedOriginPatterns("*")` with credentials reflects the origin; avoid it.

## nginx (when the gateway owns the policy)

```nginx
map $http_origin $cors_origin {
    default "";
    "https://app.example.com"   $http_origin;
    "https://admin.example.com" $http_origin;
}
server {
    location /api/ {
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin $cors_origin always;
            add_header Access-Control-Allow-Credentials "true" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE" always;
            add_header Access-Control-Allow-Headers "Content-Type, Authorization, X-Request-Id" always;
            add_header Access-Control-Max-Age 3600 always;
            add_header Vary Origin always;
            return 204;
        }
        add_header Access-Control-Allow-Origin $cors_origin always;
        add_header Access-Control-Allow-Credentials "true" always;
        add_header Access-Control-Expose-Headers "X-Request-Id, Link" always;
        add_header Vary Origin always;
        proxy_pass http://api;
    }
}
```

An empty `$cors_origin` produces no header for unlisted origins. Disable CORS in the application behind it.

## Testing with curl

```bash
# preflight
curl -si -X OPTIONS https://api.example.com/orders \
  -H "Origin: https://app.example.com" -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type,authorization" | grep -i '^access-control\|^vary\|^HTTP'
# unlisted origin: expect no Access-Control-Allow-Origin
curl -si https://api.example.com/orders -H "Origin: https://evil.example" | grep -i '^access-control'
```
