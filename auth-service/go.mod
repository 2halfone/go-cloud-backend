module auth-service

go 1.23.0

toolchain go1.24.3

replace go-cloud-backend/shared => ../shared

require (
	github.com/gofiber/fiber/v2 v2.52.8
	github.com/gofiber/jwt/v3 v3.3.10
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/lib/pq v1.10.9
	github.com/prometheus/client_golang v1.22.0
	github.com/valyala/fasthttp v1.62.0
	go-cloud-backend/shared v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.38.0
)

replace shared => ../shared

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
)
