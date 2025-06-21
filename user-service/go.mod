module user-service

go 1.23.0

toolchain go1.24.3

require (
	github.com/gofiber/fiber/v2 v2.52.8
	github.com/gofiber/jwt/v3 v3.3.10
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/lib/pq v1.10.9
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
)

require (
	github.com/valyala/fasthttp v1.62.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect; indirect	golang.org/x/sys v0.33.0 // indirect
)

replace go-cloud-backend/shared => ../shared
