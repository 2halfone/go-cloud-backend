Schema. dell'Applicazione Go Cloud Backend.

graph TB.
    %% Client Layer.
    Client[🌐 Client/Browser<br/>Frontend App].
    
    %% Load Balancer/Proxy Layer
    Internet((🌍 Internet<br/>Port 80/443))
    Nginx[🔒 Nginx Reverse Proxy<br/>Load Balancer + SSL]
    
    %% API Gateway Layer
    Gateway[🚪 API Gateway<br/>Port 3000<br/>• JWT Authentication<br/>• Rate Limiting<br/>• CORS<br/>• Request Routing]
    
    %% Microservices Layer
    AuthService[🔐 Auth Service<br/>Port 3001<br/>• User Login/Register<br/>• JWT Token Generation<br/>• Password Management]
    
    UserService[👥 User Service<br/>Port 3002<br/>• User Profile Management<br/>• QR Code Generation<br/>• Attendance Tracking<br/>• User Data CRUD]
    
    SocialLogService[📜 Social Log Service<br/>Port 3003<br/>• Social Event Logging<br/>• Audit Trail<br/>• Social Activity Tracking]
    
    %% Database Layer
    AuthDB[(🗄️ Auth Database<br/>PostgreSQL<br/>Port 5432<br/>• Users<br/>• Credentials<br/>• Sessions)]
    
    UserDB[(🗄️ User Database<br/>PostgreSQL<br/>Port 5432<br/>• Profiles<br/>• QR Codes<br/>• Attendance<br/>• Metadata)]
    
    SocialLogDB[(🗄️ Social Log DB<br/>PostgreSQL<br/>Port 5433<br/>• Social Logs<br/>• Audit Events)]
    
    %% Monitoring Layer
    Prometheus[📊 Prometheus<br/>Port 9090<br/>• Metrics Collection<br/>• System Monitoring<br/>• Performance Analytics]
    
    Portainer[🐳 Portainer<br/>Container Management<br/>• Docker Monitoring<br/>• Container Control]
    
    %% Network Layer
    DockerNet{🌐 Docker Network<br/>microservices-net<br/>Internal Communication}
    
    %% Connections
    Client --> Internet
    Internet --> Nginx
    Nginx --> Gateway
    
    Gateway --> AuthService
    Gateway --> UserService
    Gateway --> SocialLogService
    
    AuthService --> AuthDB
    UserService --> UserDB
    SocialLogService --> SocialLogDB
    UserService -.-> AuthDB
    
    %% Monitoring Connections
    Gateway -.-> Prometheus
    AuthService -.-> Prometheus
    UserService -.-> Prometheus
    SocialLogService -.-> Prometheus
    
    %% Docker Network
    Gateway --- DockerNet
    AuthService --- DockerNet
    UserService --- DockerNet
    SocialLogService --- DockerNet
    AuthDB --- DockerNet
    UserDB --- DockerNet
    SocialLogDB --- DockerNet
    Prometheus --- DockerNet
    
    %% Management
    Portainer -.-> DockerNet
    
    %% Styling
    classDef database fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef service fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef proxy fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef monitoring fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef network fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    
    class AuthDB,UserDB,SocialLogDB database
    class AuthService,UserService,Gateway,SocialLogService service
    class Nginx,Internet proxy
    class Prometheus,Portainer monitoring
    class DockerNet network


    🔧 Architettura Dettagliata:
🌐 Frontend Layer
Client: Browser/Mobile App che interagisce con l'API
🔒 Proxy Layer
Nginx: Reverse proxy, SSL termination, load balancing
Ports: 80 (HTTP) → 443 (HTTPS)
🚪 API Gateway Layer
Gateway Service: Punto di ingresso unico
Features: JWT auth, rate limiting, CORS, routing
Port: 3000
🎯 Microservices Layer
Auth Service (Port 3001):

User registration/login
JWT token management
Password security
User Service (Port 3002):

User profile management
QR code generation
Attendance tracking
CRUD operations
Social Log Service (Port 3003):

Logging di eventi sociali
Audit trail
Monitoraggio attività sociali
🗄️ Database Layer
Auth DB: User credentials, sessions
User DB: Profiles, QR codes, attendance data
Social Log DB: Logs e eventi audit
Cross-connection: User Service può leggere Auth DB per sync
📊 Monitoring Layer
Prometheus: Metrics e monitoring
Portainer: Container management via web UI
🌐 Network Layer
Docker Network: Comunicazione interna sicura tra servizi
Service Discovery: Automatic DNS resolution tra container
🚀 Flusso delle Richieste:
Client → Internet → Nginx → Gateway
Gateway verifica JWT e route la richiesta
Gateway → Auth/User/Social Log Service (based on route)
Services → Database per data persistence
Response torna indietro attraverso lo stesso path
Prometheus monitora tutto il flusso
Sistema scalabile, sicuro e monitorato! 🎉

 Schema Visivo Go Cloud Backend
                                🌍 INTERNET
                                     |
                            ┌────────▼────────┐
                            │   🔒 NGINX      │
                            │ Reverse Proxy   │
                            │   Port 80/443   │
                            └────────┬────────┘
                                     |
                            ┌────────▼────────┐
                            │   🚪 GATEWAY    │
                            │  API Gateway    │
                            │   Port 3000     │
                            │ • JWT Auth      │
                            │ • Rate Limit    │
                            │ • CORS          │
                            └────────┬────────┘
                                     |
                ┌────────────┬────────────┬────────────┐
                │            │            │            │
       ┌────────▼────────┐   │   ┌────────▼────────┐   │   ┌────────▼────────┐
       │  🔐 AUTH        │   │   │  👥 USER        │   │   │  📜 SOCIAL LOG  │
       │   SERVICE       │   │   │   SERVICE       │   │   │   SERVICE       │
       │  Port 3001      │   │   │  Port 3002      │   │   │  Port 3003      │
       │ • Login/Register│   │   │ • Profile Mgmt  │   │   │ • Social Events │
       │ • JWT Tokens    │   │   │ • QR Codes      │   │   │ • Audit Trail   │
       │ • Passwords     │   │   │ • Attendance    │   │   │ • Activity Log  │
       └────────┬────────┘   │   └────────┬────────┘   │   └────────┬────────┘
                │            │            │            │            │
                │            │            │            │            │
       ┌────────▼────────┐   │   ┌────────▼────────┐   │   ┌────────▼────────┐
       │  🗄️ AUTH DB     │   │   │  🗄️ USER DB     │   │   │  🗄️ SOCIAL LOG DB│
       │   PostgreSQL    │   │   │   PostgreSQL    │   │   │   PostgreSQL    │
       │   Port 5432     │   │   │   Port 5432     │   │   │   Port 5433     │
       │ • Users         │   │   │ • Profiles      │   │   │ • Social Logs   │
       │ • Credentials   │◄──┘   │ • QR Data       │   │   │ • Audit Events  │
       │ • Sessions      │       │ • Attendance    │   │   │                │
       └─────────────────┘       └─────────────────┘       └─────────────────┘
                        
                        🌐 DOCKER NETWORK
                      ┌─────────────────────┐
                      │  microservices-net  │
                      │  Internal Comms     │
                      └─────────────────────┘

                     📊 MONITORING LAYER
              ┌─────────────────┬─────────────────┐
              │                 │                 │
     ┌────────▼────────┐       │       ┌────────▼────────┐
     │ 📊 PROMETHEUS   │       │       │ 🐳 PORTAINER    │
     │   Monitoring    │       │       │   Container     │
     │   Port 9090     │       │       │   Management    │
     │ • Metrics       │       │       │ • Docker UI     │
     │ • Analytics     │       │       │ • Logs View     │
     └─────────────────┘       │       └─────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │    ☁️ GOOGLE        │
                    │   CLOUD COMPUTE     │
                    │      ENGINE         │
                    │  VM: 34.140.122.146 │
                    │   Ubuntu 22.04      │
                    └─────────────────────┘


                    🔄 Flusso delle Richieste:
👤 Client
   │
   │ HTTPS Request
   ▼
🔒 Nginx (80/443)
   │
   │ Proxy Pass
   ▼
🚪 Gateway (3000)
   │
   ├─ JWT Validation
   ├─ Rate Limiting  
   ├─ CORS Check
   │
   │ Route Decision
   ▼
┌─────────────┬─────────────┬─────────────┐
│             │             │             │
▼             ▼             ▼             ▼
🔐 Auth      👥 User       📜 Social Log
Service      Service      Service
(3001)       (3002)       (3003)
│             │             │
▼             ▼             ▼
🗄️ Auth DB   🗄️ User DB   🗄️ Social Log DB
(5432)       (5432)       (5433)


🎯 Porte e Servizi:

┌─────────────────────────────────────────┐
│              PORT MAPPING               │
├─────────────────────────────────────────┤
│ 🌐 External (Internet) Access:         │
│   • 80    → Nginx (HTTP)               │
│   • 443   → Nginx (HTTPS)              │
│   • 9090  → Prometheus (se aperto)     │
├─────────────────────────────────────────┤
│ 🔒 Internal (Docker Network) Only:     │
│   • 3000  → Gateway                    │
│   • 3001  → Auth Service               │
│   • 3002  → User Service               │
│   • 3003  → Social Log Service         │
│   • 5432  → PostgreSQL (Auth)          │
│   • 5432  → PostgreSQL (User)          │
│   • 5433  → PostgreSQL (Social Log)    │
└─────────────────────────────────────────┘

🏗️ Stack Tecnologico:
┌─────────────────────────────────────────┐
│              TECH STACK                 │
├─────────────────────────────────────────┤
│ 🔧 Backend: Go (Fiber Framework)       │
│ 🗄️ Database: PostgreSQL 15             │
│ 🐳 Container: Docker + Docker Compose  │
│ 🔒 Proxy: Nginx                        │
│ 📊 Monitoring: Prometheus              │
│ 🎛️ Management: Portainer               │
│ ☁️ Cloud: Google Cloud Platform        │
│ 🔐 Auth: JWT Tokens                    │
│ 🌐 API: RESTful + JSON                 │
└─────────────────────────────────────────┘

Sistema completamente containerizzato, scalabile e monitorato! 🚀
go-cloud-backend/
├── .dockerignore
├── .env
├── .gitignore
├── docker-compose.prod.yml
├── fix_metrics.sh
├── Makefile
├── readme.md
├── .github/
│   └── workflows/
│       smart-deploy.yml
├── auth-service/
│   ├── Dockerfile
│   ├── go.mod
│   ├── go.sum
│   ├── main.go
│   ├── database/
│   │   connection.go
│   ├── migrations/
│   │   0001_create_users.sql
│   │   0002_add_role_to_users.sql
│   │   0003_add_names_to_users.sql
│   │   0004_add_last_login_to_users.sql
│   │   0005_create_auth_log.sql
│   └── models/
│       auth_log.go
├── documentation/
│   ...
├── frontend/
│   └── index.html
├── gateway/
│   ├── Dockerfile
│   ├── go.mod
│   ├── go.sum
│   └── main.go
├── monitoring/
│   ├── dashboard-api/
│   │   ├── Dockerfile
│   │   ├── go.mod
│   │   ├── go.sum
│   │   ├── main.go
│   │   └── docs/
│   │       docs.go
│   │       swagger.json
│   │       swagger.yaml
│   └── prometheus-service/
│       ├── Dockerfile
│       ├── go.mod
│       ├── go.sum
│       ├── main.go
│       ├── prometheus-service.exe
│       ├── README.md
│       ├── config/
│       │   prometheus.yml
│       ├── metrics/
│       │   collectors.go
│       └── middleware/
│           metrics.go
├── nginx/
│   nginx.conf
├── shared/
│   go.mod
│   go.sum
│   └── metrics/
│       middleware.go
├── social-log-service/
│   db.go
│   Dockerfile
│   go.mod
│   go.sum
│   handler.go
│   main.go
│   model.go
│   README.md
│   schema.sql
│   social-log-service
│   social-log-service.exe
├── systemd/
│   go-microservices-auth.service
│   go-microservices-gateway.service
│   go-microservices-user.service
└── user-service/
    ├── Dockerfile
    ├── go.mod
    ├── go.sum
    ├── main
    ├── main.go
    ├── qr_handlers.go
    ├── user-service-test
    ├── database/
    │   connection.go
    ├── handlers/
    │   qr_handlers.go
    ├── migrations/
    │   0001_create_users.sql
    │   0003_create_attendance_events.sql
    │   0004_create_attendance.sql
    │   0005_add_role_to_users.sql
    │   0006_add_auth_fields_to_users.sql
    │   0007_add_role_column.sql
    │   0008_event_user_status_management.sql
    │   0009_create_attendance_triggers.sql
    │   0010_ensure_name_surname_columns.sql
    │   0011_fix_status_trigger.sql
    │   0012_automatic_qr_system_final.sql
    │   0013_add_timestamp_to_attendance_events.sql
    ├── models/
    │   qr_models.go
    ├── services/
    │   qr_service.go
    └── utils/
        jwt_utils.go