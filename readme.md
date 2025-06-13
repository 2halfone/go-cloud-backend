
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
    
    %% Database Layer
    AuthDB[(🗄️ Auth Database<br/>PostgreSQL<br/>Port 5432<br/>• Users<br/>• Credentials<br/>• Sessions)]
    
    UserDB[(🗄️ User Database<br/>PostgreSQL<br/>Port 5432<br/>• Profiles<br/>• QR Codes<br/>• Attendance<br/>• Metadata)]
    
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
    
    AuthService --> AuthDB
    UserService --> UserDB
    UserService -.-> AuthDB
    
    %% Monitoring Connections
    Gateway -.-> Prometheus
    AuthService -.-> Prometheus
    UserService -.-> Prometheus
    
    %% Docker Network
    Gateway --- DockerNet
    AuthService --- DockerNet
    UserService --- DockerNet
    AuthDB --- DockerNet
    UserDB --- DockerNet
    Prometheus --- DockerNet
    
    %% Management
    Portainer -.-> DockerNet
    
    %% Styling
    classDef database fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef service fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef proxy fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef monitoring fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef network fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    
    class AuthDB,UserDB database
    class AuthService,UserService,Gateway service
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
🗄️ Database Layer
Auth DB: User credentials, sessions
User DB: Profiles, QR codes, attendance data
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
Gateway → Auth/User Service (based on route)
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
                        ┌────────────┼────────────┐
                        │            │            │
               ┌────────▼────────┐   │   ┌────────▼────────┐
               │  🔐 AUTH        │   │   │  👥 USER        │
               │   SERVICE       │   │   │   SERVICE       │
               │  Port 3001      │   │   │  Port 3002      │
               │ • Login/Register│   │   │ • Profile Mgmt  │
               │ • JWT Tokens    │   │   │ • QR Codes      │
               │ • Passwords     │   │   │ • Attendance    │
               └────────┬────────┘   │   └────────┬────────┘
                        │            │            │
                        │            │            │
               ┌────────▼────────┐   │   ┌────────▼────────┐
               │  🗄️ AUTH DB     │   │   │  🗄️ USER DB     │
               │   PostgreSQL    │   │   │   PostgreSQL    │
               │   Port 5432     │   │   │   Port 5432     │
               │ • Users         │   │   │ • Profiles      │
               │ • Credentials   │◄──┘   │ • QR Data       │
               │ • Sessions      │       │ • Attendance    │
               └─────────────────┘       └─────────────────┘
                        
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
┌─────────────┬─────────────┐
│             │             │
▼             ▼             ▼
🔐 Auth      👥 User       📊 Metrics
Service      Service      Collection
(3001)       (3002)           │
│             │               │
▼             ▼               ▼
🗄️ Auth DB   🗄️ User DB    📊 Prometheus
(5432)       (5432)        (9090)


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
│   • 5432  → PostgreSQL (Auth)          │
│   • 5432  → PostgreSQL (User)          │
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