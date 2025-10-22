
# Create a comprehensive setup and deployment guide
setup_guide = """# Digital Forensic Toolkit - Setup and Deployment Guide

## Table of Contents
1. System Requirements
2. Development Environment Setup
3. Production Deployment
4. Configuration
5. Initial Data Setup
6. Monitoring and Maintenance
7. Troubleshooting

---

## 1. System Requirements

### Hardware Requirements

#### Development Environment:
- CPU: 8+ cores (Intel i7 or AMD Ryzen 7)
- RAM: 32GB minimum, 64GB recommended
- Storage: 1TB SSD (NVMe preferred)
- GPU: NVIDIA GPU with 8GB+ VRAM (for AI/ML)
- Network: 1Gbps Ethernet

#### Production Environment (per node):
- **Application Servers**:
  - CPU: 16+ cores
  - RAM: 64GB minimum, 128GB recommended
  - Storage: 500GB SSD

- **Processing Nodes (Spark)**:
  - CPU: 32+ cores
  - RAM: 256GB minimum
  - Storage: 2TB NVMe SSD

- **Elasticsearch Nodes**:
  - CPU: 16+ cores
  - RAM: 64GB minimum (50% for JVM heap)
  - Storage: 4TB SSD

- **Database Server**:
  - CPU: 16+ cores
  - RAM: 64GB minimum
  - Storage: 2TB SSD RAID 10

- **Storage Server**:
  - Storage: 100TB+ (evidence storage)
  - RAID 6 or distributed storage

### Software Requirements

#### Operating System:
- Ubuntu 22.04 LTS (recommended)
- Red Hat Enterprise Linux 9
- CentOS Stream 9
- Windows Server 2022 (limited support)

#### Runtime Dependencies:
- Python 3.11+
- Node.js 18 LTS
- Docker 24+
- Kubernetes 1.28+ (production)
- PostgreSQL 15+
- Elasticsearch 8.11+
- Redis 7+
- Apache Spark 3.5+

---

## 2. Development Environment Setup

### Step 1: Install System Dependencies

#### Ubuntu/Debian:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build essentials
sudo apt install -y build-essential git curl wget

# Install Python 3.11
sudo apt install -y python3.11 python3.11-dev python3.11-venv python3-pip

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install -y docker-compose-plugin
```

#### macOS:
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11 node@18 git docker docker-compose
```

### Step 2: Clone Repository

```bash
# Clone the repository
git clone https://github.com/your-org/forensic-toolkit.git
cd forensic-toolkit

# Checkout main branch
git checkout main
```

### Step 3: Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# venv\\Scripts\\activate  # Windows

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install Python dependencies
pip install -r requirements.txt

# Install forensic libraries
pip install pytsk3 pyewf volatility3 plaso dfvfs

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

**Backend .env Configuration:**
```
# Database
DATABASE_URL=postgresql://forensic:password@localhost:5432/forensic_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Elasticsearch
ELASTICSEARCH_HOSTS=http://localhost:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=changeme

# JWT Secret
JWT_SECRET_KEY=your-secret-key-here-change-in-production

# AWS Credentials (optional)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1

# Azure Credentials (optional)
AZURE_STORAGE_CONNECTION_STRING=your-connection-string

# GCP Credentials (optional)
GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
```

### Step 4: Frontend Setup

```bash
# Navigate to frontend directory
cd ../frontend

# Install Node.js dependencies
npm install

# Copy environment template
cp .env.local.example .env.local

# Edit .env.local
nano .env.local
```

**Frontend .env.local Configuration:**
```
NEXT_PUBLIC_API_URL=http://localhost:8000/api
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_ENV=development
```

### Step 5: Infrastructure Setup with Docker Compose

```bash
# Navigate to project root
cd ..

# Start infrastructure services
docker-compose up -d postgres redis elasticsearch spark-master spark-worker mongodb
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: forensic
      POSTGRES_PASSWORD: password
      POSTGRES_DB: forensic_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  mongodb:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

  spark-master:
    image: bitnami/spark:3.5
    environment:
      - SPARK_MODE=master
    ports:
      - "8080:8080"
      - "7077:7077"

  spark-worker:
    image: bitnami/spark:3.5
    environment:
      - SPARK_MODE=worker
      - SPARK_MASTER_URL=spark://spark-master:7077
      - SPARK_WORKER_MEMORY=4G
      - SPARK_WORKER_CORES=4
    depends_on:
      - spark-master

volumes:
  postgres_data:
  redis_data:
  es_data:
  mongo_data:
```

### Step 6: Database Initialization

```bash
# Activate backend virtual environment
cd backend
source venv/bin/activate

# Run database migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load initial data (optional)
python manage.py loaddata initial_data.json
```

### Step 7: Start Development Servers

**Terminal 1 - Backend API:**
```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Celery Worker:**
```bash
cd backend
source venv/bin/activate
celery -A tasks worker --loglevel=info --concurrency=4
```

**Terminal 3 - Celery Beat (Scheduler):**
```bash
cd backend
source venv/bin/activate
celery -A tasks beat --loglevel=info
```

**Terminal 4 - Frontend:**
```bash
cd frontend
npm run dev
```

### Step 8: Verify Installation

Open browser and navigate to:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/api/docs
- Elasticsearch: http://localhost:9200
- Spark UI: http://localhost:8080

---

## 3. Production Deployment

### Option A: Kubernetes Deployment

#### Prerequisites:
- Kubernetes cluster (1.28+)
- kubectl configured
- Helm 3.x installed

#### Step 1: Create Namespace

```bash
kubectl create namespace forensic-toolkit
kubectl config set-context --current --namespace=forensic-toolkit
```

#### Step 2: Create Secrets

```bash
# Create database secret
kubectl create secret generic database-credentials \\
  --from-literal=username=forensic \\
  --from-literal=password=secure-password

# Create JWT secret
kubectl create secret generic jwt-secret \\
  --from-literal=secret-key=$(openssl rand -base64 32)

# Create AWS credentials (if using)
kubectl create secret generic aws-credentials \\
  --from-file=credentials=~/.aws/credentials
```

#### Step 3: Deploy Infrastructure

```bash
# Deploy PostgreSQL
helm install postgres bitnami/postgresql \\
  --set auth.username=forensic \\
  --set auth.password=secure-password \\
  --set auth.database=forensic_db \\
  --set primary.persistence.size=100Gi

# Deploy Redis
helm install redis bitnami/redis \\
  --set auth.enabled=false \\
  --set master.persistence.size=10Gi

# Deploy Elasticsearch
helm install elasticsearch elastic/elasticsearch \\
  --set replicas=3 \\
  --set volumeClaimTemplate.resources.requests.storage=100Gi

# Deploy MongoDB
helm install mongodb bitnami/mongodb \\
  --set persistence.size=50Gi
```

#### Step 4: Deploy Application

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/configmaps/
kubectl apply -f k8s/backend-deployment.yaml
kubectl apply -f k8s/frontend-deployment.yaml
kubectl apply -f k8s/celery-deployment.yaml
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/ingress.yaml
```

**backend-deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: backend
        image: your-registry/forensic-toolkit-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: url
        - name: REDIS_URL
          value: redis://redis-master:6379/0
        - name: ELASTICSEARCH_HOSTS
          value: http://elasticsearch-master:9200
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
```

#### Step 5: Configure Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: forensic-toolkit-ingress
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-body-size: "10g"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - forensics.yourdomain.com
    secretName: forensics-tls
  rules:
  - host: forensics.yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend
            port:
              number: 8000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 3000
```

### Option B: Docker Compose Production

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: forensic
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
      POSTGRES_DB: forensic_db
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

  backend:
    image: your-registry/forensic-toolkit-backend:latest
    depends_on:
      - postgres
      - redis
      - elasticsearch
    environment:
      DATABASE_URL_FILE: /run/secrets/database_url
      REDIS_URL: redis://redis:6379/0
    secrets:
      - database_url
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '4'
          memory: 8G

  frontend:
    image: your-registry/forensic-toolkit-frontend:latest
    depends_on:
      - backend
    deploy:
      replicas: 2
      restart_policy:
        condition: on-failure

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - frontend
      - backend

secrets:
  db_password:
    file: ./secrets/db_password.txt
  database_url:
    file: ./secrets/database_url.txt

volumes:
  postgres_data:
  redis_data:
  es_data:
```

---

## 4. Configuration

### Application Configuration

**config.yaml:**
```yaml
application:
  name: "Digital Forensic Toolkit"
  version: "1.0.0"
  debug: false
  
security:
  jwt_expiration_hours: 24
  password_min_length: 12
  require_mfa: true
  max_login_attempts: 5
  
evidence:
  storage_path: "/mnt/evidence"
  max_upload_size_gb: 100
  supported_formats: ["E01", "EWF", "DD", "AFF4", "RAW"]
  hash_algorithms: ["MD5", "SHA1", "SHA256", "SHA512"]
  
processing:
  spark_master_url: "spark://spark-master:7077"
  spark_executor_memory: "8G"
  spark_executor_cores: 4
  max_parallel_jobs: 10
  
elasticsearch:
  index_prefix: "forensic"
  number_of_shards: 5
  number_of_replicas: 2
  refresh_interval: "30s"
  
ai_ml:
  model_path: "/models"
  gpu_enabled: true
  batch_size: 32
  confidence_threshold: 0.85
  
investigator_wellness:
  enable_content_filtering: true
  blur_threshold: 0.9
  max_exposure_hours_per_day: 4
  break_reminder_minutes: 60
  
chain_of_custody:
  blockchain_enabled: true
  blockchain_network: "hyperledger-fabric"
  require_digital_signature: true
```

### Nginx Configuration

**nginx.conf:**
```nginx
upstream backend {
    server backend:8000;
}

upstream frontend {
    server frontend:3000;
}

server {
    listen 80;
    server_name forensics.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name forensics.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    client_max_body_size 10G;
    
    location /api {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
    
    location /ws {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 5. Initial Data Setup

### Create Admin User

```python
from app.models import User
from app.auth import hash_password

admin = User(
    username="admin",
    email="admin@forensics.local",
    password_hash=hash_password("SecurePassword123!"),
    role="ADMIN",
    is_active=True
)
db.session.add(admin)
db.session.commit()
```

### Load Forensic Tools Configuration

```bash
python manage.py load_tools_config --file tools_config.json
```

### Initialize AI Models

```bash
python manage.py download_models
python manage.py verify_models
```

---

## 6. Monitoring and Maintenance

### Prometheus Metrics

**prometheus.yml:**
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'backend'
    static_configs:
      - targets: ['backend:8000']
  
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
  
  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch:9200']
```

### Grafana Dashboards

Import pre-built dashboards:
- System Resources
- Application Performance
- Case Processing Metrics
- Investigator Activity
- Evidence Storage Utilization

### Log Aggregation

Configure Filebeat to ship logs to Elasticsearch:

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/forensic-toolkit/*.log
  fields:
    service: forensic-toolkit

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "forensic-logs-%{+yyyy.MM.dd}"
```

### Backup Strategy

**Daily Backups:**
```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d)
BACKUP_DIR="/backups/$DATE"

# Database backup
pg_dump -h postgres -U forensic forensic_db | gzip > $BACKUP_DIR/db.sql.gz

# Elasticsearch backup
curl -X PUT "elasticsearch:9200/_snapshot/backup/$DATE?wait_for_completion=true"

# Evidence metadata
tar -czf $BACKUP_DIR/metadata.tar.gz /mnt/evidence/metadata/

# Retention: keep 30 days
find /backups -type d -mtime +30 -exec rm -rf {} +
```

---

## 7. Troubleshooting

### Common Issues

**Issue: Elasticsearch cluster health red**
```bash
# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check unassigned shards
curl -X GET "localhost:9200/_cat/shards?v&h=index,shard,state,unassigned.reason"

# Force allocate unassigned shards (emergency only)
curl -X POST "localhost:9200/_cluster/reroute?retry_failed"
```

**Issue: High memory usage**
```bash
# Check Java heap usage (Elasticsearch)
curl -X GET "localhost:9200/_nodes/stats/jvm?pretty"

# Adjust heap size
export ES_JAVA_OPTS="-Xms8g -Xmx8g"

# Clear cache
curl -X POST "localhost:9200/_cache/clear"
```

**Issue: Slow evidence processing**
```bash
# Check Spark cluster
curl http://localhost:8080/json/

# Increase Spark resources
spark-submit --executor-memory 16G --executor-cores 8 --num-executors 10

# Check disk I/O
iostat -x 1
```

**Issue: Database connection pool exhausted**
```python
# Increase pool size in config
DATABASE_POOL_SIZE = 50
DATABASE_MAX_OVERFLOW = 100
```

### Log Locations

- **Backend**: `/var/log/forensic-toolkit/backend.log`
- **Celery**: `/var/log/forensic-toolkit/celery.log`
- **Nginx**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- **PostgreSQL**: `/var/log/postgresql/postgresql-15-main.log`
- **Elasticsearch**: `/var/log/elasticsearch/`

### Health Checks

```bash
# Backend health
curl http://localhost:8000/health

# Database connection
psql -h localhost -U forensic -d forensic_db -c "SELECT 1"

# Redis connection
redis-cli ping

# Elasticsearch health
curl -X GET "localhost:9200/_cluster/health"
```

---

## Support and Documentation

- **Documentation**: https://docs.forensic-toolkit.local
- **API Reference**: https://api.forensic-toolkit.local/docs
- **Support Email**: support@forensic-toolkit.local
- **Community Forum**: https://forum.forensic-toolkit.local

"""

with open('setup_deployment_guide.md', 'w') as f:
    f.write(setup_guide)

print("Setup and Deployment Guide Created: setup_deployment_guide.md")
print(f"Total Size: {len(setup_guide)} characters")
