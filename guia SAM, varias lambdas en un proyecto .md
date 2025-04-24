# Tutorial Completo: Desarrollo Serverless con AWS SAM, Múltiples Lambdas y Código Compartido

## Introducción

Este tutorial te guiará en la creación de un proyecto serverless robusto y escalable utilizando AWS SAM (Serverless Application Model). Aprenderás a:

- Estructurar un proyecto con múltiples funciones Lambda
- Implementar código compartido entre funciones
- Aprovechar infraestructura existente (API Gateway, VPC, Lambda Layers)
- Configurar un pipeline CI/CD con GitHub Actions y OIDC
- Gestionar configuraciones y secretos con GitHub Environments
- Realizar pruebas locales completas antes del despliegue

## Tabla de Contenidos

1. [Conceptos Fundamentales](#1-conceptos-fundamentales)
2. [Arquitectura del Proyecto](#2-arquitectura-del-proyecto)
3. [Estructura del Proyecto](#3-estructura-del-proyecto)
4. [Configuración Inicial](#4-configuración-inicial)
5. [Implementación del Código Compartido](#5-implementación-del-código-compartido)
6. [Desarrollo de las Funciones Lambda](#6-desarrollo-de-las-funciones-lambda)
7. [Configuración de SAM Template](#7-configuración-de-sam-template)
8. [Configuración de GitHub y CI/CD](#8-configuración-de-github-y-cicd)
9. [Pruebas Locales](#9-pruebas-locales)
10. [Despliegue a Producción](#10-despliegue-a-producción)
11. [Monitoreo y Mantenimiento](#11-monitoreo-y-mantenimiento)
12. [Resolución de Problemas Comunes](#12-resolución-de-problemas-comunes)

## 1. Conceptos Fundamentales

### 1.1 ¿Por qué múltiples Lambdas en un proyecto?

Imagina tu aplicación serverless como un equipo de especialistas en lugar de un empleado que hace todo. Cada Lambda es un especialista en una tarea específica:

- **Lambda de Usuarios**: Maneja operaciones relacionadas con usuarios
- **Lambda de Productos**: Gestiona el catálogo de productos
- **Lambda de Órdenes**: Procesa pedidos y transacciones

Esta separación ofrece:
- Mejor organización del código
- Escalabilidad independiente según la demanda
- Facilidad para el mantenimiento y actualización
- Mayor seguridad (principio de mínimo privilegio)

### 1.2 El valor del código compartido

El código compartido es como una biblioteca central que todas tus Lambdas pueden consultar. Esto evita duplicación y mantiene la consistencia. Por ejemplo, si todas tus Lambdas necesitan formatear fechas de la misma manera, el código para esto se escribe una vez y se comparte.

### 1.3 Aprovechando infraestructura existente

En lugar de crear nuevos recursos, este enfoque utiliza:
- **API Gateway existente**: Se integra con endpoints ya configurados
- **VPC existente**: Aprovecha la configuración de red establecida
- **Lambda Layers**: Reutiliza dependencias comunes ya empaquetadas
- **GitHub Environments**: Centraliza la gestión de configuraciones

## 2. Arquitectura del Proyecto

La arquitectura sigue un modelo de microservicios serverless:

```
Cliente → API Gateway → Lambda Functions → MongoDB Atlas
                         ↓
                    Lambda Layers (dependencias)
                         ↓
                    Código Compartido
                         ↓
                    VPC (subredes, security groups)
```

## 3. Estructura del Proyecto

```
mi-proyecto-serverless/
├── template.yaml                 # Plantilla SAM principal
├── .github/
│   └── workflows/
│       └── deploy.yml           # Pipeline CI/CD
├── lambdas/                     # Directorio para todas las Lambdas
│   ├── users/                   # Lambda de usuarios
│   │   ├── app.py              # Código principal
│   │   ├── requirements.txt    # Dependencias específicas
│   │   └── __init__.py
│   ├── products/               # Lambda de productos
│   │   ├── app.py
│   │   ├── requirements.txt
│   │   └── __init__.py
│   └── orders/                 # Lambda de órdenes
│       ├── app.py
│       ├── requirements.txt
│       └── __init__.py
├── shared/                     # Código compartido
│   ├── __init__.py
│   ├── date_utils.py          # Utilidades de fecha
│   ├── db_connection.py       # Conexión a base de datos
│   ├── validators.py          # Validadores comunes
│   ├── custom_exceptions.py   # Excepciones personalizadas
│   └── models/                # Modelos de datos
│       ├── __init__.py
│       ├── user_model.py
│       └── product_model.py
├── tests/                     # Tests unitarios e integración
│   ├── unit/
│   │   ├── test_shared/
│   │   ├── test_users.py
│   │   ├── test_products.py
│   │   └── test_orders.py
│   └── integration/
├── events/                    # Eventos de prueba para SAM local
│   ├── get_users.json
│   ├── create_user.json
│   └── update_product.json
├── scripts/                   # Scripts de utilidad
│   ├── test_local.sh
│   └── setup_local_env.sh
├── .gitignore
├── README.md
└── conftest.py               # Configuración para pytest
```

## 4. Configuración Inicial

### 4.1 Prerrequisitos

Antes de comenzar, necesitarás:

1. **Cuenta de AWS** con permisos para:
   - Crear/modificar funciones Lambda
   - Acceder a API Gateway existente
   - Utilizar VPC, subredes y security groups existentes
   - Acceder a Lambda Layers existentes

2. **Cuenta de GitHub** para el repositorio y GitHub Actions

3. **Herramientas locales**:
   - Python 3.11
   - AWS CLI
   - AWS SAM CLI
   - Docker (para pruebas locales con SAM)
   - Git

### 4.2 Instalación de herramientas

#### Windows
```bash
# Instalar Python 3.11 desde python.org
# Instalar AWS CLI desde aws.amazon.com
# Instalar SAM CLI
winget install -e --id Amazon.AWSAM
```

#### macOS
```bash
# Usando Homebrew
brew install python@3.11
brew install awscli
brew tap aws/tap
brew install aws-sam-cli
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### 4.3 Inicialización del proyecto

```bash
# Crear directorio del proyecto
mkdir mi-proyecto-serverless
cd mi-proyecto-serverless

# Inicializar proyecto SAM
sam init --runtime python3.11 --name mi-proyecto-serverless --app-template hello-world

# Crear estructura de directorios
mkdir -p lambdas/{users,products,orders}
mkdir -p shared/{models}
mkdir -p tests/{unit/test_shared,integration}
mkdir -p events scripts .github/workflows
```

## 5. Implementación del Código Compartido

### 5.1 Utilidades de fecha (shared/date_utils.py)

```python
from datetime import datetime, timezone, timedelta
import pytz

class DateFormatter:
    """Formateador de fechas para mantener consistencia en toda la aplicación"""
    
    def __init__(self, timezone_name='America/Mexico_City'):
        self.timezone = pytz.timezone(timezone_name)
    
    def to_iso_format(self, date_obj=None):
        """Convierte una fecha a formato ISO 8601"""
        if date_obj is None:
            date_obj = datetime.now(self.timezone)
        elif isinstance(date_obj, str):
            date_obj = self.parse_date(date_obj)
        
        return date_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    def to_local_format(self, date_obj=None, format_string='%Y-%m-%d %H:%M:%S'):
        """Convierte una fecha a formato local"""
        if date_obj is None:
            date_obj = datetime.now(self.timezone)
        elif isinstance(date_obj, str):
            date_obj = self.parse_date(date_obj)
        
        if date_obj.tzinfo is None:
            date_obj = self.timezone.localize(date_obj)
        else:
            date_obj = date_obj.astimezone(self.timezone)
        
        return date_obj.strftime(format_string)
    
    def parse_date(self, date_string):
        """Parsea una cadena de fecha en varios formatos comunes"""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d',
            '%Y/%m/%d',
            '%d-%m-%Y',
            '%d/%m/%Y'
        ]
        
        for fmt in formats:
            try:
                parsed_date = datetime.strptime(date_string, fmt)
                if parsed_date.tzinfo is None:
                    parsed_date = self.timezone.localize(parsed_date)
                return parsed_date
            except ValueError:
                continue
        
        raise ValueError(f"No se pudo parsear la fecha: {date_string}")
```

### 5.2 Conexión a base de datos (shared/db_connection.py)

```python
import os
import logging
import time
import boto3
import json
from botocore.exceptions import ClientError
from pymongo import MongoClient

logger = logging.getLogger()

class DatabaseConnection:
    """Maneja conexiones a MongoDB con patrón singleton"""
    
    _instance = None
    _client = None
    _last_connection_time = 0
    _connection_ttl = 300  # 5 minutos
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
        return cls._instance
    
    def get_mongodb_uri(self):
        """Obtiene la URI de MongoDB desde variables de entorno o Secrets Manager"""
        direct_uri = os.environ.get('MONGODB_URI')
        if direct_uri:
            return direct_uri
        
        secret_name = os.environ.get('MONGODB_SECRET_ARN')
        if not secret_name:
            raise ValueError("No se encontró MONGODB_URI ni MONGODB_SECRET_ARN")
        
        region = os.environ.get('AWS_REGION', 'us-east-1')
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=region)
        
        try:
            response = client.get_secret_value(SecretId=secret_name)
            secret_string = response['SecretString']
            secret_data = json.loads(secret_string)
            return secret_data.get('uri')
        except ClientError as e:
            logger.error(f"Error al obtener secreto: {str(e)}")
            raise
    
    def get_client(self):
        """Obtiene o reutiliza un cliente MongoDB"""
        current_time = time.time()
        
        if self._client is None or (current_time - self._last_connection_time) > self._connection_ttl:
            mongodb_uri = self.get_mongodb_uri()
            logger.debug("Conectando a MongoDB...")
            self._client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
            self._last_connection_time = current_time
            logger.info("Conexión a MongoDB creada o renovada")
        
        return self._client
    
    def get_collection(self, collection_name=None):
        """Obtiene una colección específica"""
        if collection_name is None:
            collection_name = os.environ.get('COLLECTION_NAME')
        
        if not collection_name:
            raise ValueError("No se especificó nombre de colección")
        
        client = self.get_client()
        db_name = os.environ.get('DB_NAME', 'sampledb')
        db = client[db_name]
        return db[collection_name]
```

### 5.3 Validadores (shared/validators.py)

```python
import re
from datetime import datetime

class Validators:
    """Validadores comunes para toda la aplicación"""
    
    @staticmethod
    def validate_email(email):
        """Valida formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone):
        """Valida formato de teléfono"""
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone))
    
    @staticmethod
    def validate_date(date_string):
        """Valida que una cadena sea una fecha válida"""
        try:
            datetime.strptime(date_string, '%Y-%m-%d')
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_required_fields(data, required_fields):
        """Valida que todos los campos requeridos estén presentes"""
        missing = []
        for field in required_fields:
            if field not in data or data[field] is None:
                missing.append(field)
        return len(missing) == 0, missing
    
    @staticmethod
    def sanitize_input(data):
        """Limpia y sanitiza datos de entrada"""
        if isinstance(data, dict):
            return {k: Validators.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [Validators.sanitize_input(item) for item in data]
        elif isinstance(data, str):
            return data.strip()
        return data
```

## 6. Desarrollo de las Funciones Lambda

### 6.1 Lambda de Usuarios (lambdas/users/app.py)

```python
import json
import os
import logging
from shared.date_utils import DateFormatter
from shared.db_connection import DatabaseConnection
from shared.validators import Validators

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Instancias globales para reutilización
date_formatter = DateFormatter()
db_connection = DatabaseConnection()

def lambda_handler(event, context):
    """Maneja peticiones para la gestión de usuarios"""
    logger.info(f"Users Lambda - Received event: {json.dumps(event)}")
    
    try:
        collection = db_connection.get_collection()
        
        http_method = event.get('httpMethod', '')
        path = event.get('path', '')
        
        if http_method == 'GET' and path == '/users':
            # Obtener todos los usuarios
            users = list(collection.find({}, {'_id': 0}))
            
            for user in users:
                if 'created_at' in user:
                    user['created_at'] = date_formatter.to_local_format(user['created_at'])
                if 'last_login' in user:
                    user['last_login'] = date_formatter.to_iso_format(user['last_login'])
            
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"users": users})
            }
            
        elif http_method == 'POST' and path == '/users':
            # Crear nuevo usuario
            body = json.loads(event.get('body', '{}'))
            
            # Sanitizar y validar datos
            sanitized_data = Validators.sanitize_input(body)
            
            # Validar campos requeridos
            is_valid, missing_fields = Validators.validate_required_fields(
                sanitized_data, 
                ['name', 'email']
            )
            
            if not is_valid:
                return {
                    "statusCode": 400,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "error": "Campos requeridos faltantes",
                        "missing_fields": missing_fields
                    })
                }
            
            # Validar email
            if not Validators.validate_email(sanitized_data['email']):
                return {
                    "statusCode": 400,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"error": "Email inválido"})
                }
            
            # Añadir timestamps
            sanitized_data['created_at'] = date_formatter.get_current_timestamp()
            sanitized_data['updated_at'] = date_formatter.get_current_timestamp()
            
            result = collection.insert_one(sanitized_data)
            
            return {
                "statusCode": 201,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "message": "Usuario creado",
                    "id": str(result.inserted_id),
                    "created_at": date_formatter.to_iso_format(sanitized_data['created_at'])
                })
            }
            
        else:
            return {
                "statusCode": 404,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Ruta no encontrada"})
            }
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }
```

## 7. Configuración de SAM Template

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: Aplicación Serverless con múltiples Lambda y código compartido

Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, test, stage, prod]
    Description: Entorno de despliegue

  MongoDbUri:
    Type: String
    NoEcho: true
    Description: URI de conexión a MongoDB Atlas

  DatabaseName:
    Type: String
    Default: sampledb
    Description: Nombre de la base de datos MongoDB

  ApiGatewayType:
    Type: String
    Default: http
    AllowedValues: [http, rest]
    Description: Tipo de API Gateway existente

  ExistingApiId:
    Type: String
    Description: ID de la API Gateway existente

  ExistingApiStageName:
    Type: String
    Default: dev
    Description: Nombre del stage de la API Gateway existente

  ExistingVpcId:
    Type: String
    Description: ID de la VPC existente

  ExistingSubnetIds:
    Type: CommaDelimitedList
    Description: Lista separada por comas de IDs de subredes existentes

  ExistingSecurityGroupId:
    Type: String
    Description: ID del grupo de seguridad existente

  ExistingLayerArn:
    Type: String
    Description: ARN de la capa (layer) existente con las dependencias

  RootResourceId:
    Type: String
    Default: ""
    Description: ID del recurso raíz de la API Gateway (solo para REST API)

Globals:
  Function:
    Runtime: python3.11
    Architectures: [x86_64]
    MemorySize: 256
    Timeout: 10
    Environment:
      Variables:
        MONGODB_SECRET_ARN: !Ref MongoDBSecret
        DB_NAME: !Ref DatabaseName
        ENVIRONMENT: !Ref Environment
        LOG_LEVEL: INFO
        PYTHONPATH: "/var/task/shared:/var/task"
    VpcConfig:
      SecurityGroupIds:
        - !Ref ExistingSecurityGroupId
      SubnetIds: !Ref ExistingSubnetIds
    Layers:
      - !Ref ExistingLayerArn

Resources:
  # Secreto compartido para MongoDB
  MongoDBSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Sub '${AWS::StackName}-mongodb-${Environment}'
      Description: Credenciales de MongoDB
      SecretString: !Sub '{"uri": "${MongoDbUri}"}'

  # Lambda 1: Gestión de Usuarios
  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub '${AWS::StackName}-users-${Environment}'
      CodeUri: .
      Handler: lambdas.users.app.lambda_handler
      Environment:
        Variables:
          COLLECTION_NAME: users
      Policies:
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - ec2:CreateNetworkInterface
                - ec2:DescribeNetworkInterfaces
                - ec2:DeleteNetworkInterface
              Resource: "*"
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
                - secretsmanager:DescribeSecret
              Resource: !Ref MongoDBSecret

  UsersFunctionLogs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/lambda/${UsersFunction}'
      RetentionInDays: 7

  # Lambda 2: Gestión de Productos
  ProductsFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub '${AWS::StackName}-products-${Environment}'
      CodeUri: .
      Handler: lambdas.products.app.lambda_handler
      Environment:
        Variables:
          COLLECTION_NAME: products
      Policies:
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - ec2:CreateNetworkInterface
                - ec2:DescribeNetworkInterfaces
                - ec2:DeleteNetworkInterface
              Resource: "*"
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
                - secretsmanager:DescribeSecret
              Resource: !Ref MongoDBSecret

  ProductsFunctionLogs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/lambda/${ProductsFunction}'
      RetentionInDays: 7

  # Lambda 3: Gestión de Órdenes
  OrdersFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub '${AWS::StackName}-orders-${Environment}'
      CodeUri: .
      Handler: lambdas.orders.app.lambda_handler
      Environment:
        Variables:
          COLLECTION_NAME: orders
      Policies:
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - ec2:CreateNetworkInterface
                - ec2:DescribeNetworkInterfaces
                - ec2:DeleteNetworkInterface
              Resource: "*"
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
                - secretsmanager:DescribeSecret
              Resource: !Ref MongoDBSecret

  OrdersFunctionLogs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/lambda/${OrdersFunction}'
      RetentionInDays: 7

  # INTEGRACIONES PARA API HTTP
  UsersApiIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Condition: IsHttpApi
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ApiId: !Ref ExistingApiId
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${UsersFunction.Arn}/invocations'
      PayloadFormatVersion: '2.0'
      IntegrationMethod: POST

  UsersApiRoute:
    Type: AWS::ApiGatewayV2::Route
    Condition: IsHttpApi
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ApiId: !Ref ExistingApiId
      RouteKey: 'ANY /users/{proxy+}'
      Target: !Sub 'integrations/${UsersApiIntegration}'

  ProductsApiIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Condition: IsHttpApi
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ApiId: !Ref ExistingApiId
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${ProductsFunction.Arn}/invocations'
      PayloadFormatVersion: '2.0'
      IntegrationMethod: POST

  ProductsApiRoute:
    Type: AWS::ApiGatewayV2::Route
    Condition: IsHttpApi
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ApiId: !Ref ExistingApiId
      RouteKey: 'ANY /products/{proxy+}'
      Target: !Sub 'integrations/${ProductsApiIntegration}'

  OrdersApiIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Condition: IsHttpApi
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ApiId: !Ref ExistingApiId
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub 'arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${OrdersFunction.Arn}/invocations'
      PayloadFormatVersion: '2.0'
      IntegrationMethod: POST

  OrdersApiRoute:
    Type: AWS::ApiGatewayV2::Route
    Condition: IsHttpApi
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      ApiId: !Ref ExistingApiId
      RouteKey: 'ANY /orders/{proxy+}'
      Target: !Sub 'integrations/${OrdersApiIntegration}'

  # PERMISOS PARA API HTTP
  UsersApiPermission:
    Type: AWS::Lambda::Permission
    Condition: IsHttpApi
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref UsersFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/*/users/*'

  ProductsApiPermission:
    Type: AWS::Lambda::Permission
    Condition: IsHttpApi
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref ProductsFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/*/products/*'

  OrdersApiPermission:
    Type: AWS::Lambda::Permission
    Condition: IsHttpApi
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref OrdersFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub 'arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ExistingApiId}/*/*/orders/*'

Conditions:
  IsHttpApi: !Equals [!Ref ApiGatewayType, "http"]
  IsRestApi: !Equals [!Ref ApiGatewayType, "rest"]

Outputs:
  UsersFunctionArn:
    Description: ARN de la función Lambda de usuarios
    Value: !GetAtt UsersFunction.Arn

  ProductsFunctionArn:
    Description: ARN de la función Lambda de productos
    Value: !GetAtt ProductsFunction.Arn

  OrdersFunctionArn:
    Description: ARN de la función Lambda de órdenes
    Value: !GetAtt OrdersFunction.Arn

  UsersApiEndpoint:
    Description: URL del endpoint de usuarios
    Value: !Sub 'https://${ExistingApiId}.execute-api.${AWS::Region}.amazonaws.com/${ExistingApiStageName}/users'

  ProductsApiEndpoint:
    Description: URL del endpoint de productos
    Value: !Sub 'https://${ExistingApiId}.execute-api.${AWS::Region}.amazonaws.com/${ExistingApiStageName}/products'

  OrdersApiEndpoint:
    Description: URL del endpoint de órdenes
    Value: !Sub 'https://${ExistingApiId}.execute-api.${AWS::Region}.amazonaws.com/${ExistingApiStageName}/orders'
```

## 8. Configuración de GitHub y CI/CD

### 8.1 Configuración de GitHub Environments

Los Environments en GitHub son como diferentes escenarios donde tu aplicación puede vivir. Piensa en ellos como diferentes edificios: desarrollo (dev), pruebas (test), preparación (stage) y producción (prod). Cada uno tiene sus propias llaves y configuraciones.

Para configurar los environments:

1. Ve a tu repositorio en GitHub
2. Haz clic en "Settings" → "Environments"
3. Crea un environment para cada entorno (dev, test, stage, prod)
4. Para cada environment, configura:

**Variables de entorno** (Environment variables):
- `AWS_ROLE_ARN`: ARN del rol IAM para ese entorno
- `AWS_REGION`: Región AWS (ej. us-east-1)
- `STACK_NAME`: Nombre base del stack CloudFormation
- `ENVIRONMENT`: Nombre del entorno (dev, test, etc.)
- `DATABASE_NAME`: Nombre de la base de datos MongoDB
- `API_GATEWAY_TYPE`: Tipo de API Gateway (http o rest)
- `EXISTING_API_ID`: ID de API Gateway existente
- `EXISTING_API_STAGE_NAME`: Nombre del stage (ej. dev, prod)
- `EXISTING_VPC_ID`: ID de VPC existente
- `EXISTING_SUBNET_IDS`: IDs de subredes separados por comas
- `EXISTING_SECURITY_GROUP_ID`: ID del grupo de seguridad
- `EXISTING_LAYER_ARN`: ARN del layer existente con dependencias
- `ROOT_RESOURCE_ID`: ID del recurso raíz (solo para API REST)

**Secretos de entorno** (Environment secrets):
- `MONGODB_URI`: URI de conexión a MongoDB Atlas

### 8.2 Configuración del Pipeline CI/CD

El workflow de GitHub Actions automatiza todo el proceso de pruebas y despliegue. Crea el archivo `.github/workflows/deploy.yml`:

```yaml
name: Deploy Serverless Application

on:
  push:
    branches: [main, master, develop, 'release/*']
  pull_request:
    branches: [main, master, develop]

permissions:
  id-token: write  # Necesario para OIDC
  contents: read   # Necesario para checkout

jobs:
  test-and-deploy:
    runs-on: ubuntu-latest
    environment: ${{ github.ref == 'refs/heads/master' && 'prod' || github.ref == 'refs/heads/develop' && 'dev' || startsWith(github.ref, 'refs/heads/release/') && 'stage' || 'test' }}

    steps:
      - name: Debug Environment Variables
        run: |
          echo "GitHub Variables:"
          echo "AWS_ROLE_ARN: ${{ vars.AWS_ROLE_ARN }}"
          echo "AWS_REGION: ${{ vars.AWS_REGION }}"
          echo "STACK_NAME: ${{ vars.STACK_NAME }}"
          echo "Environment: ${{ vars.ENVIRONMENT }}"
          echo "DATABASE_NAME: ${{ vars.DATABASE_NAME }}"
          echo "API_GATEWAY_TYPE: ${{ vars.API_GATEWAY_TYPE }}"
          echo "EXISTING_API_ID: ${{ vars.EXISTING_API_ID }}"
          echo "EXISTING_API_STAGE_NAME: ${{ vars.EXISTING_API_STAGE_NAME }}"
          echo "EXISTING_VPC_ID: ${{ vars.EXISTING_VPC_ID }}"
          echo "EXISTING_SUBNET_IDS: ${{ vars.EXISTING_SUBNET_IDS }}"
          echo "EXISTING_SECURITY_GROUP_ID: ${{ vars.EXISTING_SECURITY_GROUP_ID }}"
          echo "EXISTING_LAYER_ARN: ${{ vars.EXISTING_LAYER_ARN }}"
          echo "ROOT_RESOURCE_ID: ${{ vars.ROOT_RESOURCE_ID }}"
          
          echo "GitHub Context Information:"
          echo "Repository: ${{ github.repository }}"
          echo "Branch: ${{ github.ref }}"
          echo "Workflow: ${{ github.workflow }}"

      - name: Checkout repository
        uses: actions/checkout@v3

      - name: Set up Python 3.11
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest pytest-mock boto3
          
          # Instalar dependencias compartidas
          if [ -f shared/requirements.txt ]; then
            pip install -r shared/requirements.txt
          fi
          
          # Instalar dependencias de cada Lambda
          for lambda_dir in lambdas/*; do
            if [ -f "$lambda_dir/requirements.txt" ]; then
              pip install -r "$lambda_dir/requirements.txt"
            fi
          done

      - name: Run tests
        env:
          PYTHONPATH: "${{ github.workspace }}/shared:${{ github.workspace }}"
        run: |
          python -m pytest tests/unit/ -v
          python -m pytest tests/integration/ -v

      - name: Configure AWS credentials with OIDC
        if: github.event_name == 'push'
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          mask-aws-account-id: 'no'

      - name: Get API Gateway Root Resource ID
        if: github.event_name == 'push' && vars.API_GATEWAY_TYPE == 'rest'
        id: get-root-id
        run: |
          ROOT_ID=$(aws apigateway get-resources --rest-api-id ${{ vars.EXISTING_API_ID }} --query "items[?path=='/'].id" --output text)
          echo "ROOT_RESOURCE_ID=$ROOT_ID" >> $GITHUB_OUTPUT
          echo "Obtained Root Resource ID: $ROOT_ID"

      - name: Check and delete failed stack if needed
        if: github.event_name == 'push'
        run: |
          STACK_STATUS=$(aws cloudformation describe-stacks --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }} --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "STACK_NOT_FOUND")
          
          if [[ $STACK_STATUS == *"FAILED"* || $STACK_STATUS == *"ROLLBACK"* ]]; then
            echo "Stack is in $STACK_STATUS state. Deleting..."
            aws cloudformation delete-stack --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }}
            aws cloudformation wait stack-delete-complete --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }}
            echo "Stack deleted successfully."
          elif [[ $STACK_STATUS != "STACK_NOT_FOUND" ]]; then
            echo "Stack exists and is in $STACK_STATUS state."
          else
            echo "Stack does not exist yet."
          fi

      - name: Install AWS SAM CLI
        if: github.event_name == 'push'
        run: |
          pip install aws-sam-cli

      - name: Build with SAM
        if: github.event_name == 'push'
        run: |
          sam build

      - name: Deploy with SAM
        if: github.event_name == 'push'
        run: |
          PARAMETERS="Environment=${{ vars.ENVIRONMENT }} "
          PARAMETERS+="MongoDbUri=${{ secrets.MONGODB_URI }} "
          PARAMETERS+="DatabaseName=${{ vars.DATABASE_NAME }} "
          PARAMETERS+="ApiGatewayType=${{ vars.API_GATEWAY_TYPE }} "
          PARAMETERS+="ExistingApiId=${{ vars.EXISTING_API_ID }} "
          PARAMETERS+="ExistingApiStageName=${{ vars.EXISTING_API_STAGE_NAME }} "
          PARAMETERS+="ExistingVpcId=${{ vars.EXISTING_VPC_ID }} "
          PARAMETERS+="ExistingSubnetIds=${{ vars.EXISTING_SUBNET_IDS }} "
          PARAMETERS+="ExistingSecurityGroupId=${{ vars.EXISTING_SECURITY_GROUP_ID }} "
          PARAMETERS+="ExistingLayerArn=${{ vars.EXISTING_LAYER_ARN }} "
          
          if [ "${{ vars.API_GATEWAY_TYPE }}" = "rest" ]; then
            PARAMETERS+="RootResourceId=${{ vars.ROOT_RESOURCE_ID }} "
          fi
          
          echo "Parámetros: $PARAMETERS"
          
          sam deploy --no-confirm-changeset --no-fail-on-empty-changeset \
            --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }} \
            --resolve-s3 \
            --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
            --parameter-overrides $PARAMETERS

      - name: Verify deployment
        if: github.event_name == 'push'
        run: |
          echo "Verificando el despliegue del stack"
          STACK_STATUS=$(aws cloudformation describe-stacks --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }} --query "Stacks[0].StackStatus" --output text)
          echo "Estado final del stack: $STACK_STATUS"
          
          if [[ $STACK_STATUS == "CREATE_COMPLETE" || $STACK_STATUS == "UPDATE_COMPLETE" ]]; then
            echo "✅ Despliegue exitoso"
            API_URL=$(aws cloudformation describe-stacks --stack-name ${{ vars.STACK_NAME }}-${{ vars.ENVIRONMENT }} --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" --output text)
            if [[ ! -z "$API_URL" ]]; then
              echo "🔗 API URL: $API_URL"
            fi
          else
            echo "❌ Despliegue fallido o en progreso"
            exit 1
          fi
```

## 9. Pruebas Locales

### 9.1 Configuración del Entorno Local

Crea un script para configurar el entorno local (`scripts/setup_local_env.sh`):

```bash
#!/bin/bash

# Crear y activar entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Instalar dependencias
pip install -r requirements.txt
pip install pytest pytest-mock boto3 pymongo pytz

# Configurar PYTHONPATH
export PYTHONPATH="$PWD/shared:$PWD"

# Crear archivo env.json para variables locales
cat > env.json << EOF
{
  "UsersFunction": {
    "MONGODB_URI": "mongodb+srv://usuario:password@cluster.mongodb.net/dbname",
    "DB_NAME": "sampledb",
    "COLLECTION_NAME": "users",
    "ENVIRONMENT": "local",
    "LOG_LEVEL": "DEBUG",
    "PYTHONPATH": "/var/task/shared:/var/task"
  },
  "ProductsFunction": {
    "MONGODB_URI": "mongodb+srv://usuario:password@cluster.mongodb.net/dbname",
    "DB_NAME": "sampledb",
    "COLLECTION_NAME": "products",
    "ENVIRONMENT": "local",
    "LOG_LEVEL": "DEBUG",
    "PYTHONPATH": "/var/task/shared:/var/task"
  },
  "OrdersFunction": {
    "MONGODB_URI": "mongodb+srv://usuario:password@cluster.mongodb.net/dbname",
    "DB_NAME": "sampledb",
    "COLLECTION_NAME": "orders",
    "ENVIRONMENT": "local",
    "LOG_LEVEL": "DEBUG",
    "PYTHONPATH": "/var/task/shared:/var/task"
  }
}
EOF

echo "Entorno local configurado!"
```

### 9.2 Eventos de Prueba

Crea eventos de prueba para simular peticiones HTTP:

```json
// events/get_users.json
{
  "httpMethod": "GET",
  "path": "/users",
  "headers": {
    "Content-Type": "application/json"
  },
  "queryStringParameters": null,
  "body": null
}

// events/create_user.json
{
  "httpMethod": "POST",
  "path": "/users",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"name\": \"John Doe\", \"email\": \"john@example.com\"}"
}
```

### 9.3 Script de Pruebas Directas

Crea un script para probar las Lambdas directamente (`scripts/test_local.py`):

```python
#!/usr/bin/env python3
import sys
import os
import json

# Configurar paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Configurar variables de entorno
os.environ['MONGODB_URI'] = 'mongodb+srv://usuario:password@cluster.mongodb.net/dbname'
os.environ['DB_NAME'] = 'sampledb'
os.environ['COLLECTION_NAME'] = 'users'
os.environ['ENVIRONMENT'] = 'local'
os.environ['LOG_LEVEL'] = 'DEBUG'

# Importar y probar Lambda
from lambdas.users.app import lambda_handler

# Simular evento de API Gateway
event = {
    "httpMethod": "GET",
    "path": "/users",
    "headers": {
        "Content-Type": "application/json"
    },
    "queryStringParameters": {},
    "body": None
}

# Simular contexto
class MockContext:
    aws_request_id = "local-test-id"

context = MockContext()

# Ejecutar Lambda
response = lambda_handler(event, context)
print(json.dumps(response, indent=2))
```

### 9.4 Pruebas con SAM Local

```bash
# Construir el proyecto
sam build

# Invocar una Lambda específica
sam local invoke UsersFunction --env-vars env.json --event events/get_users.json

# Iniciar API local
sam local start-api --env-vars env.json

# Probar endpoints locales
curl http://localhost:3000/users
curl -X POST http://localhost:3000/users -H "Content-Type: application/json" \
  -d '{"name": "John", "email": "john@example.com"}'
curl http://localhost:3000/products
curl http://localhost:3000/orders
```

### 9.5 Tests Unitarios

Crea tests unitarios para código compartido y Lambdas:

```python
# tests/unit/test_shared/test_date_utils.py
import pytest
from datetime import datetime
from shared.date_utils import DateFormatter

def test_date_formatter_iso_format():
    formatter = DateFormatter()
    date_str = '2024-01-15 10:30:00'
    date_obj = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
    
    iso_format = formatter.to_iso_format(date_obj)
    assert 'T' in iso_format
    assert iso_format.endswith('Z')

# tests/unit/test_users.py
import pytest
import json
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from lambdas.users.app import lambda_handler

class TestUsersLambda:
    def test_get_users_success(self):
        """Test para obtener usuarios exitosamente"""
        with patch('lambdas.users.app.db_connection') as mock_db:
            mock_collection = MagicMock()
            mock_collection.find.return_value = [
                {'name': 'John', 'email': 'john@example.com', 'created_at': '2024-01-01'}
            ]
            mock_db.get_collection.return_value = mock_collection
            
            event = {
                "httpMethod": "GET",
                "path": "/users"
            }
            
            response = lambda_handler(event, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'users' in body
            assert len(body['users']) == 1
            assert body['users'][0]['name'] == 'John'
```

## 10. Despliegue a Producción

### 10.1 Estrategia de Branching

Utiliza una estrategia de branching para gestionar los despliegues:

- `develop` → Despliega a entorno dev
- `release/*` → Despliega a entorno stage
- `master` o `main` → Despliega a entorno prod

### 10.2 Proceso de Despliegue

1. Desarrollo en rama feature:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   # ... desarrollo y commit ...
   git push origin feature/nueva-funcionalidad
   ```

2. Pull request a develop:
   - Crea PR en GitHub
   - Se ejecutan tests automáticamente
   - Requiere aprobación para merge

3. Merge a develop:
   - Se despliega automáticamente a dev
   - Tests de integración en entorno dev

4. Release candidate:
   ```bash
   git checkout -b release/v1.0.0
   git push origin release/v1.0.0
   ```
   - Se despliega a stage
   - Pruebas en entorno pre-producción

5. Merge a master/main:
   - Crea PR de release a master
   - Requiere aprobación manual
   - Se despliega a producción

## 11. Monitoreo y Mantenimiento

### 11.1 CloudWatch Logs

Cada Lambda tiene su grupo de logs configurado. Para consultarlos:

```bash
# Ver logs de una Lambda específica
aws logs get-log-events \
  --log-group-name /aws/lambda/mi-proyecto-users-dev \
  --log-stream-name 'LATEST'

# Usando SAM CLI
sam logs --stack-name mi-proyecto-serverless-dev \
  --name UsersFunction --tail
```

### 11.2 Métricas y Alarmas

Configura alarmas en CloudWatch para monitorear:

```bash
# Crear alarma para errores
aws cloudwatch put-metric-alarm \
  --alarm-name "Lambda-Users-Errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=mi-proyecto-users-dev \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:NotifyMe
```

## 12. Resolución de Problemas Comunes

### 12.1 Error: "No module named 'shared'"

**Causa**: El PYTHONPATH no está configurado correctamente.

**Solución**:
- En pruebas locales: `export PYTHONPATH="$PWD/shared:$PWD"`
- En template.yaml: Verifica que el PYTHONPATH está en las variables de entorno globales

### 12.2 Error: "Stack is in ROLLBACK_FAILED state"

**Causa**: Un despliegue anterior falló y dejó el stack en estado inconsistente.

**Solución**:
```bash
aws cloudformation delete-stack --stack-name nombre-stack-dev
aws cloudformation wait stack-delete-complete --stack-name nombre-stack-dev
```

### 12.3 Error: "Not authorized to perform sts:AssumeRoleWithWebIdentity"

**Causa**: La configuración OIDC o el rol IAM no están correctamente configurados.

**Solución**:
1. Verifica que el proveedor OIDC está creado en IAM
2. Verifica la política de confianza del rol
3. Asegúrate de que el nombre del repositorio coincide exactamente

## Conclusión

Esta guía proporciona una estructura completa para desarrollar aplicaciones serverless profesionales con AWS SAM. La combinación de múltiples Lambdas, código compartido, infraestructura existente y CI/CD automatizado permite construir aplicaciones escalables y mantenibles.

Recuerda que la clave del éxito está en:
- Mantener una estructura organizada
- Escribir tests comprensivos
- Seguir las mejores prácticas de seguridad
- Monitorear activamente tu aplicación

Con esta arquitectura, puedes escalar tu aplicación añadiendo nuevas Lambdas según sea necesario, manteniendo el código compartido centralizado y aprovechando la infraestructura existente en AWS.
