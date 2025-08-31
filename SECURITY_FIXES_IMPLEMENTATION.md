# 🔧 Security Fixes Implementation Guide

This document provides step-by-step implementation of the critical security fixes identified in the security audit.

## 🚨 CRITICAL FIXES (Implement Immediately)

### 1. Fix Dependency Vulnerabilities

```bash
# Update vulnerable dependencies
npm audit fix

# Manual updates for critical packages
npm install @nestjs/platform-express@latest
npm install multer@latest
npm install form-data@latest

# Verify fixes
npm audit --audit-level=high
```

### 2. Secure WebSocket CORS Configuration

**File:** `src/modules/chat/gateways/private-chat.gateway.ts`

```typescript
// BEFORE (VULNERABLE)
@WebSocketGateway({
  namespace: '/chat/private',
  cors: {
    origin: '*', // ❌ Allows any origin
  },
})

// AFTER (SECURE)
@WebSocketGateway({
  namespace: '/chat/private',
  cors: {
    origin: process.env.CORS_ORIGINS?.split(',') || ['https://cis-hub.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST'],
  },
})
```

**File:** `src/modules/chat/gateways/group-chat.gateway.ts`

```typescript
// BEFORE
@WebSocketGateway({
  namespace: '/chat/groups',
  cors: {
    origin: true, // ❌ Too permissive
    credentials: true,
  },
})

// AFTER (SECURE)
@WebSocketGateway({
  namespace: '/chat/groups',
  cors: {
    origin: process.env.CORS_ORIGINS?.split(',') || ['https://cis-hub.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST'],
  },
})
```

### 3. Implement Essential Security Middleware

**Install required packages:**
```bash
npm install helmet express-rate-limit @nestjs/throttler
```

**File:** `src/main.ts`

```typescript
import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { CatchEverythingFilter } from './common/filters/catch-everything.filter';
import helmet from 'helmet';
import { ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const httpAdapterHost = app.get(HttpAdapterHost);

  // 🔒 SECURITY MIDDLEWARE
  
  // 1. Helmet for security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "ws:", "wss:"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false, // For file uploads
  }));

  // 2. CORS configuration
  app.enableCors({
    origin: process.env.CORS_ORIGINS?.split(',') || ['https://cis-hub.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  });

  // 3. Global Validation Pipe with enhanced security
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
      skipMissingProperties: false,
      validateCustomDecorators: true,
      // 🔒 Prevent prototype pollution
      forbidUnknownValues: true,
    }),
  );

  // Global Prefix
  app.setGlobalPrefix('api/v1');

  // Global Exception Filter
  app.useGlobalFilters(new CatchEverythingFilter(httpAdapterHost));

  await app.listen(process.env.PORT ?? 3000);
  console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();
```

### 4. Add Rate Limiting Module

**File:** `src/app.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
// ... other imports

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [configuration],
      isGlobal: true,
      envFilePath: [`.env.${process.env.NODE_ENV || 'development'}`, '.env'],
      expandVariables: true,
    }),
    
    // 🔒 RATE LIMITING
    ThrottlerModule.forRoot([{
      name: 'short',
      ttl: 60000, // 1 minute
      limit: 10, // 10 requests per minute per IP
    }, {
      name: 'medium',
      ttl: 600000, // 10 minutes  
      limit: 50, // 50 requests per 10 minutes per IP
    }, {
      name: 'long',
      ttl: 3600000, // 1 hour
      limit: 200, // 200 requests per hour per IP
    }]),
    
    DatabaseModule,
    CacheModule,
    QueueModule,
    EventEmitterModule.forRoot(),
    AuthModule,
    // ... other modules
  ],
  controllers: [CacheTestController],
  providers: [
    // 🔒 GLOBAL RATE LIMITING
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
```

### 5. Strengthen JWT Configuration

**File:** `src/config/configuration.ts`

```typescript
export default (): AppConfig => {
  // 🔒 VALIDATE JWT SECRET
  const jwtSecret = (() => {
    const secret = process.env.JWT_SECRET;
    
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is required');
    }
    
    if (secret.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters long');
    }
    
    if (secret === 'your-secret-key' || secret === 'your-super-secret-access-key-change-this-in-production') {
      throw new Error('Default JWT_SECRET detected. Use a secure secret in production.');
    }
    
    return secret;
  })();

  return {
    port: parseInt(process.env.PORT || '3000', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
    database: {
      host: process.env.DATABASE_HOST || 'localhost',
      port: parseInt(process.env.DATABASE_PORT || '5432', 10),
      username: process.env.DATABASE_USERNAME || 'postgres',
      password: process.env.DATABASE_PASSWORD || 'postgres',
      database: process.env.DATABASE_NAME || 'mu-compass',
      ssl: process.env.DATABASE_SSL === 'true',
    },
    jwtSecret, // ✅ Validated secret
    apiPrefix: process.env.API_PREFIX || 'api',
    corsOrigins: (process.env.CORS_ORIGINS || 'https://cis-hub.netlify.app').split(','),
  };
};
```

### 6. Enhance File Upload Security

**File:** `src/modules/files/services/file-validation.service.ts`

```typescript
import { Injectable, BadRequestException } from '@nestjs/common';
import { UploadContext } from '../../../common/enums/upload_context.enum';

@Injectable()
export class FileValidationService {
  // ... existing code ...

  /**
   * 🔒 ENHANCED FILE HEADER VALIDATION
   */
  private validateFileHeaders(buffer: Buffer, mimeType: string): void {
    if (buffer.length < 4) return;

    const signatures: Record<string, string[]> = {
      'image/jpeg': ['FFD8FF'],
      'image/png': ['89504E47'],
      'image/gif': ['474946', '474946'],
      'image/webp': ['52494646'],
      'image/bmp': ['424D'],
      'application/pdf': ['25504446'],
      'application/zip': ['504B0304', '504B0506', '504B0708'],
      'application/msword': ['D0CF11E0'],
    };

    // 🔒 SPECIAL HANDLING FOR SVG (XSS PREVENTION)
    if (mimeType === 'image/svg+xml') {
      const content = buffer.toString('utf8', 0, Math.min(2000, buffer.length));
      
      // Check for malicious patterns
      const maliciousPatterns = [
        /<script[^>]*>/i,
        /javascript:/i,
        /data:text\/html/i,
        /vbscript:/i,
        /<iframe[^>]*>/i,
        /<object[^>]*>/i,
        /<embed[^>]*>/i,
        /<link[^>]*>/i,
        /on\w+\s*=/i, // Event handlers
      ];
      
      for (const pattern of maliciousPatterns) {
        if (pattern.test(content)) {
          throw new BadRequestException('SVG file contains potentially malicious content');
        }
      }
      return; // SVG validation complete
    }

    // Validate file signatures for other types
    const expectedSignatures = signatures[mimeType];
    if (expectedSignatures) {
      const headerHex = buffer.subarray(0, 8).toString('hex').toUpperCase();
      if (!expectedSignatures.some(sig => headerHex.startsWith(sig))) {
        throw new BadRequestException('File content does not match declared MIME type');
      }
    }
  }

  /**
   * 🔒 ENHANCED FILENAME VALIDATION
   */
  private validateFileName(file: Express.Multer.File): void {
    const dangerousPatterns = [
      /\.\./g, // Path traversal
      /[<>:"|?*\x00-\x1f]/g, // Invalid/control characters
      /\.(php|jsp|asp|aspx|exe|bat|cmd|com|pif|scr|vbs|js|jar|war)$/i, // Executable extensions
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i, // Windows reserved names
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(file.originalname)) {
        throw new BadRequestException('Invalid or potentially dangerous filename');
      }
    }

    // Additional filename checks
    if (file.originalname.length > 255) {
      throw new BadRequestException('Filename too long (max 255 characters)');
    }

    if (file.originalname.trim() !== file.originalname) {
      throw new BadRequestException('Filename cannot start or end with whitespace');
    }
  }
}
```

### 7. Improve Error Handling Security

**File:** `src/common/filters/catch-everything.filter.ts`

```typescript
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { v4 as uuidv4 } from 'uuid';

@Catch()
export class CatchEverythingFilter implements ExceptionFilter {
  private readonly logger = new Logger(CatchEverythingFilter.name);

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();
    const request = ctx.getRequest();
    const response = ctx.getResponse();

    const httpStatus =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const isDevelopment = process.env.NODE_ENV === 'development';
    const requestId = uuidv4(); // For tracking

    // 🔒 SECURE ERROR RESPONSE
    const errorResponse = {
      status: 'error',
      statusCode: httpStatus,
      message: this.getSafeErrorMessage(exception, isDevelopment),
      requestId, // For support without exposing internals
      timestamp: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(request),
    };

    // 🔒 LOG FULL DETAILS SERVER-SIDE ONLY
    this.logger.error({
      requestId,
      error: exception instanceof Error ? exception.message : String(exception),
      stack: exception instanceof Error ? exception.stack : undefined,
      path: httpAdapter.getRequestUrl(request),
      method: request.method,
      userAgent: request.headers['user-agent'],
      ip: request.ip,
      timestamp: new Date().toISOString(),
    });

    httpAdapter.reply(response, errorResponse, httpStatus);
  }

  private getSafeErrorMessage(exception: unknown, isDevelopment: boolean): string {
    if (exception instanceof HttpException) {
      return exception.message;
    }

    if (isDevelopment && exception instanceof Error) {
      return exception.message;
    }

    // 🔒 GENERIC MESSAGE FOR PRODUCTION
    return 'An internal server error occurred. Please contact support with the request ID.';
  }
}
```

## 🔄 Environment Variables Update

**File:** `.env.example`

```env
# 🔒 SECURITY CONFIGURATION
JWT_SECRET="generate-a-secure-32-character-secret-key-here-abcdef123456789"
JWT_ACCESS_EXPIRATION="15m"
JWT_REFRESH_EXPIRATION="7d"

# 🔒 CORS CONFIGURATION  
CORS_ORIGINS="https://cis-hub.netlify.app,https://app.cis-hub.com"

# 🔒 RATE LIMITING
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100   # Max requests per window

# 🔒 SECURITY HEADERS
HELMET_CSP_ENABLED=true
HELMET_HSTS_ENABLED=true

# Database Configuration (with SSL in production)
DATABASE_URL="postgresql://username:password@localhost:5432/cis_hub?sslmode=require"
DATABASE_SSL=true  # Enable SSL in production

# File Upload Security
MAX_FILE_SIZE=10485760  # 10MB
ALLOWED_FILE_TYPES="image/jpeg,image/png,image/webp,application/pdf"
UPLOAD_PATH="./uploads"

# Redis Configuration
REDIS_HOST="localhost"
REDIS_PORT=6379
REDIS_PASSWORD="your-redis-password-in-production"
```

## 🧪 Security Testing

**Create test file:** `tests/security.test.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Security Tests', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  // 🔒 TEST SECURITY HEADERS
  it('should include security headers', () => {
    return request(app.getHttpServer())
      .get('/api/v1/health')
      .expect((res) => {
        expect(res.headers['x-frame-options']).toBeDefined();
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        expect(res.headers['x-xss-protection']).toBeDefined();
      });
  });

  // 🔒 TEST RATE LIMITING
  it('should implement rate limiting', async () => {
    const endpoint = '/api/v1/auth/login';
    
    // Make requests up to the limit
    for (let i = 0; i < 10; i++) {
      await request(app.getHttpServer())
        .post(endpoint)
        .send({ email: 'test@std.mans.edu.eg', password: 'password' });
    }
    
    // Next request should be rate limited
    return request(app.getHttpServer())
      .post(endpoint)
      .send({ email: 'test@std.mans.edu.eg', password: 'password' })
      .expect(429);
  });

  afterEach(async () => {
    await app.close();
  });
});
```

## ✅ Security Verification Checklist

After implementing the fixes:

- [ ] Run `npm audit` - should show 0 high/critical vulnerabilities
- [ ] Test WebSocket connections from unauthorized origins - should be blocked
- [ ] Verify security headers are present in API responses
- [ ] Test rate limiting - requests should be throttled after limits
- [ ] Verify JWT tokens cannot be generated with weak secrets
- [ ] Test file upload with malicious files - should be rejected
- [ ] Check error responses don't leak sensitive information
- [ ] Verify CORS configuration blocks unauthorized origins

## 🚀 Deployment Security

**Docker security hardening:**

```dockerfile
# Use specific version instead of latest
FROM node:20.10.0-alpine AS builder

# Add security labels
LABEL security.contact="security@example.com"

# Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001 -G nodejs

# Set proper permissions
COPY --chown=nestjs:nodejs . .

# Use non-root user
USER nestjs

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

This implementation guide provides concrete steps to address the critical security vulnerabilities identified in the audit. Implement these fixes in order of priority, starting with the dependency updates and CORS configuration.