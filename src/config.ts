import path from 'node:path';
import { ServiceConfig } from './types';

function env(name: string, fallback = ''): string {
  return process.env[name]?.trim() || fallback;
}

function firstEnv(names: string[], fallback = ''): string {
  for (const name of names) {
    const value = env(name);
    if (value) return value;
  }
  return fallback;
}

function parseApiKeys(): Array<{ key: string; org_id?: string; role?: string; sub?: string }> {
  const raw = firstEnv(['RELATIONSHIP_API_KEYS', 'RELATIONSHIP_API_KEY', 'INTERNAL_API_KEY']);
  if (!raw) return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [key, org_id, role, sub] = entry.split(':');
      return {
        key,
        org_id: org_id || undefined,
        role: (role || 'service') as string,
        sub: sub || key
      };
    });
}

const sharedInternalKey = firstEnv([
  'INTERNAL_API_KEY',
  'RELATIONSHIP_INTERNAL_KEY',
  'LEMTIK_INTERNAL_KEY'
]);

export const config = {
  env: env('NODE_ENV', 'development'),
  port: Number(env('PORT', '3000')),
  jwtSecret: env('JWT_SECRET'),
  databaseUrl: firstEnv(['DATABASE_URL']),
  supabaseUrl: firstEnv(['SUPABASE_URL']),
  supabaseServiceKey: firstEnv(['SUPABASE_SERVICE_KEY']),
  redisUrl: firstEnv(['REDIS_URL']),
  resendApiKey: firstEnv(['RESEND_API_KEY']),
  groqApiKey: firstEnv(['GROQ_API_KEY']),
  groqModel: firstEnv(['GROQ_MODEL'], 'llama-3.3-70b-versatile'),
  groqBaseUrl: firstEnv(['GROQ_BASE_URL']),
  qwenApiKey: firstEnv(['QWEN_API_KEY', 'QWEN_INTERNAL_KEY', 'INTERNAL_API_KEY']),
  qwenModel: firstEnv(['QWEN_MODEL'], 'qwen-plus'),
  qwenPromptVersion: firstEnv(['QWEN_PROMPT_VERSION'], 'v1'),
  qwenTimeoutMs: Number(firstEnv(['QWEN_TIMEOUT_MS'], '8000')),
  qwenRetryCount: Number(firstEnv(['QWEN_RETRY_COUNT'], '3')),
  relationshipApiUrl: firstEnv(['RELATIONSHIP_API_URL']),
  relationshipApiKey: firstEnv(['RELATIONSHIP_API_KEY']),
  relationshipApiTimeoutMs: Number(firstEnv(['RELATIONSHIP_API_TIMEOUT_MS'], '8000')),
  relationshipApiRetryCount: Number(firstEnv(['RELATIONSHIP_API_RETRY_COUNT'], '2')),
  allowDevAuth:
    env('RELATIONSHIP_ALLOW_DEV_AUTH', '').toLowerCase() === 'true' ||
    (env('NODE_ENV', 'development') !== 'production' && !firstEnv(['RELATIONSHIP_API_KEYS', 'RELATIONSHIP_API_KEY', 'JWT_SECRET'])),
  auditLogPath: firstEnv(
    ['AUDIT_LOG_PATH'],
    path.join(process.cwd(), 'data', 'audit-log.jsonl')
  ),
  apiKeys: parseApiKeys(),
  sharedInternalKey,
  webHookSecret: env('WEBHOOK_SECRET'),
  relationshipWebhookUrls: firstEnv(['RELATIONSHIP_WEBHOOK_URLS', 'WEBHOOK_TARGET_URLS'])
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean),
  corsAllowedOrigins: firstEnv(['CORS_ALLOWED_ORIGINS', 'ALLOWED_ORIGINS'])
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean),
  blobStorageUrl: firstEnv(['BLOB_STORAGE_URL', 'AZURE_STORAGE_BLOB_URL']),
  blobStorageContainer: firstEnv(['BLOB_STORAGE_CONTAINER', 'BLOB_CONTAINER_NAME'], 'relationship-api'),
  blobStorageKey: firstEnv(['BLOB_STORAGE_KEY', 'AZURE_STORAGE_KEY']),
  orgDefault: firstEnv(['LEMTIK_DEFAULT_ORG_ID', 'ORG_ID', 'DEFAULT_ORG_ID'], 'default'),
  services: {
    osint: {
      name: 'osint',
      baseUrl: firstEnv(['OSINT_BRAIN_URL', 'OSINT_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-API-Key': firstEnv(['OSINT_BRAIN_INTERNAL_KEY', 'OSINT_BRAIN_API_KEY', 'INTERNAL_API_KEY', 'LEMTIK_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'osint'
    } satisfies ServiceConfig,
    aiAnalysis: {
      name: 'aiAnalysis',
      baseUrl: firstEnv(['AI_ANALYSIS_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-Key': firstEnv(['AI_ANALYSIS_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'aiAnalysis'
    } satisfies ServiceConfig,
    qwen: {
      name: 'qwen',
      baseUrl: firstEnv(['QWEN_URL', 'QWEN_API_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-Key': firstEnv(['QWEN_API_KEY', 'QWEN_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'qwen'
    } satisfies ServiceConfig,
    mainAgent: {
      name: 'mainAgent',
      baseUrl: firstEnv(['MAIN_AGENT_URL', 'MASTER_AI_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-Key': firstEnv(['MAIN_AGENT_INTERNAL_KEY', 'MASTER_AI_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'mainAgent'
    } satisfies ServiceConfig,
    autonomous: {
      name: 'autonomous',
      baseUrl: firstEnv(['AUTONOMOUS_CONTROL_URL', 'AUTONOMOUS_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-API-Key': firstEnv(['AUTONOMOUS_CONTROL_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'autonomous'
    } satisfies ServiceConfig,
    inventory: {
      name: 'inventory',
      baseUrl: firstEnv(['INVENTORY_SERVICE_URL', 'INVENTORY_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-Key': firstEnv(['INVENTORY_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'inventory'
    } satisfies ServiceConfig,
    proximity: {
      name: 'proximity',
      baseUrl: firstEnv(['PROXIMITY_URL']),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-Key': firstEnv(['PROXIMITY_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'proximity'
    } satisfies ServiceConfig,
    routeCalculator: {
      name: 'routeCalculator',
      baseUrl: firstEnv(['ROUTE_CALCULATOR_URL']),
      healthPath: '/health',
      defaultHeaders: {
        Authorization: `Bearer ${firstEnv(['ROUTE_CALCULATOR_INTERNAL_KEY', 'INTERNAL_API_KEY'])}`
      },
      authMode: 'bearer',
      fallbackService: 'routeCalculator'
    } satisfies ServiceConfig,
    cctv: {
      name: 'cctv',
      baseUrl: firstEnv(['CCTV_PERCEPTION_URL', 'CCTV_URL'], 'http://localhost:8004'),
      healthPath: '/health',
      defaultHeaders: {
        'X-Internal-Key': firstEnv(['CCTV_INTERNAL_KEY', 'INTERNAL_API_KEY'])
      },
      authMode: 'api-key',
      fallbackService: 'cctv'
    } satisfies ServiceConfig
  }
};

export function isElevatedRole(role?: string): boolean {
  return ['supervisor', 'manager', 'admin'].includes((role || '').toLowerCase());
}

export function isAdminRole(role?: string): boolean {
  return (role || '').toLowerCase() === 'admin';
}

export function normalizeRole(role?: string): string {
  return (role || 'service').toLowerCase();
}

export function hasExternalBackend(name: 'supabase' | 'redis' | 'resend' | 'blob'): boolean {
  if (name === 'supabase') return Boolean(config.supabaseUrl && config.supabaseServiceKey);
  if (name === 'redis') return Boolean(config.redisUrl);
  if (name === 'resend') return Boolean(config.resendApiKey);
  if (name === 'blob') return Boolean(config.blobStorageUrl && config.blobStorageKey);
  return false;
}

export function validateProductionConfig(): void {
  if (config.env !== 'production') return;
  const missing: string[] = [];
  if (config.allowDevAuth) missing.push('RELATIONSHIP_ALLOW_DEV_AUTH=false');
  if (!config.apiKeys.length && !config.jwtSecret && !config.sharedInternalKey) {
    missing.push('RELATIONSHIP_API_KEYS or JWT_SECRET');
  }
  if (!config.supabaseUrl) missing.push('SUPABASE_URL');
  if (!config.supabaseServiceKey) missing.push('SUPABASE_SERVICE_KEY');
  if (missing.length) {
    throw new Error(`Invalid production configuration: ${missing.join(', ')}`);
  }
}
