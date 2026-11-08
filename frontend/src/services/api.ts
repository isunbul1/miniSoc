/**
 * MiniSOC API client using relative /api/v1 endpoints through the Vite proxy.
 */

import type {
  AlertFilters,
  AlertUpdatePayload,
  DetectionRunResponse,
  HealthResponse,
  LogFilters,
  LogGenerateResponse,
  MitreTechniqueListResponse,
  SecurityAlert,
  SecurityAlertListResponse,
  SecurityLog,
  SecurityLogListResponse,
  StatsSummary,
} from '../types';

export class ApiError extends Error {
  status: number;
  isNetworkError: boolean;

  constructor(status: number, message: string, isNetworkError: boolean = false) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.isNetworkError = isNetworkError;
  }
}

const API_BASE = '/api/v1';

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
  } catch {
    throw new ApiError(
      0,
      'Backend server is unreachable. Please verify that the backend service is running.',
      true
    );
  }

  if (!response.ok) {
    // Specific message for development-only endpoint outside development
    if (response.status === 404 && endpoint.startsWith('/logs/generate')) {
      throw new ApiError(
        404,
        'Log generator endpoint is only available when ENVIRONMENT=development.'
      );
    }

    let errorMessage = `HTTP Error ${response.status}: ${response.statusText}`;
    try {
      const errorData = await response.json();
      if (errorData && typeof errorData.detail === 'string') {
        errorMessage = errorData.detail;
      } else if (errorData && Array.isArray(errorData.detail)) {
        errorMessage = errorData.detail.map((d: { msg?: string }) => d.msg || '').join(', ');
      }
    } catch {
      // response wasn't JSON
    }
    throw new ApiError(response.status, errorMessage);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return {} as T;
  }

  return response.json() as Promise<T>;
}

export const api = {
  /** Health check */
  getHealth(): Promise<HealthResponse> {
    return request<HealthResponse>('/health');
  },

  /** Stats Summary for Dashboard */
  getStatsSummary(): Promise<StatsSummary> {
    return request<StatsSummary>('/stats/summary');
  },

  /** Security Logs */
  getLogs(filters: LogFilters): Promise<SecurityLogListResponse> {
    const params = new URLSearchParams();
    params.set('skip', filters.skip.toString());
    params.set('limit', filters.limit.toString());
    if (filters.severity) {
      params.set('severity', filters.severity);
    }
    if (filters.event_type && filters.event_type.trim()) {
      params.set('event_type', filters.event_type.trim());
    }
    if (filters.source_ip && filters.source_ip.trim()) {
      params.set('source_ip', filters.source_ip.trim());
    }
    return request<SecurityLogListResponse>(`/logs?${params.toString()}`);
  },

  getLogById(id: number): Promise<SecurityLog> {
    return request<SecurityLog>(`/logs/${id}`);
  },

  generateLogs(seed: number = 42): Promise<LogGenerateResponse> {
    return request<LogGenerateResponse>('/logs/generate', {
      method: 'POST',
      body: JSON.stringify({ seed }),
    });
  },

  /** Security Alerts */
  getAlerts(filters: AlertFilters): Promise<SecurityAlertListResponse> {
    const params = new URLSearchParams();
    params.set('skip', filters.skip.toString());
    params.set('limit', filters.limit.toString());
    if (filters.severity) {
      params.set('severity', filters.severity);
    }
    if (filters.status) {
      params.set('status', filters.status);
    }
    return request<SecurityAlertListResponse>(`/alerts?${params.toString()}`);
  },

  getAlertById(id: number): Promise<SecurityAlert> {
    return request<SecurityAlert>(`/alerts/${id}`);
  },

  updateAlert(id: number, payload: AlertUpdatePayload): Promise<SecurityAlert> {
    return request<SecurityAlert>(`/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  /** Threat Detection */
  runDetection(): Promise<DetectionRunResponse> {
    return request<DetectionRunResponse>('/detection/run', {
      method: 'POST',
    });
  },

  /** MITRE Techniques */
  getMitreTechniques(tactic?: string): Promise<MitreTechniqueListResponse> {
    const query = tactic ? `?tactic=${encodeURIComponent(tactic)}` : '';
    return request<MitreTechniqueListResponse>(`/mitre${query}`);
  },
};
