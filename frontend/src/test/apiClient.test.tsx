import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { api, ApiError } from '../services/api';

describe('API Client Layer', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('handles network failure with clear backend unreachable message', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(api.getStatsSummary()).rejects.toThrow(ApiError);
    try {
      await api.getStatsSummary();
    } catch (err) {
      const apiErr = err as ApiError;
      expect(apiErr.isNetworkError).toBe(true);
      expect(apiErr.status).toBe(0);
      expect(apiErr.message).toContain('Backend server is unreachable');
    }
  });

  it('handles 500 server error response with extracted detail', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: async () => ({ detail: 'Database connection failed' }),
    });

    await expect(api.getStatsSummary()).rejects.toThrow('Database connection failed');
  });

  it('handles 404 on /logs/generate with specialized non-development message', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: async () => ({ detail: 'Not found' }),
    });

    await expect(api.generateLogs(42)).rejects.toThrow(
      'Log generator endpoint is only available when ENVIRONMENT=development.'
    );
  });

  it('successfully returns data for successful GET response', async () => {
    const mockSummary = {
      total_logs: 120,
      total_alerts: 4,
      alerts_by_severity: { high: 2, critical: 2 },
      alerts_by_status: { open: 4 },
      alerts_by_mitre: [],
      logs_by_event_type: { auth_failure: 100 },
      log_counts_per_hour: [],
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockSummary,
    });

    const result = await api.getStatsSummary();
    expect(result.total_logs).toBe(120);
    expect(result.total_alerts).toBe(4);
  });
});
