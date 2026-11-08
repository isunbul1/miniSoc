import { describe, it, expect } from 'vitest';
import { formatLocalTime, formatTimeOnly, getTimezoneSuffix } from '../utils/time';

describe('Time Formatting Utility', () => {
  it('formats UTC ISO timestamp with local date and timezone suffix', () => {
    const utcString = '2026-11-04T12:00:00Z';
    const formatted = formatLocalTime(utcString);
    expect(formatted).toMatch(/^2026-11-04 \d{2}:\d{2}:\d{2} \(UTC[+-]?\d*(:\d{2})?\)$/);
  });

  it('formats time only correctly with timezone suffix', () => {
    const utcString = '2026-11-04T15:30:00Z';
    const formatted = formatTimeOnly(utcString);
    expect(formatted).toMatch(/^\d{2}:\d{2} \(UTC[+-]?\d*(:\d{2})?\)$/);
  });

  it('handles null, undefined, or empty timestamps safely', () => {
    expect(formatLocalTime(null)).toBe('—');
    expect(formatLocalTime(undefined)).toBe('—');
    expect(formatLocalTime('')).toBe('—');
    expect(formatTimeOnly(null)).toBe('—');
  });

  it('handles invalid date strings gracefully', () => {
    expect(formatLocalTime('not-a-valid-date')).toBe('Invalid Date');
    expect(formatTimeOnly('not-a-valid-date')).toBe('Invalid Date');
  });

  it('computes valid timezone suffix', () => {
    const suffix = getTimezoneSuffix();
    expect(suffix).toMatch(/^\(UTC([+-]\d{1,2}(:\d{2})?)?\)$/);
  });
});
