import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityBadge } from '../components/SeverityBadge';
import type { LogSeverity } from '../types';

describe('SeverityBadge Component', () => {
  const severities: LogSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

  severities.forEach((sev) => {
    it(`renders correct label and testid for "${sev}" severity`, () => {
      render(<SeverityBadge severity={sev} />);
      const badge = screen.getByTestId(`severity-badge-${sev}`);
      expect(badge).toBeInTheDocument();
      expect(badge.textContent?.toLowerCase()).toContain(sev);
    });
  });

  it('renders with small size by default', () => {
    render(<SeverityBadge severity="high" />);
    const badge = screen.getByTestId('severity-badge-high');
    expect(badge.className).toContain('text-xs');
  });

  it('renders with medium size when specified', () => {
    render(<SeverityBadge severity="critical" size="md" />);
    const badge = screen.getByTestId('severity-badge-critical');
    expect(badge.className).toContain('text-sm');
  });
});
