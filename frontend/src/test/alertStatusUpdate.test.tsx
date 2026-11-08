import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { AlertsPage } from '../pages/AlertsPage';
import { api } from '../services/api';
import type { SecurityAlert, SecurityAlertListResponse } from '../types';

describe('Alert Status Update Workflow', () => {
  const mockAlert: SecurityAlert = {
    id: 101,
    title: 'Brute Force Authentication Detected',
    description: '7 failed attempts from 10.0.1.50',
    severity: 'high',
    status: 'open',
    source_ip: '10.0.1.50',
    rule_id: 'RULE_BRUTE_FORCE',
    incident_start: '2026-11-04T10:00:00Z',
    incident_key: 'RULE_BRUTE_FORCE:10.0.1.50:2026-11-04T10:00:00',
    detection_time: '2026-11-04T10:05:00Z',
    mitre_technique_id: 1,
    mitre_technique: {
      id: 1,
      technique_id: 'T1110',
      technique_name: 'Brute Force',
      tactic: 'Credential Access',
    },
  };

  const mockListResponse: SecurityAlertListResponse = {
    items: [mockAlert],
    total: 1,
    skip: 0,
    limit: 25,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('allows analyst to view alert details and transition status to investigating', async () => {
    vi.spyOn(api, 'getAlerts').mockResolvedValue(mockListResponse);
    vi.spyOn(api, 'updateAlert').mockResolvedValue({
      ...mockAlert,
      status: 'investigating',
    });

    render(<AlertsPage />);

    // Wait for alert to load in table
    await waitFor(() => {
      expect(screen.getByText('Brute Force Authentication Detected')).toBeInTheDocument();
    });

    // Initial status badge should say Open
    expect(screen.getByTestId('status-badge-open')).toBeInTheDocument();

    // Click Triage button to open detail panel
    const triageButton = screen.getByText('Triage');
    fireEvent.click(triageButton);

    // Detail panel should be open
    expect(screen.getByText('Incident Workflow Transition')).toBeInTheDocument();

    // Find and click the 'Investigating' status button
    const actionButtons = screen.getByTestId('status-action-buttons');
    const investigatingBtn = within(actionButtons, 'Investigating');
    expect(investigatingBtn).toBeInTheDocument();
    fireEvent.click(investigatingBtn);

    // Verify API called with correct payload
    await waitFor(() => {
      expect(api.updateAlert).toHaveBeenCalledWith(101, { status: 'investigating' });
    });

    // Check that status is updated
    await waitFor(() => {
      expect(screen.getByText('Status changed to "investigating"')).toBeInTheDocument();
    });
  });
});

function within(container: HTMLElement, text: string): HTMLElement {
  const elements = container.querySelectorAll('button');
  for (const el of elements) {
    if (el.textContent?.trim() === text) return el;
  }
  throw new Error(`Button with text "${text}" not found`);
}
