import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CodeViewer } from '../components/CodeViewer';

describe('XSS Protection & Plain Text Rendering', () => {
  it('renders script tags as pure plain text and never injects executable scripts', () => {
    const maliciousPayload = "<script>alert('xss')</script>";
    const { container } = render(
      <CodeViewer content={maliciousPayload} label="Command Line" />
    );

    // Verify there is NO <script> element in the DOM
    const scriptElements = container.querySelectorAll('script');
    expect(scriptElements.length).toBe(0);

    // Verify the text content is rendered literally as plain text
    const pre = screen.getByTestId('code-viewer-content');
    expect(pre).toBeInTheDocument();
    expect(pre.textContent).toBe(maliciousPayload);
    expect(pre.innerHTML).not.toContain('<script>');
    // In DOM, < is encoded as &lt;
    expect(pre.innerHTML).toContain('&lt;script&gt;');
  });

  it('renders img onerror payload safely as literal text without DOM injection', () => {
    const maliciousImgPayload = "<img src=x onerror=\"alert('hacked')\">";
    const { container } = render(
      <CodeViewer content={maliciousImgPayload} label="Raw Log" />
    );

    const imgElements = container.querySelectorAll('img');
    expect(imgElements.length).toBe(0);

    const pre = screen.getByTestId('code-viewer-content');
    expect(pre.textContent).toBe(maliciousImgPayload);
  });
});
