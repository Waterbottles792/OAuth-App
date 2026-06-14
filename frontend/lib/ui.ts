/**
 * Minimal shared inline-style tokens (Phase 7). Dependency-free; keeps the pages visually
 * consistent without pulling in a CSS framework.
 */
import { CSSProperties } from 'react';

export const page: CSSProperties = {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '2rem',
    background: '#f5f6f8',
};

export const card: CSSProperties = {
    background: '#fff',
    padding: '2.5rem',
    borderRadius: 10,
    boxShadow: '0 2px 12px rgba(0,0,0,0.08)',
    width: '100%',
    maxWidth: 460,
};

export const wideCard: CSSProperties = { ...card, maxWidth: 760 };

export const h1: CSSProperties = { fontSize: '1.6rem', margin: '0 0 1.5rem', color: '#1a1a2e' };

export const label: CSSProperties = { display: 'block', fontSize: '0.85rem', color: '#444', marginBottom: 4 };

export const input: CSSProperties = {
    width: '100%',
    padding: '0.65rem 0.75rem',
    fontSize: '1rem',
    border: '1px solid #ccd',
    borderRadius: 6,
    boxSizing: 'border-box',
    marginBottom: '1rem',
};

export const button: CSSProperties = {
    width: '100%',
    padding: '0.7rem',
    fontSize: '1rem',
    fontWeight: 600,
    color: '#fff',
    background: '#4338ca',
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
};

export const buttonSecondary: CSSProperties = {
    ...button,
    background: '#fff',
    color: '#4338ca',
    border: '1px solid #4338ca',
};

export const buttonDanger: CSSProperties = { ...button, background: '#b91c1c', width: 'auto', padding: '0.4rem 0.8rem' };

export const alertError: CSSProperties = {
    background: '#fde8e8',
    border: '1px solid #f5b5b5',
    color: '#9b1c1c',
    padding: '0.75rem 1rem',
    borderRadius: 6,
    marginBottom: '1rem',
    fontSize: '0.9rem',
};

export const alertInfo: CSSProperties = {
    background: '#e1effe',
    border: '1px solid #a4cafe',
    color: '#1e429f',
    padding: '0.75rem 1rem',
    borderRadius: 6,
    marginBottom: '1rem',
    fontSize: '0.9rem',
};

export const link: CSSProperties = { color: '#4338ca', textDecoration: 'none' };
