/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type UserRole = 'guest' | 'user' | 'admin';

export interface User {
  id: number;
  username: string;
  role: UserRole;
  passwordHash?: string;
  salt?: string;
  bio?: string;
}

export interface Note {
  id: number;
  userId: number;
  username: string;
  content: string;
  isPublic: boolean;
  createdAt: string;
}

export interface SecretDocument {
  id: number;
  title: string;
  classification: string;
  content: string;
  ownerId: number;
}

export interface JwtTokenParts {
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: string;
  raw: string;
}

export interface SqlQueryResponse {
  query: string;
  parameterizedQuery?: string;
  paramsUsed?: string[];
  results: Record<string, any>[];
  logs: string[];
  executionTimeMs: number;
  vulnerable: boolean;
  error?: string;
}

export interface SecurityMetric {
  title: string;
  status: 'safe' | 'vulnerable' | 'info';
  details: string;
  recommendation: string;
}
