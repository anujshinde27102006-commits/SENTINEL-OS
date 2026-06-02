/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { User, Note, SecretDocument, SqlQueryResponse } from '../src/types';
import { hashPassword } from './crypto-utils';

// State stored in memory on the server
let usersTable: User[] = [];
let notesTable: Note[] = [];
let secretsTable: SecretDocument[] = [];

// Helper to seed initial data safely
let isSeeded = false;
export function seedDatabase() {
  if (isSeeded) return;

  // Seed default users (with secure PBKDF2 hashes)
  const usersToSeed = [
    { username: 'admin', role: 'admin' as const, bio: 'Chief Security Officer. Monitors unauthorized accesses.' },
    { username: 'alice', role: 'user' as const, bio: 'Security Auditor in training. Loves cryptographic models.' },
    { username: 'bob', role: 'user' as const, bio: 'Frontend designer trying to configure defensive headers.' },
    { username: 'guest_user', role: 'guest' as const, bio: 'ReadOnly Guest account.' }
  ];

  usersToSeed.forEach((u, idx) => {
    // We use password equal to username + "123" for simple demo
    const defaultPass = `${u.username}123`;
    const { hash, salt } = hashPassword(defaultPass);
    usersTable.push({
      id: idx + 1,
      username: u.username,
      role: u.role,
      passwordHash: hash,
      salt: salt,
      bio: u.bio
    });
  });

  // Seed secrets
  secretsTable.push(
    { id: 101, title: 'Main production API Gateway credentials', classification: 'CRITICAL', content: 'SECRET_API_KEY=gai_studio_super_secret_jwt_bearer_token_99x88', ownerId: 1 },
    { id: 102, title: 'Penetration audit findings', classification: 'SECRET', content: 'Audit failed on section A3: Broken Access Control. Fixed via token validation.', ownerId: 1 },
    { id: 103, title: 'Database connection string', classification: 'CONFIDENTIAL', content: 'postgresql://admin:super_safe_p@ssw0rd@db.internal:5432/core_prod', ownerId: 1 }
  );

  // Seed notes
  notesTable.push(
    { id: 201, userId: 2, username: 'alice', content: 'Remember to verify Authorization header formatting!', isPublic: true, createdAt: new Date(Date.now() - 3600000).toISOString() },
    { id: 202, userId: 3, username: 'bob', content: 'Tested XSS protection using default JSX markup. It escapes brackets perfectly.', isPublic: true, createdAt: new Date().toISOString() }
  );

  isSeeded = true;
  console.log('Database state fully seeded with 3 tables, user hashes created via PBKDF2.');
}

// Get raw arrays (for internal authorized APIs)
export function getAllUsers(): User[] {
  return usersTable.map(u => ({ id: u.id, username: u.username, role: u.role, bio: u.bio }));
}

export function findUserById(id: number): User | null {
  const u = usersTable.find(user => user.id === id);
  return u ? { ...u } : null;
}

export function findUserByUsername(username: string): User | null {
  const u = usersTable.find(user => user.username.toLowerCase() === username.toLowerCase());
  return u ? { ...u } : null;
}

export function addUser(username: string, passwordHash: string, salt: string, role: 'user' | 'guest' = 'user'): User {
  const id = usersTable.length + 1;
  const newUser: User = {
    id,
    username,
    role,
    passwordHash,
    salt,
    bio: `Newly registered user in role ${role}.`
  };
  usersTable.push(newUser);
  return { id, username, role, bio: newUser.bio };
}

export function getNotes(): Note[] {
  return [...notesTable];
}

export function getSecrets(isAdmin: boolean): SecretDocument[] {
  if (!isAdmin) {
    // Simulate query throwing Permission Denied (Broken Access Control)
    throw new Error('Access Denied: Secrets database requires Role = admin.');
  }
  return [...secretsTable];
}

export function addNote(userId: number, username: string, content: string, isPublic: boolean): Note {
  const id = notesTable.length + 1;
  const newNote: Note = {
    id,
    userId,
    username,
    content,
    isPublic,
    createdAt: new Date().toISOString()
  };
  notesTable.push(newNote);
  return newNote;
}

// ==========================================
// SECURITY LAB SIMULATION ENGINE - SQL INJECTION
// ==========================================

/**
 * Execute a vulnerable lookup of user secret records.
 * Concatenates user raw text into the query and evaluates conditions like standard relational engines.
 */
export function querySecretsVulnerable(rawSearchString: string): SqlQueryResponse {
  const startTime = performance.now();
  const logs: string[] = [];

  // Re-verify seed
  seedDatabase();

  const formattedQuery = `SELECT * FROM secrets WHERE title LIKE '%${rawSearchString}%' OR content LIKE '%${rawSearchString}%';`;
  logs.push(`SQL Parser received query: ${formattedQuery}`);
  logs.push(`Parser parsing input clauses...`);

  let results: Record<string, any>[] = [];
  let isMaliciousInjection = false;

  // Let's analyze if injection bypass exists.
  // Common payloads:
  // ' OR '1'='1
  // ' OR 1=1 --
  // ' OR 'a'='a
  // UNION SELECT
  const normalizedSearch = rawSearchString.toLowerCase();
  
  const injectionPatterns = [
    "' or '1'='1",
    "' or 1=1",
    "or true",
    "' or 'a'='a",
    "' or 1=1--",
    "' or 'x'='x",
    "union select",
    "or ''=''"
  ];

  if (injectionPatterns.some(pat => normalizedSearch.includes(pat))) {
    isMaliciousInjection = true;
    logs.push(`[CRITICAL] Syntax modification detected! SQL parser token evaluates OR condition to TRUE.`);
    logs.push(`Row filter evaluated: WHERE (title LIKE '%...%') OR TRUE`);
    logs.push(`Bypassing all standard RBAC filters. Relational logic returned all tuples.`);
    results = secretsTable.map(s => ({
      id: s.id,
      title: s.title,
      classification: s.classification,
      content: s.content, // Vulnerable query leaks EVERYTHING!
      owner_id: s.ownerId
    }));
  } else {
    // standard literal lookup
    logs.push(`Constructed filter predicate: WHERE (title LIKE '${rawSearchString}')`);
    results = secretsTable
      .filter(s => 
        s.title.toLowerCase().includes(normalizedSearch) || 
        s.content.toLowerCase().includes(normalizedSearch)
      )
      .map(s => ({
        id: s.id,
        title: s.title,
        classification: s.classification,
        content: s.content,
        owner_id: s.ownerId
      }));
    logs.push(`Returned ${results.length} rows matching literal expression.`);
  }

  const executionTimeMs = parseFloat((performance.now() - startTime).toFixed(2));
  return {
    query: formattedQuery,
    results,
    logs,
    executionTimeMs,
    vulnerable: true
  };
}

/**
 * Execute secure parameterized lookup.
 * Parameters are tokenized and sent separately to prevent parsing modification.
 */
export function querySecretsSecure(searchParam: string): SqlQueryResponse {
  const startTime = performance.now();
  const logs: string[] = [];

  // Re-verify seed
  seedDatabase();

  const queryTemplate = `SELECT * FROM secrets WHERE (title LIKE $1) OR (content LIKE $1);`;
  logs.push(`Prepared statement registered: ${queryTemplate}`);
  logs.push(`Binding searchParam value as literal scalar: $1 = "${searchParam}"`);
  logs.push(`Logical structure of query cannot be modified. Parameter '$1' does not undergo lexical analysis as tokens.`);

  // In standard PG or SQLite, bind will treat the parameter as flat text.
  // So the search will look up the literally matched string.
  const normalizedSearch = searchParam.toLowerCase();
  const results = secretsTable
    .filter(s => 
      s.title.toLowerCase().includes(normalizedSearch) || 
      s.content.toLowerCase().includes(normalizedSearch)
    )
    .map(s => ({
      id: s.id,
      title: s.title,
      classification: s.classification,
      content: s.content,
      owner_id: s.ownerId
    }));

  logs.push(`Returned ${results.length} matching rows. If a SQL payload was input, it was treated strictly as plain text.`);

  const executionTimeMs = parseFloat((performance.now() - startTime).toFixed(2));
  return {
    query: queryTemplate,
    parameterizedQuery: `SELECT * FROM secrets WHERE (title LIKE ?) OR (content LIKE ?);`,
    paramsUsed: [searchParam, searchParam],
    results,
    logs,
    executionTimeMs,
    vulnerable: false
  };
}
