#!/usr/bin/env node
/**
 * maskprompt MCP server.
 *
 * Two tools:
 *   redact    — return the input with PII replaced per a chosen strategy
 *   find_pii  — return the matches without rewriting the input
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { findPii, mask, type Strategy } from './masker.js';

const VERSION = '0.1.0';

const server = new Server(
  { name: 'maskprompt', version: VERSION },
  { capabilities: { tools: {} } },
);

const TOOLS = [
  {
    name: 'redact',
    description:
      'Redact PII (emails, phones, credit cards w/ Luhn, SSNs, IPv4, AWS keys, GitHub tokens, JWTs) from a string. Returns the masked string and the list of matches with byte offsets.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text to redact.' },
        strategy: {
          type: 'string',
          enum: ['tag', 'hash', 'fixed', 'remove'],
          description:
            "How to replace each match: 'tag' = <KIND>, 'hash' = <KIND:abc12345> (truncated SHA-256 of the original), 'fixed' = '█' repeated, 'remove' = empty. Default 'tag'.",
          default: 'tag',
        },
      },
      required: ['text'],
    },
  },
  {
    name: 'find_pii',
    description:
      'Same detection as redact, but does not rewrite the input — returns the list of matches only. Useful for an agent that wants to refuse based on detected PII rather than send it through.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text to scan.' },
      },
      required: ['text'],
    },
  },
] as const;

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

interface RedactArgs {
  text: string;
  strategy?: Strategy;
}
interface FindArgs {
  text: string;
}

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    switch (name) {
      case 'redact': {
        const a = args as unknown as RedactArgs;
        const r = mask(a.text, a.strategy ?? 'tag');
        return jsonResult(r);
      }
      case 'find_pii': {
        const a = args as unknown as FindArgs;
        return jsonResult({ count: findPii(a.text).length, matches: findPii(a.text) });
      }
      default:
        return errorResult('unknown tool: ' + name);
    }
  } catch (err) {
    return errorResult('internal error: ' + (err as Error).message);
  }
});

function jsonResult(value: unknown) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
  };
}

function errorResult(message: string) {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write(`maskprompt MCP server v${VERSION} ready on stdio\n`);
