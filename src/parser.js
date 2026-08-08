'use strict';

/**
 * CloudCheck Smart Parser
 * 
 * A proper tokeniser and block-level parser for Bicep, Terraform HCL, and ARM JSON.
 * 
 * What this does vs regex:
 * - Strips comments before analysis (no false positives from commented-out code)
 * - Tokenises into meaningful units (strings, identifiers, numbers, operators)
 * - Parses into structured blocks (resource, param, var, output, module)
 * - Resolves variable references (param x = true -> follows x when used in properties)
 * - Understands nested property paths (properties.networkAcls.defaultAction)
 * - Knows the difference between property values and string content
 * - Multi-line property awareness
 */

/* ================================================================
   TOKENISER
   ================================================================ */

const TK = {
  STRING: 'STRING',
  NUMBER: 'NUMBER',
  BOOL: 'BOOL',
  NULL: 'NULL',
  IDENT: 'IDENT',
  LBRACE: 'LBRACE',   // {
  RBRACE: 'RBRACE',   // }
  LBRACKET: 'LBRACKET', // [
  RBRACKET: 'RBRACKET', // ]
  LPAREN: 'LPAREN',   // (
  RPAREN: 'RPAREN',   // )
  EQUALS: 'EQUALS',   // =
  COLON: 'COLON',     // :
  DOT: 'DOT',         // .
  COMMA: 'COMMA',     // ,
  AT: 'AT',           // @
  NEWLINE: 'NEWLINE',
  EOF: 'EOF',
};

/**
 * Strip single-line (//) and multi-line (/* *\/) comments from source.
 * Also strips Bicep decorators from comment perspective (keeps them as tokens).
 * Preserves line counts by replacing comment content with spaces/newlines.
 */
function stripComments(source) {
  let result = '';
  let i = 0;
  const len = source.length;

  while (i < len) {
    // Multi-line comment
    if (source[i] === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < len && !(source[i] === '*' && source[i + 1] === '/')) {
        result += source[i] === '\n' ? '\n' : ' ';
        i++;
      }
      i += 2; // skip */
      continue;
    }
    // Single-line comment
    if (source[i] === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < len && source[i] !== '\n') i++;
      continue;
    }
    // Hash comment (Terraform)
    if (source[i] === '#') {
      i++;
      while (i < len && source[i] !== '\n') i++;
      continue;
    }
    result += source[i];
    i++;
  }
  return result;
}

/**
 * Tokenise cleaned source into a flat token array.
 * Each token: { type, value, line }
 */
function tokenise(source) {
  const cleaned = stripComments(source);
  const tokens = [];
  let i = 0;
  let line = 1;
  const len = cleaned.length;

  while (i < len) {
    const ch = cleaned[i];

    // Whitespace (not newline)
    if (ch === ' ' || ch === '\t' || ch === '\r') { i++; continue; }

    // Newline
    if (ch === '\n') { line++; i++; continue; }

    // Single-quoted string (Bicep)
    if (ch === "'") {
      let str = '';
      i++;
      while (i < len && cleaned[i] !== "'") {
        if (cleaned[i] === '\\') { i++; str += cleaned[i] || ''; }
        else str += cleaned[i];
        i++;
      }
      i++; // closing quote
      tokens.push({ type: TK.STRING, value: str, line });
      continue;
    }

    // Double-quoted string (ARM JSON / Terraform)
    if (ch === '"') {
      let str = '';
      i++;
      while (i < len && cleaned[i] !== '"') {
        if (cleaned[i] === '\\') { i++; str += cleaned[i] || ''; }
        else str += cleaned[i];
        i++;
      }
      i++; // closing quote
      tokens.push({ type: TK.STRING, value: str, line });
      continue;
    }

    // Heredoc (Terraform <<EOT...EOT)
    if (ch === '<' && cleaned[i+1] === '<') {
      i += 2;
      if (cleaned[i] === '-') i++; // <<-EOT
      let delim = '';
      while (i < len && cleaned[i] !== '\n') { delim += cleaned[i]; i++; }
      delim = delim.trim();
      let hereStr = '';
      i++; // skip newline
      while (i < len) {
        let lineContent = '';
        const lineStart = i;
        while (i < len && cleaned[i] !== '\n') { lineContent += cleaned[i]; i++; }
        if (lineContent.trim() === delim) { i++; break; }
        hereStr += lineContent + '\n';
        if (i < len) { line++; i++; }
      }
      tokens.push({ type: TK.STRING, value: hereStr, line });
      continue;
    }

    // Number
    if ((ch >= '0' && ch <= '9') || (ch === '-' && cleaned[i+1] >= '0' && cleaned[i+1] <= '9')) {
      let num = ch; i++;
      while (i < len && ((cleaned[i] >= '0' && cleaned[i] <= '9') || cleaned[i] === '.')) {
        num += cleaned[i]; i++;
      }
      tokens.push({ type: TK.NUMBER, value: parseFloat(num), line });
      continue;
    }

    // Identifier or keyword
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_') {
      let ident = '';
      while (i < len && ((cleaned[i] >= 'a' && cleaned[i] <= 'z') ||
             (cleaned[i] >= 'A' && cleaned[i] <= 'Z') ||
             (cleaned[i] >= '0' && cleaned[i] <= '9') ||
             cleaned[i] === '_' || cleaned[i] === '-')) {
        ident += cleaned[i]; i++;
      }
      // Keywords
      if (ident === 'true') { tokens.push({ type: TK.BOOL, value: true, line }); continue; }
      if (ident === 'false') { tokens.push({ type: TK.BOOL, value: false, line }); continue; }
      if (ident === 'null' || ident === 'None' || ident === 'nil') { tokens.push({ type: TK.NULL, value: null, line }); continue; }
      tokens.push({ type: TK.IDENT, value: ident, line });
      continue;
    }

    // Punctuation
    const punct = {
      '{': TK.LBRACE, '}': TK.RBRACE,
      '[': TK.LBRACKET, ']': TK.RBRACKET,
      '(': TK.LPAREN, ')': TK.RPAREN,
      '=': TK.EQUALS, ':': TK.COLON,
      '.': TK.DOT, ',': TK.COMMA,
      '@': TK.AT,
    };
    if (punct[ch]) {
      tokens.push({ type: punct[ch], value: ch, line });
      i++; continue;
    }

    // Skip unknown chars
    i++;
  }

  tokens.push({ type: TK.EOF, value: null, line });
  return tokens;
}

/* ================================================================
   BLOCK PARSER
   
   Produces a flat list of "nodes":
   {
     kind: 'resource' | 'param' | 'var' | 'output' | 'module' | 'terraform' | 'provider'
     name: string
     resourceType: string (for resources)
     apiVersion: string (for resources)
     properties: Map<string, any>  (flattened dot-path -> value)
     line: number
     decorators: string[]
   }
   ================================================================ */

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
    this.nodes = [];
    this.params = new Map();  // param name -> value (for resolution)
    this.vars = new Map();    // var name -> value
  }

  peek() { return this.tokens[this.pos]; }
  advance() { return this.tokens[this.pos++]; }
  
  at(type) { return this.peek().type === type; }
  
  // Skip tokens until we find the target type or EOF
  skipTo(type) {
    while (!this.at(TK.EOF) && !this.at(type)) this.advance();
  }

  // Eat a specific token type, return its value or null
  eat(type) {
    if (this.at(type)) return this.advance().value;
    return null;
  }

  // Parse a value: string, number, bool, null, reference, or object/array
  parseValue() {
    const t = this.peek();
    
    if (t.type === TK.STRING) { this.advance(); return t.value; }
    if (t.type === TK.NUMBER) { this.advance(); return t.value; }
    if (t.type === TK.BOOL)   { this.advance(); return t.value; }
    if (t.type === TK.NULL)   { this.advance(); return null; }
    
    // Object literal
    if (t.type === TK.LBRACE) {
      return this.parseObject();
    }
    
    // Array literal
    if (t.type === TK.LBRACKET) {
      return this.parseArray();
    }
    
    // Identifier reference (could be param/var reference, function call)
    if (t.type === TK.IDENT) {
      const name = t.value;
      this.advance();
      
      // Function call
      if (this.at(TK.LPAREN)) {
        this.advance(); // (
        let depth = 1;
        const args = [];
        while (!this.at(TK.EOF) && depth > 0) {
          if (this.at(TK.LPAREN)) depth++;
          if (this.at(TK.RPAREN)) { depth--; if (depth === 0) break; }
          args.push(this.parseValue());
          this.eat(TK.COMMA);
        }
        this.eat(TK.RPAREN);
        // Return resolved value for known functions
        return `__fn:${name}`;
      }
      
      // Property access chain (a.b.c)
      let chain = name;
      while (this.at(TK.DOT)) {
        this.advance();
        if (this.at(TK.IDENT)) chain += '.' + this.advance().value;
      }
      
      // Try to resolve param/var reference
      if (this.params.has(name)) return this.params.get(name);
      if (this.vars.has(name)) return this.vars.get(name);
      
      return `__ref:${chain}`;
    }
    
    // Skip unknown token
    this.advance();
    return undefined;
  }

  // Parse { key: value, ... } or { key = value ... }
  parseObject() {
    const obj = {};
    this.eat(TK.LBRACE);
    
    while (!this.at(TK.RBRACE) && !this.at(TK.EOF)) {
      // Skip decorators inside objects
      if (this.at(TK.AT)) {
        this.advance();
        this.skipTo(TK.NEWLINE);
        continue;
      }
      
      // Key
      let key = null;
      if (this.at(TK.IDENT)) key = this.advance().value;
      else if (this.at(TK.STRING)) key = this.advance().value;
      else { this.advance(); continue; }
      
      // Separator: : or =
      this.eat(TK.COLON) || this.eat(TK.EQUALS);
      
      const val = this.parseValue();
      if (key !== null) obj[key] = val;
      
      this.eat(TK.COMMA);
    }
    
    this.eat(TK.RBRACE);
    return obj;
  }

  // Parse [ value, value, ... ]
  parseArray() {
    const arr = [];
    this.eat(TK.LBRACKET);
    while (!this.at(TK.RBRACKET) && !this.at(TK.EOF)) {
      arr.push(this.parseValue());
      this.eat(TK.COMMA);
    }
    this.eat(TK.RBRACKET);
    return arr;
  }

  // Flatten nested object into dot-path map
  // { networkAcls: { defaultAction: 'Deny' } } -> { 'networkAcls.defaultAction': 'Deny' }
  flattenProps(obj, prefix, map) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      if (prefix) map.set(prefix, obj);
      return;
    }
    for (const [k, v] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        this.flattenProps(v, path, map);
      } else {
        map.set(path, v);
        // Also store the key alone for quick lookup
        map.set(k, v);
      }
    }
  }

  // Parse Bicep source
  parseBicep() {
    while (!this.at(TK.EOF)) {
      const t = this.peek();
      
      // Decorator (@description, @secure, etc.)
      const decorators = [];
      while (this.at(TK.AT)) {
        this.advance();
        if (this.at(TK.IDENT)) {
          const decName = this.advance().value;
          decorators.push(decName);
          // Skip decorator args
          if (this.at(TK.LPAREN)) {
            this.advance();
            let depth = 1;
            while (!this.at(TK.EOF) && depth > 0) {
              if (this.at(TK.LPAREN)) depth++;
              if (this.at(TK.RPAREN)) depth--;
              if (depth > 0) this.advance();
            }
            this.eat(TK.RPAREN);
          }
        }
      }

      if (!this.at(TK.IDENT)) { this.advance(); continue; }
      
      const keyword = this.peek().value;
      
      if (keyword === 'targetScope') {
        this.advance();
        this.eat(TK.EQUALS);
        const val = this.parseValue();
        this.nodes.push({ kind: 'targetScope', value: val, line: t.line });
        continue;
      }

      if (keyword === 'param') {
        this.advance();
        const name = this.eat(TK.IDENT);
        const typeTok = this.at(TK.IDENT) ? this.advance().value : null;
        let defaultVal = undefined;
        if (this.eat(TK.EQUALS)) {
          defaultVal = this.parseValue();
        }
        if (name) this.params.set(name, defaultVal);
        this.nodes.push({ kind: 'param', name, dataType: typeTok, defaultValue: defaultVal, decorators, line: t.line });
        continue;
      }

      if (keyword === 'var') {
        this.advance();
        const name = this.eat(TK.IDENT);
        this.eat(TK.EQUALS);
        const val = this.parseValue();
        if (name) this.vars.set(name, val);
        this.nodes.push({ kind: 'var', name, value: val, line: t.line });
        continue;
      }

      if (keyword === 'output') {
        this.advance();
        const name = this.eat(TK.IDENT);
        const typeTok = this.at(TK.IDENT) ? this.advance().value : null;
        this.eat(TK.EQUALS);
        const val = this.parseValue();
        this.nodes.push({ kind: 'output', name, dataType: typeTok, value: val, line: t.line });
        continue;
      }

      if (keyword === 'resource') {
        this.advance();
        const symName = this.eat(TK.IDENT);
        
        // Resource type string: 'Microsoft.Storage/storageAccounts@2023-01-01'
        let resourceType = null, apiVersion = null;
        if (this.at(TK.STRING)) {
          const typeStr = this.advance().value;
          const parts = typeStr.split('@');
          resourceType = parts[0];
          apiVersion = parts[1] || null;
        }
        
        // 'existing' keyword
        let existing = false;
        if (this.at(TK.IDENT) && this.peek().value === 'existing') {
          existing = true; this.advance();
        }
        
        this.eat(TK.EQUALS);
        
        // Conditional
        if (this.at(TK.IDENT) && this.peek().value === 'if') {
          this.advance();
          this.advance(); // skip condition
        }
        
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        const props = new Map();
        this.flattenProps(body, '', props);
        
        this.nodes.push({
          kind: 'resource',
          name: symName,
          resourceType,
          apiVersion,
          existing,
          properties: props,
          rawBody: body,
          decorators,
          line: t.line,
        });
        continue;
      }

      if (keyword === 'module') {
        this.advance();
        const name = this.eat(TK.IDENT);
        const path = this.at(TK.STRING) ? this.advance().value : null;
        this.eat(TK.EQUALS);
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        this.nodes.push({ kind: 'module', name, path, rawBody: body, line: t.line });
        continue;
      }

      this.advance();
    }
    return this.nodes;
  }

  // Parse Terraform HCL
  parseTerraform() {
    while (!this.at(TK.EOF)) {
      if (!this.at(TK.IDENT)) { this.advance(); continue; }
      
      const keyword = this.peek().value;
      const line = this.peek().line;

      // terraform {} block
      if (keyword === 'terraform') {
        this.advance();
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        const props = new Map();
        this.flattenProps(body, '', props);
        this.nodes.push({ kind: 'terraform', properties: props, rawBody: body, line });
        continue;
      }

      // provider "name" {}
      if (keyword === 'provider') {
        this.advance();
        const name = this.at(TK.STRING) ? this.advance().value : this.eat(TK.IDENT);
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        const props = new Map();
        this.flattenProps(body, '', props);
        this.nodes.push({ kind: 'provider', name, properties: props, rawBody: body, line });
        continue;
      }

      // variable "name" {}
      if (keyword === 'variable') {
        this.advance();
        const name = this.at(TK.STRING) ? this.advance().value : this.eat(TK.IDENT);
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        const defaultVal = body.default;
        if (name) this.vars.set(name, defaultVal);
        this.nodes.push({ kind: 'param', name, defaultValue: defaultVal, rawBody: body, line });
        continue;
      }

      // output "name" {}
      if (keyword === 'output') {
        this.advance();
        const name = this.at(TK.STRING) ? this.advance().value : this.eat(TK.IDENT);
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        this.nodes.push({ kind: 'output', name, value: body.value, rawBody: body, line });
        continue;
      }

      // resource "type" "name" {}
      if (keyword === 'resource') {
        this.advance();
        const resourceType = this.at(TK.STRING) ? this.advance().value : null;
        const symName = this.at(TK.STRING) ? this.advance().value : this.eat(TK.IDENT);
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        const props = new Map();
        this.flattenProps(body, '', props);
        this.nodes.push({
          kind: 'resource',
          name: symName,
          resourceType,
          properties: props,
          rawBody: body,
          line,
        });
        continue;
      }

      // data "type" "name" {}
      if (keyword === 'data') {
        this.advance();
        const dataType = this.at(TK.STRING) ? this.advance().value : null;
        const name = this.at(TK.STRING) ? this.advance().value : this.eat(TK.IDENT);
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        this.nodes.push({ kind: 'data', dataType, name, rawBody: body, line });
        continue;
      }

      // locals {}
      if (keyword === 'locals') {
        this.advance();
        const body = this.at(TK.LBRACE) ? this.parseObject() : {};
        for (const [k, v] of Object.entries(body)) {
          this.vars.set(k, v);
        }
        this.nodes.push({ kind: 'locals', rawBody: body, line });
        continue;
      }

      this.advance();
    }
    return this.nodes;
  }

  // Parse ARM JSON
  parseARM(source) {
    // ARM JSON is valid JSON — use native parser then convert to nodes
    try {
      const arm = JSON.parse(source);
      if (!arm.resources) return [];
      
      for (const r of arm.resources) {
        const typeParts = (r.type || '').split('@');
        const resourceType = typeParts[0];
        const apiVersion = r.apiVersion || null;
        const props = new Map();
        
        // Flatten all properties
        const merge = { ...r, ...(r.properties || {}) };
        delete merge.properties;
        this.flattenProps(merge, '', props);
        // Also flatten properties sub-object with prefix
        if (r.properties) this.flattenProps(r.properties, 'properties', props);
        if (r.tags) this.flattenProps(r.tags, 'tags', props);
        
        this.nodes.push({
          kind: 'resource',
          name: r.name || null,
          resourceType,
          apiVersion,
          properties: props,
          rawBody: r,
          line: 1,
        });
      }
      
      // Extract parameters
      if (arm.parameters) {
        for (const [name, p] of Object.entries(arm.parameters)) {
          this.params.set(name, p.defaultValue);
          this.nodes.push({ kind: 'param', name, defaultValue: p.defaultValue, line: 1 });
        }
      }
      
      // Extract outputs
      if (arm.outputs) {
        for (const [name, o] of Object.entries(arm.outputs)) {
          this.nodes.push({ kind: 'output', name, value: o.value, line: 1 });
        }
      }
    } catch (e) {
      // Fallback: not valid JSON, return empty
    }
    return this.nodes;
  }
}

/* ================================================================
   RESOLVE VALUE
   Resolves a property value, following param/var references.
   Returns the resolved primitive or the raw value.
   ================================================================ */

function resolveValue(val, params, vars) {
  if (val === null || val === undefined) return val;
  if (typeof val !== 'string') return val;
  
  // Param/var reference
  if (val.startsWith('__ref:')) {
    const refName = val.slice(6).split('.')[0];
    if (params.has(refName)) return resolveValue(params.get(refName), params, vars);
    if (vars.has(refName)) return resolveValue(vars.get(refName), params, vars);
  }
  
  return val;
}

/* ================================================================
   MAIN PARSE FUNCTION
   Returns a ParseResult object with nodes and helper methods.
   ================================================================ */

function parse(source, format) {
  const tokens = tokenise(source);
  const parser = new Parser(tokens);
  let nodes = [];

  if (format === 'bicep') {
    nodes = parser.parseBicep();
  } else if (format === 'terraform') {
    nodes = parser.parseTerraform();
  } else if (format === 'arm') {
    nodes = parser.parseARM(source);
  }

  const params = parser.params;
  const vars = parser.vars;

  return new ParseResult(nodes, params, vars, source, format);
}

/* ================================================================
   PARSE RESULT
   Query interface over the parsed nodes.
   ================================================================ */

class ParseResult {
  constructor(nodes, params, vars, source, format) {
    this.nodes = nodes;
    this.params = params;
    this.vars = vars;
    this.source = source;
    this.format = format;
  }

  // Get all resource nodes
  resources() {
    return this.nodes.filter(n => n.kind === 'resource');
  }

  // Get resources matching a type pattern
  resourcesOfType(pattern) {
    return this.resources().filter(r => r.resourceType && pattern.test(r.resourceType));
  }

  // Get a resolved property value from a resource
  // Supports dot-path: prop(resource, 'properties.networkAcls.defaultAction')
  prop(resource, path) {
    if (!resource.properties) return undefined;
    
    // Try exact path first
    if (resource.properties.has(path)) {
      return resolveValue(resource.properties.get(path), this.params, this.vars);
    }
    
    // Try the last segment (key only)
    const key = path.split('.').pop();
    if (resource.properties.has(key)) {
      return resolveValue(resource.properties.get(key), this.params, this.vars);
    }
    
    // Walk the rawBody manually for nested paths
    const parts = path.split('.');
    let cur = resource.rawBody;
    for (const part of parts) {
      if (cur && typeof cur === 'object') cur = cur[part];
      else { cur = undefined; break; }
    }
    if (cur !== undefined) return resolveValue(cur, this.params, this.vars);
    
    return undefined;
  }

  // Check if any resource has a property matching a value
  anyResourceHasProp(typePattern, propPath, value) {
    return this.resourcesOfType(typePattern).some(r => {
      const v = this.prop(r, propPath);
      return v === value;
    });
  }

  // Get all param nodes
  paramNodes() {
    return this.nodes.filter(n => n.kind === 'param');
  }

  // Get all output nodes
  outputNodes() {
    return this.nodes.filter(n => n.kind === 'output');
  }

  // Check if targetScope is declared (Bicep)
  hasTargetScope() {
    return this.nodes.some(n => n.kind === 'targetScope');
  }

  // Check if any param has @secure decorator
  hasSecureParam(name) {
    return this.paramNodes().some(p => p.name === name && p.decorators && p.decorators.includes('secure'));
  }

  // Get the terraform block
  terraformBlock() {
    return this.nodes.find(n => n.kind === 'terraform');
  }

  // Check if tags object contains a key (case-insensitive)
  hasTag(tagKey) {
    const re = new RegExp(tagKey, 'i');
    // Check in var/param values (common pattern: var tags = { Environment: 'prod' })
    for (const [, val] of this.vars) {
      if (val && typeof val === 'object') {
        if (Object.keys(val).some(k => re.test(k))) return true;
      }
    }
    // Check in all resource tag properties
    for (const r of this.resources()) {
      for (const [k, v] of r.properties) {
        if (k.toLowerCase().includes('tag') && v && typeof v === 'object') {
          if (Object.keys(v).some(k2 => re.test(k2))) return true;
        }
      }
      // Check tags property directly
      const tags = this.prop(r, 'tags');
      if (tags && typeof tags === 'object') {
        if (Object.keys(tags).some(k => re.test(k))) return true;
      }
    }
    // Also check params named tags
    for (const [name, val] of this.params) {
      if (name.toLowerCase().includes('tag') && val && typeof val === 'object') {
        if (Object.keys(val).some(k => re.test(k))) return true;
      }
    }
    return false;
  }

  // Does any resource reference diagnostic settings?
  hasDiagnosticSettings() {
    return this.resourcesOfType(/Insights\/diagnosticSettings|diagnostic_setting|cloudwatch_log_group/i).length > 0;
  }

  // Does any resource reference Log Analytics?
  hasLogAnalytics() {
    return this.nodes.some(n => {
      if (!n.properties) return false;
      for (const [k, v] of n.properties) {
        if (/workspace/i.test(k) && v) return true;
      }
      return false;
    }) || /logAnalyticsWorkspace|log_analytics_workspace|workspace_id/i.test(this.source);
  }

  // Get all outputs
  hasOutputs() {
    return this.outputNodes().length > 0;
  }

  // Check if backend is configured (Terraform)
  hasRemoteBackend() {
    const tf = this.terraformBlock();
    if (!tf) return false;
    const body = tf.rawBody || {};
    return !!(body.backend || body.cloud);
  }

  // Check if provider version is pinned (Terraform)
  hasProviderVersionPin() {
    const tf = this.terraformBlock();
    if (!tf) return false;
    const body = tf.rawBody || {};
    if (!body.required_providers) return false;
    const rp = body.required_providers;
    if (typeof rp !== 'object') return false;
    return Object.values(rp).some(p => p && p.version);
  }

  // Check if required_version is set (Terraform)
  hasRequiredVersion() {
    const tf = this.terraformBlock();
    if (!tf) return false;
    return !!(tf.rawBody && tf.rawBody.required_version);
  }

  // Get API version year for a resource
  apiVersionYear(resource) {
    if (!resource.apiVersion) return null;
    const m = resource.apiVersion.match(/^(\d{4})/);
    return m ? parseInt(m[1]) : null;
  }

  // Check for hardcoded secrets in param default values
  hasHardcodedSecrets() {
    for (const p of this.paramNodes()) {
      // Secure params with default values are a problem
      if (p.decorators && p.decorators.includes('secure') && p.defaultValue !== undefined && p.defaultValue !== null) {
        return true;
      }
      // Any param named password/secret with a string default
      if (/password|secret|key/i.test(p.name || '') && typeof p.defaultValue === 'string' && p.defaultValue.length >= 4) {
        return true;
      }
    }
    // Check var values too
    for (const [name, val] of this.vars) {
      if (/password|secret|apikey/i.test(name) && typeof val === 'string' && val.length >= 4) {
        return true;
      }
    }
    return false;
  }
}

module.exports = { parse, tokenise, stripComments, ParseResult };
