'use strict';

/**
 * Detects whether a document is Bicep, Terraform HCL, or ARM JSON.
 * Returns: 'bicep' | 'terraform' | 'arm' | 'unknown'
 */
function detectFormat(text) {
  const t = text.trim();
  if (!t) return 'unknown';

  // ARM JSON — has Azure schema or Microsoft. resource types in JSON
  if (t.startsWith('{') && /"\$schema"\s*:\s*"https:\/\/schema\.management\.azure/i.test(t)) return 'arm';
  if (t.startsWith('{') && /"type"\s*:\s*"Microsoft\./i.test(t)) return 'arm';

  // Terraform HCL — has terraform/resource/provider blocks
  if (/^\s*(terraform|resource|provider|variable|output|module|data)\s+["a-z_]/im.test(t)) return 'terraform';

  // Bicep — has decorators, targetScope, param, or resource with API version string
  if (/@(description|batchSize|secure|minLength|maxLength|allowed|minValue|maxValue)\s*\(/i.test(t)) return 'bicep';
  if (/\btargetScope\s*=/i.test(t)) return 'bicep';
  if (/^param\s+\w+\s+\w+/im.test(t)) return 'bicep';
  if (/^resource\s+\w+\s+'[^']+'\s*=/im.test(t)) return 'bicep';
  if (/^var\s+\w+\s*=/im.test(t)) return 'bicep';

  return 'unknown';
}

/**
 * Map VS Code language IDs to format hints.
 * The detector still runs on content, but file extension gives a strong prior.
 */
function formatFromLanguageId(languageId) {
  const map = {
    bicep: 'bicep',
    terraform: 'terraform',
    'arm-template': 'arm',
  };
  return map[languageId] || null;
}

module.exports = { detectFormat, formatFromLanguageId };
