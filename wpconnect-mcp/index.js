#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/common/shared.js';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';

// Configuration file path
const CONFIG_PATH = path.join(os.homedir(), '.wpconnect.json');

/**
 * Clean and normalize site URLs
 */
function normalizeSiteUrl(url) {
  if (!url) return '';
  let clean = url.trim().replace(/\/$/, '');
  if (!/^https?:\/\//i.test(clean)) {
    clean = 'https://' + clean;
  }
  return clean;
}

/**
 * Load settings from the local configuration file
 */
async function readConfig() {
  try {
    const data = await fs.readFile(CONFIG_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return { defaultSite: '', sites: {} };
  }
}

/**
 * Save settings to the local configuration file
 */
async function writeConfig(config) {
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
}

/**
 * Retrieve credentials for the selected target site
 */
async function getCredentials(requestedSite) {
  const config = await readConfig();
  
  let targetSite = '';
  if (requestedSite) {
    targetSite = normalizeSiteUrl(requestedSite);
  } else {
    targetSite = config.defaultSite;
  }
  
  if (!targetSite) {
    // Check environment variables as a legacy fallback
    const envSite = process.env.WPCONNECT_SITE;
    const envToken = process.env.WPCONNECT_TOKEN;
    if (envSite && envToken) {
      return { siteUrl: normalizeSiteUrl(envSite), token: envToken };
    }
    throw new Error('No WordPress site configured. Run "wpconnect-mcp add-site --site <url> --token <token>" in your terminal first.');
  }

  // Attempt direct lookup
  let siteConfig = config.sites && config.sites[targetSite];

  // Try matching domain names if the protocols/slashes differ slightly
  if (!siteConfig && requestedSite) {
    try {
      const requestedHost = new URL(normalizeSiteUrl(requestedSite)).hostname;
      const matchedKey = Object.keys(config.sites || {}).find(k => {
        try {
          return new URL(k).hostname === requestedHost;
        } catch {
          return false;
        }
      });
      if (matchedKey) {
        targetSite = matchedKey;
        siteConfig = config.sites[matchedKey];
      }
    } catch {
      // Fallback to raw check
    }
  }
  
  if (!siteConfig) {
    throw new Error(`WordPress site "${targetSite}" is not configured. Configure it first using "wpconnect-mcp add-site --site "${targetSite}" --token <token>".`);
  }
  
  return { siteUrl: targetSite, token: siteConfig.token };
}

// ============================================================================
// CLI MANAGEMENT COMMANDS
// ============================================================================
const args = process.argv.slice(2);
const command = args[0];

if (command === 'add-site') {
  let site = '';
  let token = '';
  let isDefault = false;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--site' && args[i + 1]) {
      site = args[i + 1];
    } else if (args[i] === '--token' && args[i + 1]) {
      token = args[i + 1];
    } else if (args[i] === '--default') {
      isDefault = true;
    }
  }

  if (!site || !token) {
    console.error('Error: Both --site and --token parameters are required.');
    console.error('Usage: wpconnect-mcp add-site --site <site_url> --token <token> [--default]');
    process.exit(1);
  }

  const normalizedSite = normalizeSiteUrl(site);
  const config = await readConfig();

  config.sites = config.sites || {};
  config.sites[normalizedSite] = {
    token: token,
    label: new URL(normalizedSite).hostname,
    updated: new Date().toISOString()
  };

  if (isDefault || !config.defaultSite) {
    config.defaultSite = normalizedSite;
  }

  await writeConfig(config);
  console.log(`[SUCCESS] Configured connection for site: ${normalizedSite}`);
  if (config.defaultSite === normalizedSite) {
    console.log(`[INFO] Set ${normalizedSite} as default target site.`);
  }
  process.exit(0);
}

if (command === 'list-sites') {
  const config = await readConfig();
  const sitesList = Object.keys(config.sites || {});

  if (sitesList.length === 0) {
    console.log('No WordPress sites configured in ~/.wpconnect.json yet.');
    console.log('Configure a site using: wpconnect-mcp add-site --site <url> --token <token>');
    process.exit(0);
  }

  console.log('\nConfigured wpConnect WordPress Sites:');
  console.log('===========================================================================');
  for (const site of sitesList) {
    const isDefault = config.defaultSite === site ? ' [DEFAULT]' : '';
    console.log(`- ${site}${isDefault}`);
  }
  console.log('===========================================================================\n');
  process.exit(0);
}

if (command === 'remove-site') {
  let site = '';
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--site' && args[i + 1]) {
      site = args[i + 1];
    }
  }

  if (!site) {
    console.error('Error: --site parameter is required.');
    console.error('Usage: wpconnect-mcp remove-site --site <site_url>');
    process.exit(1);
  }

  const normalizedSite = normalizeSiteUrl(site);
  const config = await readConfig();

  if (config.sites && config.sites[normalizedSite]) {
    delete config.sites[normalizedSite];
    if (config.defaultSite === normalizedSite) {
      config.defaultSite = Object.keys(config.sites)[0] || '';
    }
    await writeConfig(config);
    console.log(`[SUCCESS] Removed site ${normalizedSite} from config.`);
  } else {
    console.error(`[ERROR] Site ${normalizedSite} not found in configuration.`);
    process.exit(1);
  }
  process.exit(0);
}

if (command === 'set-default') {
  let site = '';
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--site' && args[i + 1]) {
      site = args[i + 1];
    }
  }

  if (!site) {
    console.error('Error: --site parameter is required.');
    console.error('Usage: wpconnect-mcp set-default --site <site_url>');
    process.exit(1);
  }

  const normalizedSite = normalizeSiteUrl(site);
  const config = await readConfig();

  if (config.sites && config.sites[normalizedSite]) {
    config.defaultSite = normalizedSite;
    await writeConfig(config);
    console.log(`[SUCCESS] Set ${normalizedSite} as default target site.`);
  } else {
    console.error(`[ERROR] Site ${normalizedSite} is not configured. Add it first.`);
    process.exit(1);
  }
  process.exit(0);
}

// ============================================================================
// NETWORK REQUEST EXECUTORS
// ============================================================================

/**
 * Make a secure call to the WordPress Plugin REST API
 */
async function callWordPress(siteUrl, token, endpoint, method = 'GET', data = null, isUpload = false) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

  const url = `${siteUrl}/wp-json/wpconnect/v1/${endpoint}`;
  
  const headers = {
    'X-WPConnect-Auth': `Bearer ${token}`,
    'X-WPConnect-Timestamp': timestamp,
    'X-WPConnect-Nonce': nonce
  };

  let body = null;
  if (data) {
    if (isUpload) {
      body = data; // FormData
    } else {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(data);
    }
  }

  try {
    const response = await fetch(url, { method, headers, body });

    // If REST API is not found or fails with auth/security block, try Admin-AJAX fallback
    if (response.status === 401 || response.status === 404 || response.status === 403) {
      return await callWordPressAjax(siteUrl, token, endpoint, method, data, isUpload, headers);
    }

    const resData = await response.json();
    return resData;
  } catch (error) {
    console.error(`wpConnect: REST call failed (${error.message}). Attempting Admin-AJAX fallback...`);
    return await callWordPressAjax(siteUrl, token, endpoint, method, data, isUpload, headers);
  }
}

/**
 * Fallback handler: Routes requests through admin-ajax.php
 */
async function callWordPressAjax(siteUrl, token, endpoint, method, data, isUpload, headers) {
  const ajaxUrl = `${siteUrl}/wp-admin/admin-ajax.php`;
  
  // Translate REST route to AJAX action
  let action = '';
  if (endpoint === 'posts') {
    action = method === 'GET' ? 'get_posts' : 'create_post';
  } else if (endpoint.startsWith('posts/')) {
    action = 'update_post';
  } else if (endpoint === 'media') {
    action = 'upload_media';
  } else if (endpoint === 'tags') {
    action = 'get_tags';
  } else if (endpoint === 'categories') {
    action = 'get_categories';
  }

  const ajaxHeaders = { ...headers };
  let body;

  if (isUpload) {
    body = data;
    body.append('action', 'wpconnect_api');
    body.append('wpconnect_action', action);
  } else {
    ajaxHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
    const params = new URLSearchParams();
    params.append('action', 'wpconnect_api');
    params.append('wpconnect_action', action);
    
    if (action === 'update_post') {
      const postId = endpoint.split('/')[1];
      params.append('post_id', postId);
    }

    if (data) {
      for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'object') {
          params.append(key, JSON.stringify(value));
        } else {
          params.append(key, value);
        }
      }
    }
    body = params.toString();
  }

  const response = await fetch(ajaxUrl, { method: 'POST', headers: ajaxHeaders, body });
  return await response.json();
}

// ============================================================================
// MCP SERVER INITIALIZATION
// ============================================================================

// Create the MCP Server instance
const server = new Server(
  {
    name: 'wpconnect-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register Tool Schemas
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'wpconnect_get_posts',
        description: 'Retrieve titles, content, URLs, and IDs of existing posts from the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            limit: {
              type: 'integer',
              description: 'Maximum number of posts to retrieve (default 50)',
            },
          },
        },
      },
      {
        name: 'wpconnect_create_post',
        description: 'Create a new post draft or publish directly on a WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            title: {
              type: 'string',
              description: 'Title of the post',
            },
            content: {
              type: 'string',
              description: 'Content of the post in clean HTML or Gutenberg block markup',
            },
            status: {
              type: 'string',
              enum: ['draft', 'publish'],
              description: 'Post status: draft (default for review) or publish (direct)',
            },
            categories: {
              type: 'array',
              items: { type: 'integer' },
              description: 'List of category IDs to assign',
            },
            tags: {
              type: 'array',
              items: { type: 'integer' },
              description: 'List of tag IDs to assign (e.g. 1-5 tags)',
            },
            featured_media: {
              type: 'integer',
              description: 'ID of the uploaded media file to set as the Featured Image',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'wpconnect_update_post',
        description: 'Update an existing post (e.g., to insert SEO internal links).',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            id: {
              type: 'integer',
              description: 'WordPress Post ID to update',
            },
            title: {
              type: 'string',
              description: 'New title',
            },
            content: {
              type: 'string',
              description: 'New content body',
            },
            status: {
              type: 'string',
              enum: ['draft', 'publish'],
            },
            categories: {
              type: 'array',
              items: { type: 'integer' },
            },
            tags: {
              type: 'array',
              items: { type: 'integer' },
            },
            featured_media: {
              type: 'integer',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'wpconnect_upload_media',
        description: 'Upload a featured or inline image/graph to the WordPress media library.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            file_path: {
              type: 'string',
              description: 'Absolute path to the image file on your local machine',
            },
            image_url: {
              type: 'string',
              description: 'URL of the remote image to download and upload',
            },
            filename: {
              type: 'string',
              description: 'Optional name for the file (default image.png)',
            },
          },
        },
      },
      {
        name: 'wpconnect_list_tags',
        description: 'List all tags on the WordPress site to select the 1-5 most relevant ones.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            }
          },
        },
      },
      {
        name: 'wpconnect_list_categories',
        description: 'List all categories on the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            }
          },
        },
      },
    ],
  };
});

// Handle Tool Executions
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'wpconnect_get_posts': {
        const { site, limit = 50 } = args;
        const { siteUrl, token } = await getCredentials(site);
        const res = await callWordPress(siteUrl, token, 'posts', 'GET', { limit });
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_create_post': {
        const { site, ...postParams } = args;
        const { siteUrl, token } = await getCredentials(site);
        const res = await callWordPress(siteUrl, token, 'posts', 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_update_post': {
        const { site, id, ...postParams } = args;
        const { siteUrl, token } = await getCredentials(site);
        const res = await callWordPress(siteUrl, token, `posts/${id}`, 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_upload_media': {
        const { site, file_path, image_url, filename } = args;
        const { siteUrl, token } = await getCredentials(site);
        let fileBuffer;
        let nameToUse = filename || 'image.png';

        if (!file_path && !image_url) {
          throw new Error('Either file_path or image_url must be provided.');
        }

        if (image_url) {
          // Fetch image from URL
          const imgRes = await fetch(image_url);
          if (!imgRes.ok) throw new Error(`Failed to download image from URL: ${image_url}`);
          fileBuffer = Buffer.from(await imgRes.arrayBuffer());
          if (!filename) {
            const urlPath = new URL(image_url).pathname;
            const parsedName = path.basename(urlPath);
            if (parsedName && parsedName.includes('.')) nameToUse = parsedName;
          }
        } else {
          // Read local file
          fileBuffer = await fs.readFile(file_path);
          if (!filename) nameToUse = path.basename(file_path);
        }

        // Build FormData payload compatible with native fetch
        const formData = new FormData();
        const blob = new Blob([fileBuffer]);
        formData.append('file', blob, nameToUse);

        const res = await callWordPress(siteUrl, token, 'media', 'POST', formData, true);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_list_tags': {
        const { site } = args;
        const { siteUrl, token } = await getCredentials(site);
        const res = await callWordPress(siteUrl, token, 'tags', 'GET');
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_list_categories': {
        const { site } = args;
        const { siteUrl, token } = await getCredentials(site);
        const res = await callWordPress(siteUrl, token, 'categories', 'GET');
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify({ success: false, error: error.message }) }],
    };
  }
});

// Run the MCP server
async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('wpConnect MCP Server running on stdio');
}

run().catch((error) => {
  console.error('Fatal error running server:', error);
  process.exit(1);
});
