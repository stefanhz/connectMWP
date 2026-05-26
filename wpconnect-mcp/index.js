#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/common/shared.js';
import fs from 'fs/promises';
import path from 'path';

// Parse command line arguments
const args = process.argv.slice(2);
let siteUrl = '';
let token = '';

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--site' && args[i + 1]) {
    siteUrl = args[i + 1].replace(/\/$/, '');
  } else if (args[i] === '--token' && args[i + 1]) {
    token = args[i + 1];
  }
}

// Fallback to environment variables
if (!siteUrl) siteUrl = process.env.WPCONNECT_SITE || '';
if (!token) token = process.env.WPCONNECT_TOKEN || '';

if (!siteUrl || !token) {
  console.error('Error: Missing WordPress site URL or connection token.');
  console.error('Usage: npx wpconnect-mcp --site <site_url> --token <token>');
  console.error('Or set WPCONNECT_SITE and WPCONNECT_TOKEN environment variables.');
  process.exit(1);
}

/**
 * Make a secure call to the WordPress Plugin REST API
 */
async function callWordPress(endpoint, method = 'GET', data = null, isUpload = false) {
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
      return await callWordPressAjax(endpoint, method, data, isUpload, headers);
    }

    const resData = await response.json();
    return resData;
  } catch (error) {
    console.error(`wpConnect: REST call failed (${error.message}). Attempting Admin-AJAX fallback...`);
    return await callWordPressAjax(endpoint, method, data, isUpload, headers);
  }
}

/**
 * Fallback handler: Routes requests through admin-ajax.php
 */
async function callWordPressAjax(endpoint, method, data, isUpload, headers) {
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
        description: 'Retrieve titles, content, URLs, and IDs of existing posts from the site. Used for business context research and finding internal linking opportunities.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'integer',
              description: 'Maximum number of posts to retrieve (default 50)',
            },
          },
        },
      },
      {
        name: 'wpconnect_create_post',
        description: 'Create a new post draft or publish directly. Returns post ID, permalink, and edit link.',
        inputSchema: {
          type: 'object',
          properties: {
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
        description: 'Upload a featured or inline image/graph to the WordPress media library from a local path or a remote image URL.',
        inputSchema: {
          type: 'object',
          properties: {
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
          properties: {},
        },
      },
      {
        name: 'wpconnect_list_categories',
        description: 'List all categories on the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {},
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
        const limit = args.limit || 50;
        const res = await callWordPress('posts', 'GET', { limit });
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_create_post': {
        const res = await callWordPress('posts', 'POST', args);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_update_post': {
        const { id, ...postParams } = args;
        const res = await callWordPress(`posts/${id}`, 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_upload_media': {
        const { file_path, image_url, filename } = args;
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

        const res = await callWordPress('media', 'POST', formData, true);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_list_tags': {
        const res = await callWordPress('tags', 'GET');
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'wpconnect_list_categories': {
        const res = await callWordPress('categories', 'GET');
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
