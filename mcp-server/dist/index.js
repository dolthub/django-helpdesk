#!/usr/bin/env node
/**
 * Django Helpdesk MCP Server (TypeScript)
 *
 * This MCP server exposes the django-helpdesk API to AI agents, providing tools for:
 * - Listing and filtering tickets
 * - Creating new tickets
 * - Adding follow-ups to tickets
 * - Managing ticket status and assignments
 * - Retrieving ticket details
 * - Agent session management
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema, ListPromptsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import { createWriteStream } from 'fs';
import { resolve } from 'path';
import { wrapper as axiosCookieJarSupport } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
class HelpdeskMCPServer {
    server;
    config;
    client;
    authenticated = false;
    sessionInfo = null;
    csrfToken;
    credentials = {};
    logStream;
    cookieJar;
    constructor(logFile) {
        this.server = new Server({
            name: 'django-helpdesk-ts',
            version: '0.1.0',
        }, {
            capabilities: {
                tools: {},
                resources: {},
                prompts: {},
            },
        });
        this.setupFileLogging(logFile);
        this.config = this.loadConfig();
        this.cookieJar = new CookieJar();
        // Set up axios with cookie jar support
        axiosCookieJarSupport(axios);
        this.client = axios.create({
            baseURL: this.config.baseUrl,
            timeout: 30000,
            withCredentials: true,
            // Enable cookie jar for automatic cookie handling
            jar: this.cookieJar,
        });
        this.setupHandlers();
        this.setupLogging();
    }
    setupFileLogging(logFile) {
        if (logFile) {
            try {
                const logPath = resolve(logFile);
                this.logStream = createWriteStream(logPath, { flags: 'a' });
                this.logStream.on('error', (err) => {
                    console.error(`Failed to write to log file ${logPath}: ${err.message}`);
                });
            }
            catch (error) {
                console.error(`Failed to setup log file ${logFile}: ${error}`);
            }
        }
    }
    log(message) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] ${message}\n`;
        if (this.logStream) {
            this.logStream.write(logMessage);
        }
        else {
            // Fallback to stderr if no log file specified
            process.stderr.write(logMessage);
        }
    }
    getCurrentCsrfToken() {
        /**
         * Extract current CSRF token from cookies.
         * This is required for Django REST Framework's SessionAuthentication.
         */
        try {
            const jar = this.client.defaults.jar;
            if (!jar)
                return null;
            const cookies = jar.getCookiesSync(this.config.baseUrl);
            for (const cookie of cookies) {
                if (cookie.key === 'csrftoken') {
                    return cookie.value;
                }
            }
        }
        catch (error) {
            this.log(`⚠️ Error getting CSRF token from cookies: ${error}`);
        }
        return null;
    }
    loadConfig() {
        // Use 127.0.0.1 instead of localhost to avoid IPv6 resolution issues
        const defaultUrl = process.env.HELPDESK_BASE_URL || 'http://127.0.0.1:8080';
        return {
            baseUrl: defaultUrl,
        };
    }
    setupLogging() {
        // Setup request/response interceptors for detailed logging
        this.client.interceptors.request.use((config) => {
            this.log(`🌐 HTTP Request: ${config.method?.toUpperCase()} ${config.url}`);
            this.log(`📤 Request Headers: ${JSON.stringify(config.headers, null, 2)}`);
            if (config.params) {
                this.log(`📤 Request Params: ${JSON.stringify(config.params, null, 2)}`);
            }
            if (config.data) {
                this.log(`📤 Request Body: ${JSON.stringify(config.data, null, 2)}`);
            }
            return config;
        }, (error) => {
            this.log(`❌ Request Error: ${error.message}`);
            return Promise.reject(error);
        });
        this.client.interceptors.response.use((response) => {
            this.log(`📥 Response Status: ${response.status}`);
            this.log(`📥 Response Headers: ${JSON.stringify(response.headers, null, 2)}`);
            this.log(`📥 Response Body: ${JSON.stringify(response.data, null, 2)}`);
            this.log(`✅ HTTP Response Success: ${response.config.method?.toUpperCase()} ${response.config.url}`);
            return response;
        }, (error) => {
            this.log(`❌ Response Error: ${error.message}`);
            if (error.response) {
                this.log(`📥 Error Response Status: ${error.response.status}`);
                this.log(`📥 Error Response Headers: ${JSON.stringify(error.response.headers, null, 2)}`);
                this.log(`📥 Error Response Body: ${JSON.stringify(error.response.data, null, 2)}`);
                // Enhanced debugging for 403 Forbidden errors
                if (error.response.status === 403) {
                    this.log(`🚫 403 FORBIDDEN DEBUG INFO:`);
                    this.log(`🚫 Request URL: ${error.config?.url}`);
                    this.log(`🚫 Request Method: ${error.config?.method?.toUpperCase()}`);
                    this.log(`🚫 Request Headers: ${JSON.stringify(error.config?.headers, null, 2)}`);
                    this.log(`🚫 Authentication Status: ${this.authenticated}`);
                    this.log(`🚫 Authentication Method: HTTP Basic Auth`);
                    this.log(`🚫 CSRF Token: ${this.csrfToken ? this.csrfToken.substring(0, 10) + '...' : 'None'}`);
                    // Log cookies for debugging
                    if (this.cookieJar) {
                        this.cookieJar.getCookies(error.config?.url || this.config.baseUrl)
                            .then(cookies => {
                            this.log(`🚫 Current Cookies: ${cookies.map(c => `${c.key}=${c.value}`).join('; ')}`);
                        })
                            .catch(cookieError => {
                            this.log(`🚫 Cookie Error: ${cookieError.message}`);
                        });
                    }
                    // Log response details that might indicate permission issues
                    if (error.response.data) {
                        const errorData = error.response.data;
                        if (typeof errorData === 'string') {
                            this.log(`🚫 Error Message: ${errorData}`);
                        }
                        else if (errorData.detail) {
                            this.log(`🚫 Error Detail: ${errorData.detail}`);
                        }
                        else if (errorData.error) {
                            this.log(`🚫 Error Field: ${errorData.error}`);
                        }
                    }
                }
            }
            return Promise.reject(error);
        });
    }
    setupHandlers() {
        // List tools handler
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            this.log('📨 MCP Request: list_tools');
            this.log('📤 MCP Request Headers: {}');
            this.log('📤 MCP Request Body: {}');
            const tools = [
                {
                    name: 'authenticate',
                    description: 'Authenticate with django-helpdesk using username and password',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            username: {
                                type: 'string',
                                description: 'Username for authentication',
                            },
                            password: {
                                type: 'string',
                                description: 'Password for authentication',
                            },
                        },
                        required: ['username', 'password'],
                    },
                },
                {
                    name: 'list_tickets',
                    description: 'List tickets with optional filtering by status, queue, or other criteria',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            status: {
                                type: 'string',
                                description: 'Filter by ticket status (e.g., "Open", "Resolved", "Closed"). Can be comma-separated for multiple statuses.',
                            },
                            queue_id: {
                                type: 'number',
                                description: 'Filter by queue ID',
                            },
                            assigned_to: {
                                type: 'number',
                                description: 'Filter by assigned user ID',
                            },
                            page: {
                                type: 'number',
                                description: 'Page number for pagination (default: 1)',
                            },
                            page_size: {
                                type: 'number',
                                description: 'Number of results per page (default: 25)',
                            },
                        },
                    },
                },
                {
                    name: 'get_ticket',
                    description: 'Get detailed information about a specific ticket',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            ticket_id: {
                                type: 'number',
                                description: 'The ID of the ticket to retrieve',
                            },
                        },
                        required: ['ticket_id'],
                    },
                },
                {
                    name: 'create_ticket',
                    description: 'Create a new ticket',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            queue: {
                                type: 'number',
                                description: 'Queue ID for the ticket',
                            },
                            title: {
                                type: 'string',
                                description: 'Title of the ticket',
                            },
                            description: {
                                type: 'string',
                                description: 'Description/body of the ticket',
                            },
                            submitter_email: {
                                type: 'string',
                                description: 'Email address of the ticket submitter',
                            },
                            priority: {
                                type: 'number',
                                description: 'Priority level (1-5, where 1 is highest priority)',
                            },
                            assigned_to: {
                                type: 'number',
                                description: 'User ID to assign the ticket to (optional)',
                            },
                            due_date: {
                                type: 'string',
                                format: 'date',
                                description: 'Due date in YYYY-MM-DD format (optional)',
                            },
                        },
                        required: ['queue', 'title', 'description', 'submitter_email'],
                    },
                },
                {
                    name: 'add_followup',
                    description: 'Add a follow-up comment to an existing ticket',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            ticket_id: {
                                type: 'number',
                                description: 'The ID of the ticket to add a follow-up to',
                            },
                            title: {
                                type: 'string',
                                description: 'Title of the follow-up',
                            },
                            comment: {
                                type: 'string',
                                description: 'The follow-up comment text',
                            },
                            public: {
                                type: 'boolean',
                                description: 'Whether this follow-up is visible to the public (default: true)',
                            },
                            new_status: {
                                type: 'number',
                                description: 'New status to set for the ticket (optional)',
                            },
                            time_spent: {
                                type: 'string',
                                description: 'Time spent on this follow-up (in minutes or HH:MM format)',
                            },
                        },
                        required: ['ticket_id', 'comment'],
                    },
                },
                {
                    name: 'update_ticket',
                    description: 'Update an existing ticket\'s properties',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            ticket_id: {
                                type: 'number',
                                description: 'The ID of the ticket to update',
                            },
                            title: {
                                type: 'string',
                                description: 'New title for the ticket',
                            },
                            description: {
                                type: 'string',
                                description: 'New description for the ticket',
                            },
                            status: {
                                type: 'number',
                                description: 'New status for the ticket',
                            },
                            priority: {
                                type: 'number',
                                description: 'New priority level (1-5)',
                            },
                            assigned_to: {
                                type: 'number',
                                description: 'User ID to assign the ticket to',
                            },
                            due_date: {
                                type: 'string',
                                format: 'date',
                                description: 'New due date in YYYY-MM-DD format',
                            },
                        },
                        required: ['ticket_id'],
                    },
                },
                {
                    name: 'get_queues',
                    description: 'List all available ticket queues',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                    },
                },
                {
                    name: 'get_users',
                    description: 'List users that can be assigned to tickets',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            page: {
                                type: 'number',
                                description: 'Page number for pagination',
                            },
                        },
                    },
                },
                {
                    name: 'get_agent_session_info',
                    description: 'Get current agent session information (branch name, intent, etc.)',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                    },
                },
                {
                    name: 'set_agent_intent',
                    description: 'Set the intent for the current agent session',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            intent: {
                                type: 'string',
                                description: 'The intent to set for the session (max 512 characters)',
                            },
                        },
                        required: ['intent'],
                    },
                },
                {
                    name: 'finish_agent_session',
                    description: 'Finish the current agent session and perform cleanup',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                    },
                },
            ];
            const result = { tools };
            this.log(`📥 MCP Response: list_tools -> ${tools.length} tools`);
            this.log('📥 MCP Response Headers: {}');
            this.log(`📥 MCP Response Body: ${JSON.stringify(result, null, 2)}`);
            return result;
        });
        // List resources handler
        this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
            this.log('📨 MCP Request: list_resources');
            this.log('📤 MCP Request Headers: {}');
            this.log('📤 MCP Request Body: {}');
            const result = { resources: [] };
            this.log('📥 MCP Response: list_resources -> 0 resources');
            this.log('📥 MCP Response Headers: {}');
            this.log(`📥 MCP Response Body: ${JSON.stringify(result, null, 2)}`);
            return result;
        });
        // List prompts handler
        this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
            this.log('📨 MCP Request: list_prompts');
            this.log('📤 MCP Request Headers: {}');
            this.log('📤 MCP Request Body: {}');
            const result = { prompts: [] };
            this.log('📥 MCP Response: list_prompts -> 0 prompts');
            this.log('📥 MCP Response Headers: {}');
            this.log(`📥 MCP Response Body: ${JSON.stringify(result, null, 2)}`);
            return result;
        });
        // Call tool handler
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;
            // Log MCP request with masked sensitive data
            const safeArgs = { ...args };
            if (name === 'authenticate' && safeArgs.password) {
                safeArgs.password = '***';
            }
            const requestBody = {
                method: 'tools/call',
                params: {
                    name,
                    arguments: safeArgs,
                },
            };
            this.log('📨 MCP Request: call_tool');
            this.log('📤 MCP Request Headers: {}');
            this.log(`📤 MCP Request Body: ${JSON.stringify(requestBody, null, 2)}`);
            try {
                let result;
                switch (name) {
                    case 'authenticate':
                        result = await this.authenticateUser(args);
                        break;
                    case 'list_tickets':
                        result = await this.listTickets(args);
                        break;
                    case 'get_ticket':
                        result = await this.getTicket(args);
                        break;
                    case 'create_ticket':
                        result = await this.createTicket(args);
                        break;
                    case 'add_followup':
                        result = await this.addFollowup(args);
                        break;
                    case 'update_ticket':
                        result = await this.updateTicket(args);
                        break;
                    case 'get_queues':
                        result = await this.getQueues(args);
                        break;
                    case 'get_users':
                        result = await this.getUsers(args);
                        break;
                    case 'get_agent_session_info':
                        result = await this.getAgentSessionInfo(args);
                        break;
                    case 'set_agent_intent':
                        result = await this.setAgentIntent(args);
                        break;
                    case 'finish_agent_session':
                        result = await this.finishAgentSession(args);
                        break;
                    default:
                        result = {
                            content: [
                                {
                                    type: 'text',
                                    text: `Unknown tool: ${name}`,
                                },
                            ],
                            isError: true,
                        };
                }
                this.log(`✅ Tool completed: ${name}`);
                this.log('📥 MCP Response: call_tool -> Success');
                this.log('📥 MCP Response Headers: {}');
                this.log(`📥 MCP Response Body: ${JSON.stringify(result, null, 2)}`);
                return result;
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                const errorResult = {
                    content: [
                        {
                            type: 'text',
                            text: `Error calling ${name}: ${errorMessage}`,
                        },
                    ],
                    isError: true,
                };
                this.log(`❌ Tool error: ${name} -> ${errorMessage}`);
                this.log('📥 MCP Response: call_tool -> Error');
                this.log('📥 MCP Response Headers: {}');
                this.log(`📥 MCP Response Body: ${JSON.stringify(errorResult, null, 2)}`);
                return errorResult;
            }
        });
    }
    async makeRequest(method, endpoint, params, data) {
        if (!this.authenticated) {
            throw new Error('Authentication required');
        }
        const config = {
            method,
            url: `/api/${endpoint.replace(/^\//, '')}`,
        };
        if (params)
            config.params = params;
        if (data)
            config.data = data;
        // Set up headers
        config.headers = {};
        // Add Content-Type for requests with data
        if (data) {
            config.headers['Content-Type'] = 'application/json';
        }
        // Add CSRF token if available (needed for POST/PUT/PATCH/DELETE requests)
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
            // Get current CSRF token from cookies (required for DRF SessionAuthentication)
            const currentCsrfToken = this.getCurrentCsrfToken();
            if (currentCsrfToken) {
                config.headers['X-CSRFToken'] = currentCsrfToken;
                this.log(`🔑 Using current CSRF token: ${currentCsrfToken.substring(0, 20)}...`);
            }
            else if (this.csrfToken) {
                // Fallback to stored token from login
                config.headers['X-CSRFToken'] = this.csrfToken;
                this.log(`🔑 Using stored CSRF token: ${this.csrfToken.substring(0, 20)}...`);
            }
            else {
                this.log(`⚠️ No CSRF token available for ${method} request`);
            }
        }
        // Enhanced logging for API requests to help debug 403s
        this.log(`🔧 Making API request: ${method} ${config.url}`);
        this.log(`🔧 Request config: ${JSON.stringify({
            method: config.method,
            url: config.url,
            headers: config.headers,
            hasData: !!data,
            hasParams: !!params
        }, null, 2)}`);
        const response = await this.client.request(config);
        return response.data;
    }
    async authenticateUser(args) {
        const { username, password } = args;
        this.credentials.username = username;
        this.credentials.password = password;
        // Check if already authenticated - test with a simple API call
        this.log(`🔍 Checking if already authenticated...`);
        try {
            const testResponse = await this.client.get('/api/agent-session-info/');
            if (testResponse.status === 200) {
                this.log(`✅ Already authenticated! Session info: ${JSON.stringify(testResponse.data)}`);
                this.authenticated = true;
                return {
                    content: [
                        {
                            type: 'text',
                            text: `Already authenticated as user: ${testResponse.data.username}\nBranch: ${testResponse.data.branch_name || 'Not set'}\nIntent: ${testResponse.data.intent || 'Not set'}`,
                        },
                    ],
                };
            }
        }
        catch (error) {
            this.log(`🔍 Not authenticated yet, proceeding with login...`);
        }
        this.log(`🔑 Attempting Django session authentication for user: ${username}`);
        try {
            // Step 1: Get the login page to extract CSRF token (same as api_client.py)
            const loginUrl = `${this.config.baseUrl}/login/`;
            this.log(`🌐 Getting CSRF token from login page: GET ${loginUrl}`);
            const loginPageResponse = await this.client.get(loginUrl);
            this.log(`📥 Login page response: ${loginPageResponse.status}`);
            // Step 2: Extract CSRF token from login form (same logic as api_client.py)
            let csrfToken = null;
            // Try to extract from HTML form
            const csrfMatch = loginPageResponse.data.match(/name=['"]csrfmiddlewaretoken['"] value=['"]([^'"]+)['"]/);
            if (csrfMatch) {
                csrfToken = csrfMatch[1];
                this.log(`🔑 CSRF token extracted from login form: ${csrfToken.substring(0, 20)}...`);
            }
            // Also get CSRF token from cookies
            if (loginPageResponse.headers['set-cookie']) {
                const csrfCookie = loginPageResponse.headers['set-cookie']
                    .find((cookie) => cookie.startsWith('csrftoken='));
                if (csrfCookie) {
                    const cookieToken = csrfCookie.split('=')[1].split(';')[0];
                    if (!csrfToken) {
                        csrfToken = cookieToken;
                    }
                    this.log(`🔑 CSRF token from cookies: ${cookieToken.substring(0, 20)}...`);
                }
            }
            if (!csrfToken) {
                this.log(`⚠️ No CSRF token found, proceeding without it`);
            }
            // Step 3: Prepare login data (same as api_client.py)
            const loginData = {
                username,
                password,
            };
            if (csrfToken) {
                loginData.csrfmiddlewaretoken = csrfToken;
            }
            // Step 4: Prepare headers (same as api_client.py)
            const headers = {
                'Referer': loginUrl,
                'Content-Type': 'application/x-www-form-urlencoded',
            };
            if (csrfToken) {
                headers['X-CSRFToken'] = csrfToken;
                this.csrfToken = csrfToken; // Store for future API calls
            }
            this.log(`🌐 Submitting login form to: ${loginUrl}`);
            this.log(`📤 Login headers: ${JSON.stringify(headers, null, 2)}`);
            this.log(`📤 Login data: ${JSON.stringify({ ...loginData, password: '***' }, null, 2)}`);
            // Step 5: Submit login form (use form data, not JSON)
            const loginResponse = await this.client.post(loginUrl, new URLSearchParams(loginData), {
                headers,
                maxRedirects: 0,
                validateStatus: (status) => status >= 200 && status < 400,
            });
            this.log(`📥 Login response status: ${loginResponse.status}`);
            this.log(`📥 Response headers: ${JSON.stringify(loginResponse.headers, null, 2)}`);
            // Step 6: Check for successful login (same logic as api_client.py)
            let loginSuccess = false;
            if (loginResponse.status === 302 || loginResponse.status === 301) {
                this.log(`✅ Login successful (redirect detected)`);
                loginSuccess = true;
            }
            else if (loginResponse.status === 200) {
                // Check if we're still on login page (login failed) or redirected to dashboard
                const responseText = loginResponse.data || '';
                if (responseText.includes('login') || responseText.includes('password')) {
                    this.log(`❌ Login failed - still on login page`);
                    throw new Error('Invalid credentials');
                }
                else {
                    this.log(`✅ Login successful (200 response)`);
                    loginSuccess = true;
                }
            }
            else {
                throw new Error(`Login failed with status ${loginResponse.status}`);
            }
            if (loginSuccess) {
                // Check for session cookie
                const sessionCookies = loginResponse.headers['set-cookie'] || [];
                const sessionCookie = sessionCookies.find((cookie) => cookie.startsWith('sessionid='));
                if (sessionCookie) {
                    this.log(`🍪 Session ID: ${sessionCookie.split('=')[1].split(';')[0].substring(0, 20)}...`);
                }
                this.authenticated = true;
                this.log(`✅ Successfully authenticated user: ${username} using Django session login`);
                return {
                    content: [
                        {
                            type: 'text',
                            text: `✓ Successfully authenticated as ${username} using Django session authentication\n\nYou can now use other tools to interact with the helpdesk system.`,
                        },
                    ],
                };
            }
            else {
                throw new Error('Authentication failed');
            }
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            this.log(`❌ Authentication failed for ${username}: ${errorMessage}`);
            throw new Error(`Authentication failed: ${errorMessage}`);
        }
    }
    async listTickets(args) {
        const params = {};
        if (args.status)
            params.status = args.status;
        if (args.queue_id)
            params.queue_id = args.queue_id;
        if (args.assigned_to)
            params.assigned_to = args.assigned_to;
        if (args.page)
            params.page = args.page;
        if (args.page_size)
            params.page_size = args.page_size;
        const data = await this.makeRequest('GET', 'tickets/', params);
        let resultText = `Found ${data.count || 0} tickets`;
        if (data.results && data.results.length > 0) {
            resultText += ':\n\n';
            data.results.forEach((ticket) => {
                resultText += `#${ticket.id}: ${ticket.title}\n`;
                resultText += `  Status: ${ticket.status || 'Unknown'}\n`;
                resultText += `  Queue: ${ticket.queue?.title || 'Unknown'}\n`;
                resultText += `  Created: ${ticket.created || 'Unknown'}\n`;
                if (ticket.assigned_to) {
                    resultText += `  Assigned to: ${ticket.assigned_to}\n`;
                }
                resultText += '\n';
            });
        }
        return {
            content: [
                {
                    type: 'text',
                    text: resultText,
                },
            ],
        };
    }
    async getTicket(args) {
        const { ticket_id } = args;
        const data = await this.makeRequest('GET', `tickets/${ticket_id}/`);
        let resultText = `Ticket #${data.id}: ${data.title}\n`;
        resultText += `Status: ${data.status || 'Unknown'}\n`;
        resultText += `Priority: ${data.priority || 'Unknown'}\n`;
        resultText += `Queue: ${data.queue || 'Unknown'}\n`;
        resultText += `Submitter: ${data.submitter_email || 'Unknown'}\n`;
        if (data.assigned_to) {
            resultText += `Assigned to: ${data.assigned_to}\n`;
        }
        if (data.due_date) {
            resultText += `Due date: ${data.due_date}\n`;
        }
        resultText += `\nDescription:\n${data.description || 'No description'}\n`;
        if (data.followup_set && data.followup_set.length > 0) {
            resultText += `\nFollow-ups (${data.followup_set.length}):\n`;
            data.followup_set.forEach((followup) => {
                resultText += `- ${followup.date || 'Unknown date'}: ${followup.title || 'No title'}\n`;
                if (followup.comment) {
                    const comment = followup.comment.length > 100
                        ? followup.comment.substring(0, 100) + '...'
                        : followup.comment;
                    resultText += `  ${comment}\n`;
                }
            });
        }
        return {
            content: [
                {
                    type: 'text',
                    text: resultText,
                },
            ],
        };
    }
    async createTicket(args) {
        const ticketData = {
            queue: args.queue,
            title: args.title,
            description: args.description,
            submitter_email: args.submitter_email,
        };
        // Add optional fields
        ['priority', 'assigned_to', 'due_date'].forEach((field) => {
            if (args[field]) {
                ticketData[field] = args[field];
            }
        });
        const data = await this.makeRequest('POST', 'tickets/', undefined, ticketData);
        let resultText = `Created ticket #${data.id}: ${data.title}\n`;
        resultText += `Status: ${data.status || 'Unknown'}\n`;
        resultText += `Queue: ${data.queue || 'Unknown'}\n`;
        resultText += `Submitter: ${data.submitter_email || 'Unknown'}\n`;
        return {
            content: [
                {
                    type: 'text',
                    text: resultText,
                },
            ],
        };
    }
    async addFollowup(args) {
        const { ticket_id, comment } = args;
        const followupData = {
            ticket: ticket_id,
            comment,
            public: args.public !== undefined ? args.public : true,
        };
        // Add optional fields
        if (args.title)
            followupData.title = args.title;
        if (args.new_status)
            followupData.new_status = args.new_status;
        if (args.time_spent)
            followupData.time_spent = args.time_spent;
        const data = await this.makeRequest('POST', 'followups/', undefined, followupData);
        let resultText = `Added follow-up to ticket #${ticket_id}\n`;
        resultText += `Follow-up ID: ${data.id}\n`;
        resultText += `Date: ${data.date || 'Unknown'}\n`;
        if (data.title) {
            resultText += `Title: ${data.title}\n`;
        }
        return {
            content: [
                {
                    type: 'text',
                    text: resultText,
                },
            ],
        };
    }
    async updateTicket(args) {
        const { ticket_id, ...updateData } = args;
        const data = await this.makeRequest('PATCH', `tickets/${ticket_id}/`, undefined, updateData);
        let resultText = `Updated ticket #${data.id}: ${data.title}\n`;
        resultText += `Status: ${data.status || 'Unknown'}\n`;
        resultText += `Priority: ${data.priority || 'Unknown'}\n`;
        return {
            content: [
                {
                    type: 'text',
                    text: resultText,
                },
            ],
        };
    }
    async getQueues(args) {
        try {
            const data = await this.makeRequest('GET', 'queues/');
            let resultText = 'Available queues:\n\n';
            const queues = data.results || data;
            if (Array.isArray(queues)) {
                queues.forEach((queue) => {
                    resultText += `ID ${queue.id}: ${queue.title}\n`;
                    if (queue.slug) {
                        resultText += `  Slug: ${queue.slug}\n`;
                    }
                    resultText += '\n';
                });
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
        catch (error) {
            // Fallback: extract queue info from tickets
            const ticketData = await this.makeRequest('GET', 'tickets/', { page_size: 100 });
            const queues = {};
            if (ticketData.results) {
                ticketData.results.forEach((ticket) => {
                    if (ticket.queue && ticket.queue.id) {
                        queues[ticket.queue.id] = ticket.queue;
                    }
                });
            }
            let resultText = 'Available queues (extracted from tickets):\n\n';
            Object.values(queues).forEach((queue) => {
                resultText += `ID ${queue.id}: ${queue.title}\n`;
            });
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
    }
    async getUsers(args) {
        const params = {};
        if (args.page)
            params.page = args.page;
        try {
            const data = await this.makeRequest('GET', 'users/', params);
            let resultText = 'Available users for assignment:\n\n';
            const users = data.results || data;
            if (Array.isArray(users)) {
                users.forEach((user) => {
                    resultText += `ID ${user.id}: ${user.username || 'Unknown'}\n`;
                    if (user.first_name || user.last_name) {
                        const name = `${user.first_name || ''} ${user.last_name || ''}`.trim();
                        resultText += `  Name: ${name}\n`;
                    }
                    if (user.email) {
                        resultText += `  Email: ${user.email}\n`;
                    }
                    resultText += '\n';
                });
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            let resultText = `Could not retrieve users list: ${errorMessage}\n`;
            resultText += 'Note: User assignment may require extracting user IDs from existing ticket assignments.';
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
    }
    async getAgentSessionInfo(args) {
        try {
            const data = await this.makeRequest('GET', 'agent-session-info/');
            let resultText = 'Agent Session Information:\n\n';
            resultText += `User ID: ${data.user_id || 'N/A'}\n`;
            resultText += `Username: ${data.username || 'N/A'}\n`;
            resultText += `Is Agent: ${data.is_agent || 'N/A'}\n`;
            resultText += `Branch Name: ${data.branch_name || 'Not set'}\n`;
            const intent = data.intent;
            resultText += `Intent: ${intent === null || intent === undefined ? 'Not set' : intent}\n`;
            resultText += `Session Key: ${data.session_key || 'N/A'}\n`;
            resultText += `Authentication: ${data.authentication_method || 'N/A'}\n`;
            if (data.branch_name) {
                resultText += `\nBranch Usage Examples:\n`;
                resultText += `  Database context: Working in branch '${data.branch_name}'\n`;
                resultText += `  Isolation: Changes are isolated to this branch\n`;
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return {
                content: [
                    {
                        type: 'text',
                        text: `Error getting session info: ${errorMessage}`,
                    },
                ],
            };
        }
    }
    async setAgentIntent(args) {
        const { intent } = args;
        if (intent.length > 512) {
            return {
                content: [
                    {
                        type: 'text',
                        text: 'Error: Intent must be 512 characters or less',
                    },
                ],
            };
        }
        try {
            const data = await this.makeRequest('POST', 'set-agent-intent/', undefined, { intent });
            let resultText = 'Agent Intent Set Successfully\n\n';
            resultText += `Intent: ${data.intent || 'Unknown'}\n`;
            resultText += `User: ${data.username || 'Unknown'}\n`;
            resultText += `Branch: ${data.branch_name || 'Unknown'}\n`;
            resultText += `Session: ${data.session_key || 'Unknown'}\n`;
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return {
                content: [
                    {
                        type: 'text',
                        text: `Error setting intent: ${errorMessage}`,
                    },
                ],
            };
        }
    }
    async finishAgentSession(args) {
        try {
            const data = await this.makeRequest('POST', 'finish-agent-session/');
            let resultText = 'Agent Session Finished Successfully\n\n';
            resultText += `User: ${data.username || 'Unknown'}\n`;
            resultText += `Branch: ${data.branch_name || 'Unknown'}\n`;
            resultText += `Intent: ${data.intent || 'Not set'}\n`;
            resultText += `Session: ${data.session_key || 'Unknown'}\n`;
            resultText += `\nSession cleanup completed and user logged out.\n`;
            resultText += `You will need to re-authenticate for further API calls.\n`;
            // Mark as no longer authenticated since the session was finished
            this.authenticated = false;
            this.sessionInfo = null;
            return {
                content: [
                    {
                        type: 'text',
                        text: resultText,
                    },
                ],
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return {
                content: [
                    {
                        type: 'text',
                        text: `Error finishing session: ${errorMessage}`,
                    },
                ],
            };
        }
    }
    cleanup() {
        if (this.logStream) {
            this.logStream.end();
        }
    }
    async run() {
        this.log('🚀 Starting Django Helpdesk MCP Server (TypeScript)...');
        this.log('📡 Server version: 0.1.0');
        this.log(`🔗 Django Helpdesk URL: ${this.config.baseUrl}`);
        if (this.logStream) {
            this.log(`📝 Logging to file enabled`);
        }
        else {
            this.log(`📝 Logging to stderr`);
        }
        this.log('⚡ Server ready - waiting for client connections...');
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        this.log('🔌 Client connected to MCP server');
    }
}
// Parse command line arguments
function parseArgs() {
    const args = process.argv.slice(2);
    const result = {};
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--log-file' && i + 1 < args.length) {
            result.logFile = args[i + 1];
            i++; // Skip the next argument since it's the log file path
        }
    }
    return result;
}
// Main entry point
async function main() {
    const { logFile } = parseArgs();
    const server = new HelpdeskMCPServer(logFile);
    process.on('SIGINT', () => {
        console.error('\n🛑 Server shutdown requested');
        server.cleanup();
        process.exit(0);
    });
    process.on('SIGTERM', () => {
        console.error('\n🛑 Server shutdown requested');
        server.cleanup();
        process.exit(0);
    });
    try {
        await server.run();
    }
    catch (error) {
        console.error('💥 Server error:', error);
        server.cleanup();
        process.exit(1);
    }
}
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch((error) => {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    });
}
//# sourceMappingURL=index.js.map