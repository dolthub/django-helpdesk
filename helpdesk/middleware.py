"""
Django middleware for logging HTTP requests and responses.
"""

import json
import logging
import time
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.http import StreamingHttpResponse, FileResponse


logger = logging.getLogger('helpdesk.requests')


class RequestResponseLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log HTTP requests and responses for django-helpdesk.
    
    Logs:
    - Request method, path, user, IP address
    - Request headers and body (for API endpoints)
    - Response status code and headers
    - Response body (for API endpoints, excluding large files)
    - Request processing time
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        
        # Configure which paths to log
        self.log_paths = getattr(settings, 'HELPDESK_LOG_PATHS', [
            '/api/',
            '/helpdesk/',
        ])
        
        # Configure sensitive headers to exclude from logging
        self.sensitive_headers = getattr(settings, 'HELPDESK_LOG_SENSITIVE_HEADERS', [
            'authorization',
            'cookie',
            'x-api-key',
            'x-auth-token',
        ])
        
        # Max body size to log (in bytes)
        self.max_body_size = getattr(settings, 'HELPDESK_LOG_MAX_BODY_SIZE', 10000)
        
        # Whether to log request/response bodies
        self.log_bodies = getattr(settings, 'HELPDESK_LOG_BODIES', True)

    def process_request(self, request):
        """Process the request before it reaches the view."""
        if not self._should_log_request(request):
            return None
            
        # Store request start time
        request._logging_start_time = time.time()
        
        # Log request details
        self._log_request(request)
        
        return None

    def process_response(self, request, response):
        """Process the response before it's returned to the client."""
        if not self._should_log_request(request):
            return response
            
        # Log response details
        self._log_response(request, response)
        
        return response

    def _should_log_request(self, request):
        """Determine if this request should be logged."""
        path = request.path
        return any(path.startswith(log_path) for log_path in self.log_paths)

    def _log_request(self, request):
        """Log request details."""
        try:
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Get user info
            user_info = self._get_user_info(request)
            
            # Get headers (excluding sensitive ones)
            headers = self._filter_headers(dict(request.headers))

            # Get request body for POST/PUT/PATCH requests
            body = None
            if self.log_bodies and request.method in ['POST', 'PUT', 'PATCH']:
                body = self._get_request_body(request)

            print(self.log_bodies)
            print(body)
            
            log_data = {
                'type': 'request',
                'method': request.method,
                'path': request.path,
                'query_params': dict(request.GET),
                'user': user_info,
                'client_ip': client_ip,
                'headers': headers,
                'content_type': request.content_type,
                'content_length': request.META.get('CONTENT_LENGTH'),
            }
            
            if body is not None:
                log_data['body'] = body

            print(log_data)
                
            logger.info(f"Request: {request.method} {request.path}", extra=log_data)
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")

    def _log_response(self, request, response):
        """Log response details."""
        try:
            # Calculate request processing time
            processing_time = None
            if hasattr(request, '_logging_start_time'):
                processing_time = round((time.time() - request._logging_start_time) * 1000, 2)
            
            # Get response headers (excluding sensitive ones)
            headers = self._filter_headers(dict(response.items()))
            
            # Get response body for API endpoints
            body = None
            if self.log_bodies and self._is_api_endpoint(request):
                body = self._get_response_body(response)
            
            log_data = {
                'type': 'response',
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'headers': headers,
                'content_type': response.get('Content-Type'),
                'content_length': response.get('Content-Length'),
                'processing_time_ms': processing_time,
            }
            
            if body is not None:
                log_data['body'] = body

            # Log with appropriate level based on status code
            #if response.status_code >= 500:
            #    logger.error(f"Response: {response.status_code} for {request.method} {request.path}", extra=log_data)
            #elif response.status_code >= 400:
            #    logger.warning(f"Response: {response.status_code} for {request.method} {request.path}", extra=log_data)
            #else:
            #    logger.info(f"Response: {response.status_code} for {request.method} {request.path}", extra=log_data)
                
        except Exception as e:
            logger.error(f"Error logging response: {e}")

    def _get_client_ip(self, request):
        """Get the client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _get_user_info(self, request):
        """Get user information from the request."""
        if hasattr(request, 'user') and request.user.is_authenticated:
            return {
                'id': request.user.id,
                'username': request.user.username,
                'email': getattr(request.user, 'email', ''),
                'is_staff': request.user.is_staff,
                'is_superuser': request.user.is_superuser,
            }
        return None

    def _filter_headers(self, headers):
        """Filter out sensitive headers from logging."""
        filtered = {}
        for key, value in headers.items():
            if key.lower() in self.sensitive_headers:
                filtered[key] = '[FILTERED]'
            else:
                filtered[key] = value
        return filtered

    def _get_request_body(self, request):
        """Get the request body for logging."""
        try:
            if hasattr(request, '_body') and request._body:
                body = request._body.decode('utf-8')
                
                # Limit body size for logging
                if len(body) > self.max_body_size:
                    body = body[:self.max_body_size] + '... [TRUNCATED]'
                
                # Try to parse as JSON for better logging
                if request.content_type == 'application/json':
                    try:
                        return json.loads(body)
                    except json.JSONDecodeError:
                        pass
                        
                return body
        except Exception:
            pass
        return None

    def _get_response_body(self, response):
        """Get the response body for logging."""
        try:
            # Skip logging for file responses and streaming responses
            if isinstance(response, (StreamingHttpResponse, FileResponse)):
                return '[STREAMING_RESPONSE]'
            
            # Only log JSON responses and small text responses
            content_type = response.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    content = response.content.decode('utf-8')
                    if len(content) <= self.max_body_size:
                        return json.loads(content)
                    else:
                        return '[RESPONSE_TOO_LARGE]'
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return '[INVALID_JSON]'
            elif 'text/' in content_type:
                try:
                    content = response.content.decode('utf-8')
                    if len(content) <= self.max_body_size:
                        return content
                    else:
                        return '[RESPONSE_TOO_LARGE]'
                except UnicodeDecodeError:
                    return '[BINARY_CONTENT]'
            else:
                return '[NON_TEXT_CONTENT]'
                
        except Exception:
            return '[LOGGING_ERROR]'

    def _is_api_endpoint(self, request):
        """Check if this is an API endpoint."""
        return request.path.startswith('/api/')