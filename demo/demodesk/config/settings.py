"""
Django settings for django-helpdesk demodesk project.

"""

import os


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "_crkn1+fnzu5$vns_-d+^ayiq%z4k*s!!ag0!mfy36(y!vrazd"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False, # Keep Django's default loggers
    'formatters': {
        'standard': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s\n'
                     'Method: %(method)s | Path: %(path)s | User: %(user)s | IP: %(client_ip)s\n'
                     # 'Status: %(status_code)s | Time: %(processing_time_ms)s ms\n'
                     'Headers: %(headers)s\n'
                     #'Body: %(body)s\n'
                     '---'
        },
        'json': {
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
        'request_console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'detailed',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/helpdesk_requests.log',
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'detailed',
        },
    },
    'loggers': {
        'django.server': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'helpdesk.requests': {
            'handlers': ['request_console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'helpdesk': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'helpdesk.api': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']

# SECURITY WARNING: you probably want to configure your server
# to use HTTPS with secure cookies, then you'd want to set
# the following settings:
#
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
#
# We leave them commented out here because most likely for
# an internal demo you don't need such security, but please
# remember when setting up your own development / production server!

# Default teams mode to enabled unless overridden by an environment variable set to "false"
HELPDESK_TEAMS_MODE_ENABLED = (
    os.getenv("HELPDESK_TEAMS_MODE_ENABLED", "true").lower() == "true"
)

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "django.contrib.humanize",
    "bootstrap4form",
    "helpdesk",  # This is us!
    "rest_framework",  # required for the API
    # "rest_framework.authtoken"  # Disabled token authentication
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        # 'rest_framework.authentication.TokenAuthentication',  # Disabled
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

if HELPDESK_TEAMS_MODE_ENABLED:
    INSTALLED_APPS.extend(
        [
            "account",  # Required by pinax-teams
            "pinax.invitations",  # required by pinax-teams
            "pinax.teams",  # team support
            "reversion",  # required by pinax-teams
        ]
    )

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "helpdesk.middleware.AgentBranchNameMiddleware",  # Agent branch name creation
    "helpdesk.middleware.AgentSessionTimeoutMiddleware",  # Agent session timeout detection
    "helpdesk.middleware.AgentAccessControlMiddleware",  # Agent access control
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "helpdesk.middleware.RequestResponseLoggingMiddleware",  # Request/Response logging
]

ROOT_URLCONF = "demodesk.config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": True,
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "demodesk.config.wsgi.application"


# django-helpdesk configuration settings
# You can override django-helpdesk's defaults by redefining them here.
# To see what settings are available, see the docs/configuration.rst
# file for more information.
# Some common settings are below.

HELPDESK_DEFAULT_SETTINGS = {
    "use_email_as_submitter": True,
    "email_on_ticket_assign": True,
    "email_on_ticket_change": True,
    "login_view_ticketlist": True,
    "email_on_ticket_apichange": True,
    "preset_replies": True,
    "tickets_per_page": 25,
}

# Should the public web portal be enabled?
HELPDESK_PUBLIC_ENABLED = True
HELPDESK_VIEW_A_TICKET_PUBLIC = True
HELPDESK_SUBMIT_A_TICKET_PUBLIC = True

# Should the Knowledgebase be enabled?
HELPDESK_KB_ENABLED = True

HELPDESK_TICKETS_TIMELINE_ENABLED = True

# Allow users to change their passwords
HELPDESK_SHOW_CHANGE_PASSWORD = True

# Instead of showing the public web portal first,
# we can instead redirect users straight to the login page.
HELPDESK_REDIRECT_TO_LOGIN_BY_DEFAULT = False
LOGIN_URL = "helpdesk:login"
LOGIN_REDIRECT_URL = "helpdesk:home"
# You can also redirect to a specific page after logging out (instead of logout page)
# LOGOUT_REDIRECT_URL = 'helpdesk:home'

# Database
# - by default, we use SQLite3 for the demo, but you can also
#   configure MySQL or PostgreSQL, see the docs for more:
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    "default": {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'helpdesk',
        'USER': 'helpdesk',
        'PASSWORD': 'HelpDesk-pAsS',
        'HOST': '127.0.0.1',   # Or an IP Address that your DB is hosted on
        'PORT': '3306',
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

# Sites
# - this allows hosting of more than one site from a single server,
#   in practice you can probably just leave this default if you only
#   host a single site, but read more in the docs:
# https://docs.djangoproject.com/en/1.11/ref/contrib/sites/

SITE_ID = 1


# Sessions
# https://docs.djangoproject.com/en/1.11/topics/http/sessions

SESSION_COOKIE_AGE = 86400  # = 1 day
SESSION_SAVE_EVERY_REQUEST = True  # Ensure sessions are saved for API requests

# For better default security, set these cookie flags, but
# these are likely to cause problems when testing locally
# CSRF_COOKIE_SECURE = True
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_HTTPONLY = True
# SESSION_COOKIE_HTTPONLY = True


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'helpdesk.authentication.HelpdeskAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
]

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Email
# https://docs.djangoproject.com/en/1.11/topics/email/

# This demo uses the console backend, which simply prints emails to the console
# rather than actually sending them out.
DEFAULT_FROM_EMAIL = "helpdesk@example.com"
SERVER_EMAIL = "helpdesk@example.com"
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# If you want to test sending real emails, uncomment and modify the following:
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST = 'smtp.example.com'
# EMAIL_PORT = '25'

# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

# By default, django-helpdesk uses en, but other languages are also available.
# The most complete translations are: es-MX, ru, zh-Hans
# Contribute to our translations via Transifex if you can!
# See CONTRIBUTING.rst for more info.
LANGUAGE_CODE = "en-US"

TIME_ZONE = "UTC"

USE_I18N = True


USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = "/static/"
# static root needs to be defined in order to use collectstatic
STATIC_ROOT = os.path.join(BASE_DIR, "static")

# MEDIA_ROOT is where media uploads are stored.
# We set this to a directory to host file attachments created
# with tickets.
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Fixtures
# https://docs.djangoproject.com/en/1.11/ref/settings/#std:setting-FIXTURE_DIRS
# - This is only necessary to make the demo project work, not needed for
# your own projects unless you make your own fixtures
FIXTURE_DIRS = [os.path.join(BASE_DIR, "fixtures")]


# for Django 3.2+, set default for autofields:
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Disable teams mode for simpler permissions
HELPDESK_TEAMS_MODE_ENABLED = False

# Request/Response Logging Middleware Configuration
HELPDESK_LOG_PATHS = [
    '/api/',
    '/helpdesk/',
]

HELPDESK_LOG_SENSITIVE_HEADERS = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
]

HELPDESK_LOG_MAX_BODY_SIZE = 10000  # 10KB
HELPDESK_LOG_BODIES = True

# CSRF settings for API access
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_USE_SESSIONS = False     # Use cookie-based CSRF tokens
CSRF_COOKIE_SAMESITE = 'Lax'  # Allow cross-site requests with CSRF token

# Session settings for API access  
SESSION_COOKIE_HTTPONLY = False  # Allow API clients to access session
SESSION_COOKIE_SAMESITE = 'Lax'  # Allow cross-site requests with session

# Agent Access Control Configuration
HELPDESK_AGENT_ALLOWED_PATHS = [
    '/api/',
]

try:
    from .local_settings import *  # noqa
except ImportError:
    pass
