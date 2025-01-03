"""
Django settings for drp_aa_mvp project.

Generated by 'django-admin startproject' using Django 3.2.12.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


DEV = 'dev'
STAGING = 'staging'
PRODUCTION = 'production'
TESTING = 'test'
ENV = os.environ.get('DJANGO_ENV', DEV)


def get(variable, default=''):
    """
    To be used over os.environ.get() to avoid deploying local/dev keys in production. Forced
    env vars to be present.
    """
    if ENV == PRODUCTION and variable not in os.environ:
        raise Exception('Required environment variable not set: {}'.format(variable))

    return os.environ.get(variable, default)


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-%k6u+v8prz33iu179r=u^x=nqgf3eaged+x5h93rs(kob^t6u)'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False #True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'drp-authorized-agent.herokuapp.com', '44.209.94.186', 'osiraa.datarightsprotocol.org']

# Application definition
INSTALLED_APPS = [
    'user_identity.apps.UserIdentityConfig',
    'covered_business.apps.CoveredBusinessConfig',
    'data_rights_request.apps.DataRightsRequestConfig',
    'reporting.apps.ReportingConfig',
    'agent_keys.apps.AgentKeysConfig',
    'drp_pip.apps.DrpPipConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'drp_aa_mvp.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'drp_aa_mvp.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

if ENV in [STAGING, PRODUCTION]:
    import dj_database_url
    DATABASES = {
        'default': dj_database_url.config(conn_max_age=500, ssl_require=False),
    }
else:
    # for local use only ...
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'NAME': os.environ.get('POSTGRES_NAME') or 'authorizedagent',
            'USER': os.environ.get('POSTGRES_USER') or 'postgres',
            'PASSWORD': os.environ.get('POSTGRES_PASSWORD') or 'rootz',
            'HOST': os.environ.get('POSTGRES_HOST') or 'localhost',
            'PORT': os.environ.get('POSTGRES_PORT') or '5432'
        },
    }


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    { 'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator' },
    { 'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator' },
    { 'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator' },
    { 'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator' },
]


# Authorized Agent ID and Name, should match entries in service directory
AUTHORIZED_AGENT_ID = get('AUTHORIZED_AGENT_ID', 'CR_AA_DRP_ID_001_LOCAL')
AUTHORIZED_AGENT_NAME = get('AUTHORIZED_AGENT_NAME', 'OSIRAA Local Test Instance')
WEB_URL = get('WEB_URL', 'http://127.0.0.1:8003')

# Authorized Agent Signing Key (64-bit encoded).  Must remain secret.
AGENT_SIGNING_KEY_B64 = get('AGENT_SIGNING_KEY_B64', '098LMB1ayJW1N45oQ4J22ddU96gXr3/x5hEmKnPFpP0=')

# Authorized Agent Verify Key (64-bit encoded)
# This is the public verify key for use in sending DRP requests to CB and PIP partners. 
# It must match the key decalared in the Service Directory, or else partners' attempt 
# to validate DRP messages they receive will fail
AGENT_VERIFY_KEY_B64 = get('AGENT_VERIFY_KEY_B64', 'jkX15E7+NA/0E7K5YAp7+GndMP6/Fa0dJJYyr1GJPoQ=')

SERVICE_DIRECTORY_AGENT_URL = 'https://discovery.datarightsprotocol.org/agents.json'
SERVICE_DIRECTORY_BUSINESS_URL = 'https://discovery.datarightsprotocol.org/businesses.json'

# CB ID and Name for OSIRPIP 
OSIRAA_PIP_CB_ID = get('OSIRAA_PIP_CB_ID', "osirpip-cb-local-01") 
OSIRAA_PIP_CB_NAME = get('OSIRAA_PIP_CB_NAME', 'OSIRPIP Local Test Instance')

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/
"""
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'

# Extra places for collectstatic to find static files.
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)
"""

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
