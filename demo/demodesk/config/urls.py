"""django-helpdesk demodesk URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token


# The following uses the static() helper function,
# which only works when in development mode (using DEBUG).
# For a real deployment, you'd have to properly configure a media server.
# For more information, see:
# https://docs.djangoproject.com/en/1.10/howto/static-files/

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("helpdesk.urls", namespace="helpdesk")),
    path("api/auth/", include("rest_framework.urls", namespace="rest_framework")),
    path("api-token-auth/", obtain_auth_token, name="api_token_auth"),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
