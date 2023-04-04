from django.contrib import admin
from .models import AuthorizedAgent, DataRightsRequest, DataRightsStatus

# Register your models here.
admin.site.register(AuthorizedAgent)
admin.site.register(DataRightsRequest)
admin.site.register(DataRightsStatus)
