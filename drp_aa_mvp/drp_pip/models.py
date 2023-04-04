from django.db import models
import data_rights_request.models as drr


class MessageValidationException(Exception):
    pass

# TKTKTK I should really be thinking hard about just using the one in
# the OSIRAA side... not sue how that would effect an "internal" end
# to end test tho right now so just duplicating.
class DataRightsRequest(drr.DataRightsRequest):
    pass
class DataRightsStatus(drr.DataRightsStatus):
    pass


class AuthorizedAgent(models.Model):
    name                  = models.CharField(max_length=63, blank=True, default='')
    brand_name            = models.CharField(max_length=63, blank=True, default='')
    aa_id                 = models.CharField(max_length=63, blank=True, default='')
    logo                  = models.ImageField('Logo Image', upload_to='company-logos', blank=True)
    logo_thumbnail        = models.ImageField(upload_to='company-logos/thumbnails', blank=True)
    subtitle_description  = models.TextField(blank=True)

    verify_key            = models.TextField('Hex encoded key to verify signed requests')
    bearer_token          = models.TextField('pair-wise token between AA and CB', blank=True)

    def __str__(self):
        return self.name

    @classmethod
    def fetch_by_id(cls, aa_id: str):
        return cls.objects.get(aa_id=aa_id)

    @classmethod
    def fetch_by_bearer_token(cls, token: str):
        return cls.objects.get(bearer_token=token)
