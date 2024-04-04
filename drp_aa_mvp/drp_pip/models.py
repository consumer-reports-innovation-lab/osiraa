from django.db import models
import data_rights_request.models as drr

import json
import logging
import requests


class MessageValidationException(Exception):
    pass

class DataRightsRequest(drr.DataRightsRequest):
    aa_id                 = models.CharField(max_length=63, blank=True, default='')

class DataRightsStatus(drr.DataRightsStatus):
    aa_id                 = models.CharField(max_length=63, blank=True, default='')

class AuthorizedAgent(models.Model):
    name                  = models.CharField(max_length=63, blank=True, default='')
    brand_name            = models.CharField(max_length=63, blank=True, default='')
    aa_id                 = models.CharField(max_length=63, blank=True, default='')
    logo                  = models.ImageField('Logo Image', upload_to='company-logos', blank=True)
    logo_thumbnail        = models.ImageField(upload_to='company-logos/thumbnails', blank=True)
    subtitle_description  = models.TextField(blank=True)
    verify_key            = models.TextField('Base64 encoded key to verify signed requests')
    bearer_token          = models.TextField('pair-wise token between AA and CB', blank=True)

    def __str__(self):
        return self.name

    @classmethod
    def fetch_by_id(cls, aa_id: str):
        return cls.objects.get(aa_id=aa_id)

    @classmethod
    def fetch_by_bearer_token(cls, token: str):
        return cls.objects.get(bearer_token=token)

    @classmethod
    def refresh_from_directory(cls, directory_url):
        response = requests.get(directory_url)

        try:
            response_json = json.loads(response.text)
        except ValueError as e:
            logging.warn('**  WARNING - refresh_service_directory_data(): NOT valid json  **')
            return False 

        # loop thru entries and update the CB's in the DB
        for item in response_json:
            agent_id = str(item['id'])  # this field corresponds to cb_id in the CovereredBusiness model

            aa_id = item["id"]
            name = item["name"]
            logo = item.get("logo")
            verify_key = item["verify_key"]

            try:
                agent_model = cls.fetch_by_id(agent_id)
            except cls.DoesNotExist as e:
                agent_model = None

            if agent_model is not None:
                agent_model.aa_id = aa_id
                agent_model.name = name
                agent_model.logo = logo
                agent_model.verify_key = verify_key
                agent_model.save()
            else:
                new_agent = cls.objects.create(
                    aa_id = aa_id,
                    name = name,
                    logo = logo,
                    verify_key = verify_key,
                )
