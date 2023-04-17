from typing import Dict, List
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

import json

from covered_business.models import CoveredBusiness
from drp_pip.models import AuthorizedAgent

def index(request):
    context = dict(
        cbs=cbs_list(CoveredBusiness.objects.all()),
        aas=aas_list(AuthorizedAgent.objects.all()),
    )
    context["json_cbs"] = json.dumps(context["cbs"], indent=2)
    context["json_aas"] = json.dumps(context["aas"], indent=2)
    return render(request, 'service_directories/index.html', context)


def cbs_list(cb_list: List[CoveredBusiness]):
    def cb_to_dict(cb: CoveredBusiness) -> Dict:
        return dict(
            id=cb.cb_id,
            name=cb.brand_name,
            logo=cb.logo.url if cb.logo else None,
            api_base=cb.api_root_endpoint,
            supported_actions=cb.supported_actions,
            web_url="https://example.com/fixme",
            technical_contact="privacy-eng@example.com",
            business_contact="privacy-legal@example.com",
        )
    return [ cb_to_dict(cb) for cb in cb_list ]


def aas_list(aa_list: List[AuthorizedAgent]):
    def aa_to_dict(aa: AuthorizedAgent) -> Dict:
        return dict(
            id=aa.aa_id,
            name=aa.brand_name,
            logo=aa.logo.url if aa.logo else None,
            verify_key=aa.verify_key,
            web_url="https://example.com/fixme",
            identity_assurance_url="https://example.com/fixme",
            technical_contact="drp-tech@example.com",
            business_contact="drp@example.com",
        )
    return [ aa_to_dict(aa) for aa in aa_list ]
    

@csrf_exempt
def business_directory(request):
    return JsonResponse(
        cbs_list(CoveredBusiness.objects.all()),
        # TypeError: In order to allow non-dict objects to be serialized set the safe parameter to False.
        safe=False
    )


@csrf_exempt
def agent_directory(request):
    return JsonResponse(
        aas_list(AuthorizedAgent.objects.all()),
        # TypeError: In order to allow non-dict objects to be serialized set the safe parameter to False.
        safe=False
    )
