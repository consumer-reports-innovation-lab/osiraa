from datetime import datetime
from django.shortcuts import render
from django.http import HttpResponse

import json
import validators

from data_rights_request.models import ACTION_CHOICES, STATUS_CHOICES

def index(request):
    context = {}

    return render(request, 'reporting/index.html', context)


#-------------------------------------------------------------------------------------------------#
# test_discovery_endpoint

def test_is_discovery_endpoint_valid_url(request_url, response):
    return response.status_code == 200

def test_is_discovery_endpoint_compliant_url(request_url):
    return '/.well-known/data-rights.json' in request_url

def test_is_valid_json(response):
    try:
        json.loads(response.text)
    except ValueError as e:
        return False    
    return (response.text[0:1] == '{' or response.text[0:1] == '[')

def test_contains_version_field(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'version' in response_json and response_json['version'] == '0.6'  

def test_contians_api_base(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'api_base' in response_json and response_json['api_base'][0:8] == 'https://'

def test_is_valid_api_base(response):
    # todo: can only test for this by calling /excercise and /status ...
    return 'Unknown'

def test_enumerates_supported_actions(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'actions' in response_json and type(response_json['actions']) == list and len(response_json['actions']) > 0

def test_supported_actions_valid(response):
    known_action_values = ['sale:opt-out', 'sale:opt-in', 'access', 'deletion', 'access:categories ', 'access:specific ']
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    if 'actions' in response_json and type(response_json['actions'] == list):
        actions = response_json['actions']
        for action in actions:
            if action not in known_action_values :
                return False
        return True
    return False

def test_supported_actions_implemented(response):
    # todo: can only test for this by calling /excercise for each supported action ...
    return 'Unknown'

def test_conatins_relationships(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'user_relationships' in response_json and type(response_json['user_relationships']) == list and len(response_json['user_relationships']) > 0

def test_discovery_contains_no_unknown_fields(response):
    known_fields = ['version', 'api_base', 'actions', 'user_relationships']
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    for field in response_json:
        if field not in known_fields:
            return False
    return True

def test_discovery_endpoint(request_url, response):
    test_results = []

    """
    1.  GET .well-known/data-rights.json
        - Covered Business's domain SHOULD have a /.well-known/data-rights.json
        - Discovery Endpoint MUST be valid JSON
        - Discovery Endpoint MUST contain a version field (currently 0.6)
        - Discovery Endpoint MUST provide an API base
            - API base MUST be valid for subsequent calls
        - Discovery Endpoint MUST provide a list of supported actions
            - supported actions MUST be valid (on list)
            - supported actions MUST be implemented by /excerise endpoint
        - Discovery Endpoint MAY contain a user_relationships hint set
        - Discovery Endpoint SHOULD NOT contain additional undefined fields
    """

    # test Covered Business's domain SHOULD have a discovery endpoint
    is_valid_endpoint = test_is_discovery_endpoint_valid_url(request_url, response)
    test_results.append({'name': 'Is valid enpoint', 'result': is_valid_endpoint})

    # test Covered Business's domain a discovery endpoint SHOULD be /.well-known/data-rights.json
    is_compliant_endpoint = test_is_discovery_endpoint_compliant_url(request_url)
    test_results.append({'name': 'Is compliant enpoint', 'result': is_compliant_endpoint})

    # test Discovery Endpoint MUST be valid JSON
    is_valid_json = test_is_valid_json(response)
    test_results.append({'name': 'Is valid json', 'result': is_valid_json})

    # test Discovery Endpoint MUST contain a version field (currently 0.6)
    contains_version_field = test_contains_version_field(response)
    test_results.append({'name': 'Contains version field', 'result': contains_version_field})

    # test Discovery Endpoint MUST provide an API base
    contians_api_base = test_contians_api_base(response)
    test_results.append({'name': 'Contains API Base', 'result': contians_api_base})

    # test API base MUST be valid for subsequent calls
    is_valid_api_base = test_is_valid_api_base(response)
    test_results.append({'name': 'Is valid API Base', 'result': is_valid_api_base})

    # test Discovery Endpoint MUST provide a list of supported actions
    enumerates_supported_actions = test_enumerates_supported_actions(response)
    test_results.append({'name': 'Enumerates supported actions', 'result': enumerates_supported_actions})

    # test supported actions MUST be valid (on list)
    supported_actions_valid = test_supported_actions_valid(response)
    test_results.append({'name': 'Supported actions are valid', 'result': supported_actions_valid})

    # test supported actions MUST be supported by /excerise endpoint
    supported_actions_implemented = test_supported_actions_implemented(response)
    test_results.append({'name': 'Supported actions are implemented', 'result': supported_actions_implemented})

    # test Discovery Endpoint MAY contain a user_relationships hint set
    contains_relationships = test_conatins_relationships(response)
    test_results.append({'name': 'Contains user relationships', 'result': contains_relationships})

    # test Discovery Endpoint SHOULD NOT contain additional undefined fields
    contains_no_unknown_fields = test_discovery_contains_no_unknown_fields(response)
    test_results.append({'name': 'Contains no unknown fields', 'result': contains_no_unknown_fields})

    return test_results


#-------------------------------------------------------------------------------------------------#
# test_excercise_endpoint

def test_is_data_rights_status_obj(response):
    required_fields = ['request_id', 'received_at', 'status']
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    # todo: for now we just check for requried fields; is there a better way, maybe by using types ... ?    
    for field in required_fields:
        if field not in response_json:
            return False
    return True

def test_contains_request_id(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'request_id' in response_json and response_json['request_id'] != '' 

def test_is_request_id_unique_string(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    # todo: test by comparing to other id's for this CR in the DB ...      
    return "Unknown"

def test_contains_received_at(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'received_at' in response_json and response_json['received_at'] != '' 

def test_is_received_at_time_format(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    try:
        datetime.fromisoformat(response_json['received_at'])
    except:
        return False
    return True

def test_contains_status_field(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'status' in response_json and response_json['status'] != '' 

def test_is_status_valid(response):
    known_status_values = [ 'in_progress', 'open', 'fulfilled', 'revoked', 'denied', 'expired' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'status' in response_json and response_json['status'] in known_status_values

def test_contains_reason_field(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'reason' in response_json and response_json['reason'] != '' 

def test_is_reason_valid(response):
    known_reason_values = [ 'need_verification', 'suspected_fraud', 'insufficient_verification', 'no_match', 'claim_not_covered', 'too_many_requests', 'outside_jurisdiction', 'other', '“none' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    return 'reason' in response_json and response_json['reason'] in known_reason_values

def test_has_expected_by_iso_time_format(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    try:
        datetime.fromisoformat(response_json['expected_by'])
    except:
        return False
    return True

def test_has_user_verification_url_valid_format(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    if 'user_verification_url' not in response_json or response_json['user_verification_url'] == None:
        return 'N/A'   
    return validators.url(response_json['user_verification_url'])

def test_excercise_contains_no_unknown_fields(response):
    known_fields = ['request_id', 'received_at', 'expected_by', 'status', 'reason', 'processing_details', 'user_verification_url']
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    for field in response_json:
        if field not in known_fields:
            return False
    return True

def test_is_reponse_valid_for_access_ccpa(response):
    valid_status_values = [ 'in_progress', 'open' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    return False 

def test_is_reponse_valid_for_access_voluntary(response):
    valid_status_values = [ 'in_progress', 'open', 'denied' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    if is_valid_status and response_json['status'] == 'denied':
        return 'reason' in response_json and response_json['reason'] == 'outside_jurisdiction'
    return False

def test_is_reponse_valid_for_deletion_ccpa(response):
    valid_status_values = [ 'in_progress', 'open' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    return False 

def test_is_reponse_valid_for_deletion_voluntary(response):
    valid_status_values = [ 'in_progress', 'open', 'denied' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    if is_valid_status and response_json['status'] == 'denied':
        return 'reason' in response_json and response_json['reason'] == 'outside_jurisdiction'
    return False  

def test_is_reponse_valid_for_optout_ccpa(response):
    valid_status_values = [ 'in_progress', 'open' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    return False   

def test_is_reponse_valid_for_optout_voluntary(response):
    valid_status_values = [ 'in_progress', 'open', 'denied' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    if is_valid_status and response_json['status'] == 'denied':
        return 'reason' in response_json and response_json['reason'] == 'outside_jurisdiction'
    return False  

def test_is_reponse_valid_for_optin_ccpa(response):
    valid_status_values = [ 'in_progress', 'open' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    return False    

def test_is_reponse_valid_for_optin_voluntary(response):
    valid_status_values = [ 'in_progress', 'open', 'denied' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    is_valid_status = 'status' in response_json and response_json['status'] in valid_status_values
    if is_valid_status and response_json['status'] == 'open':
        return 'reason' in response_json and response_json['reason'] == None
    if is_valid_status and response_json['status'] == '“in_progress”':
        return 'reason' in response_json and (response_json['reason'] == 'need_verification' or response_json['reason'] == None)
    if is_valid_status and response_json['status'] == 'denied':
        return 'reason' in response_json and response_json['reason'] == 'outside_jurisdiction'
    return False 

def test_excercise_endpoint(request_json, response):
    test_results = []

    """
    2   POST /exercise
        - action: [ access | deletion | sale:opt_out | sale:opt_in | access:categories | access:specific ]
        - regime: [ ccpa | voluntary ]
        - all calls MUST return a Data Rights Status object for all actions listed in .well-known/data-rights.json
        - values of fields may vary, see below

        - returns a Data Rights Status object
        - Data Rights Status object MUST contain field “request_id”
            - String which is unique within the scope of the AA:CB relationship
        - Data Rights Status object MUST contain field “received_at”
            - “received_at” is an ISO 8601 string (ISO time format)
        - Data Rights Status object MUST contain “status” field
            - “status” allowable values: [ "in_progress" | "open" | "fulfilled" | "revoked" | "denied" | "expired" ]
            - allowable status varies with action; see below
        - Data Rights Status object MAY contain “reason” field
            - “reason” allowable values: "need_verification" | "suspected_fraud" | “insufficient_verification” | "no_match" | "claim_not_covered" | "too_many_requests" | "outside_jurisdiction" | "other" | “none”
            - allowable reason varies with status; see below
        - Data Rights Status object MAY contain “expected_by” field
            - “expected_by” is an ISO 8601 string (ISO time format)
        - Data Rights Status object MAY contain 'processing_details' field
            - TBD: any contstraint on this ... ?
        - Data Rights Status object MAY contain 'user_verification_url' field
            - “user_verification_url” is a valid url
        - Additional, optional or unknown  fields - no additional fields allowed

    2.1. POST /exercise, { action: “access”, regime: “ccpa” }
        - status: “open” | “in_progress”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”

    2.2. POST /exercise, { action: access, regime: voluntary }
        - status: “open” | “in_progress” | “denied”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”
        - if status == “denied”, reason SHOULD be “outside_jurisdiction”

    2.3. POST /exercise, { action: deletion, regime: ccpa }
        - status: “open” | “in_progress”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”

    2.4. POST /exercise, { action: deletion, regime: voluntary }
        - status: “open” | “in_progress” | “denied”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”
        - if status == “denied”, reason SHOULD be “outside_jurisdiction”

    2.5. POST /exercise, { action: sale:opt_out, regime: ccpa }
        - status: “open” | “in_progress”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”

    2.6. POST /exercise, { action: sale:opt_out, regime: voluntary }
        - status: “open” | “in_progress” | “denied”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”
        - if status == “denied”, reason SHOULD be “outside_jurisdiction”

    2.7. POST /exercise, { action: sale:opt_in, regime: ccpa }
        - status: “open” | “in_progress”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”

    2.8. POST /exercise, { action: sale:opt_in, regime: voluntary }
        - status: “open” | “in_progress” | “denied”
        - if status == “open”, reason SHOULD be “none”
        - if status == “in_progress”, reason SHOULD be “need_verification” | “none”
        - if status == “denied”, reason SHOULD be “outside_jurisdiction”
    """

    # test returns a Data Rights Status object
    is_data_rights_status_obj = test_is_data_rights_status_obj(response)
    test_results.append({'name': 'Returns a Data Rights Status object', 'result': is_data_rights_status_obj})

    # test Data Rights Status object MUST contain field “request_id”
    contains_request_id = test_contains_request_id(response)
    test_results.append({'name': 'Contains field request_id', 'result': contains_request_id})

    # test “request_id” is a string which is unique within the scope of the AA:CB relationship
    is_request_id_unique_string = test_is_request_id_unique_string(response)
    test_results.append({'name': 'reqest_id is a unique string', 'result': is_request_id_unique_string})

    # test Data Rights Status object MUST contain field “received_at”
    contains_received_at = test_contains_received_at(response)
    test_results.append({'name': 'Contains field received_at', 'result': contains_received_at})

    # test “received_at” is an ISO 8601 string (ISO time format)
    is_received_at_time_format = test_is_received_at_time_format(response)
    test_results.append({'name': 'Is received_at ISO time format', 'result': is_received_at_time_format})

    # test Data Rights Status object MUST contain “status” field
    contains_status_field = test_contains_status_field(response)
    test_results.append({'name': 'Contains status field', 'result': contains_status_field})

    # test “status” allowable values: [ "in_progress" | "open" | "fulfilled" | "revoked" | "denied" | "expired" ]
    is_status_valid = test_is_status_valid(response)
    test_results.append({'name': 'Is status valid', 'result': is_status_valid})

    # test Data Rights Status object MAY contain “reason” field
    contains_reason_field = test_contains_reason_field(response)
    test_results.append({'name': 'Contains reason field', 'result': contains_reason_field})

    # test “reason” allowable values: "need_verification" | "suspected_fraud" | “insufficient_verification” | "no_match" | "claim_not_covered" | "too_many_requests" | "outside_jurisdiction" | "other" | “none”
    is_reason_valid = test_is_reason_valid(response)
    test_results.append({'name': 'Is reason valid', 'result': is_reason_valid})

    # test Data Rights Status object MAY contain “expected_by” field; “expected_by” is an ISO 8601 string (ISO time format)
    has_expected_by_iso_time_format = test_has_expected_by_iso_time_format(response)
    test_results.append({'name': 'Has expected_by as ISO time format', 'result': has_expected_by_iso_time_format})

    # todo: test Data Rights Status object MAY contain 'user_verification_url' field; is a valid url
    has_user_verification_url_valid_format = test_has_user_verification_url_valid_format(response)
    test_results.append({'name': 'Has user_verification_url in valid format', 'result': has_user_verification_url_valid_format})

    # test Additional, optional or unknown  fields - no additional fields allowed
    contains_no_unknown_fields = test_excercise_contains_no_unknown_fields(response)
    test_results.append({'name': 'Contains no unknown fields', 'result': contains_no_unknown_fields})

    # test { action: access, regime: ccpa }
    if request_json['exercise'][0] == 'access' and request_json['regime'] == 'ccpa':
        is_reponse_valid_for_access_ccpa = test_is_reponse_valid_for_access_ccpa(response)
        test_results.append({'name': 'Response valid for access + ccpa', 'result': is_reponse_valid_for_access_ccpa})

    # test { action: access, regime: voluntary }
    if request_json['exercise'][0] == 'access' and request_json['regime'] == 'voluntary':
        is_reponse_valid_for_access_voluntary = test_is_reponse_valid_for_access_voluntary(response)
        test_results.append({'name': 'Response valid for access + voluntary', 'result': is_reponse_valid_for_access_voluntary})

    # test { action: deletion, regime: ccpa }
    if request_json['exercise'][0] == 'deletion' and request_json['regime'] == 'ccpa':
        is_reponse_valid_for_deletion_ccpa = test_is_reponse_valid_for_deletion_ccpa(response)
        test_results.append({'name': 'Response valid for deletion + ccpa', 'result': is_reponse_valid_for_deletion_ccpa})

    # test { action: deletion, regime: voluntary }
    if  request_json['exercise'][0] == 'deletion' and request_json['regime'] == 'voluntary':
        is_reponse_valid_for_deletion_voluntary = test_is_reponse_valid_for_deletion_voluntary(response)
        test_results.append({'name': 'Response valid for deletion + voluntary', 'result': is_reponse_valid_for_deletion_voluntary})

    # test { action: sale:opt_out, regime: ccpa }
    if  request_json['exercise'][0] == 'sale:opt_out' and request_json['regime'] == 'ccpa':
        is_reponse_valid_for_optout_ccpa = test_is_reponse_valid_for_optout_ccpa(response)
        test_results.append({'name': 'Response valid for sale:opt_out + ccpa', 'result': is_reponse_valid_for_optout_ccpa})

    # test { action: sale:opt_out, regime: voluntary }
    if  request_json['exercise'][0] == 'sale:opt_out' and request_json['regime'] == 'voluntary':
        is_reponse_valid_for_optout_voluntary = test_is_reponse_valid_for_optout_voluntary(response)
        test_results.append({'name': 'Response valid for sale:opt_out + voluntary', 'result': is_reponse_valid_for_optout_voluntary})

    # test { action: sale:opt_in, regime: ccpa }
    if  request_json['exercise'][0] == 'sale:opt_in' and request_json['regime'] == 'ccpa':
        is_reponse_valid_for_optin_ccpa = test_is_reponse_valid_for_optin_ccpa(response)
        test_results.append({'name': 'Response valid for sale:opt_in + ccpa', 'result': is_reponse_valid_for_optin_ccpa})

    # test { action: sale:opt_in, regime: voluntary }
    if  request_json['exercise'][0] == 'sale:opt_in' and request_json['regime'] == 'voluntary':
        is_reponse_valid_for_optin_voluntary = test_is_reponse_valid_for_optin_voluntary(response)
        test_results.append({'name': 'Response valid for sale:opt_in + voluntary', 'result': is_reponse_valid_for_optin_voluntary})

    return test_results


#-------------------------------------------------------------------------------------------------#
# test_status_endpoint

def test_request_id_matches_request(response, request_url):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    if 'results_url' not in response_json:
        return False
    response_request_id = response_json['request_id']
    request_request_id = request_url.GET.get('request_id', '')
    return response_request_id == request_request_id

def test_is_reponse_valid_for_status_fulfilled(response):
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    has_valid_fields = 'results_url' in response_json and 'expires_at' in response_json
    is_final = 'final' in response_json and response_json['final'] == 'true'
    return has_valid_fields and is_final

def test_is_reponse_valid_for_status_denied(response):
    valid_reason_values = [ 'suspected_fraud', 'insufficient_verification', 'no_match', 'claim_not_covered', 'too_many_requests', 'outside_jurisdiction', 'other', '“none' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    has_valid_fields = '“processing_details”' in response_json
    has_valid_reason = 'reason' in response_json and response_json['reason'] in valid_reason_values
    is_final = 'final' in response_json and response_json['final'] == 'true' and response_json['reason'] != 'too_many_requests'
    return has_valid_fields and has_valid_reason and is_final

def test_is_reponse_valid_for_status_expired(response, request):
    valid_reason_values = [ 'suspected_fraud', 'insufficient_verification', 'no_match', 'claim_not_covered', 'too_many_requests', 'outside_jurisdiction', 'other', '“none' ]
    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        return False 
    # The time is currently after “expires_at” in the request   
    # todo: can't write a meaningful test of this; the request does not contain a param 'expires_at'
    # todo: we could look up the value of 'expires_at' in the /exercise request with a matching reqiest_id ...
    is_time_after_expires_at = False
    is_final = 'final' in response_json and response_json['final'] == 'true'
    return is_time_after_expires_at and is_final


def test_status_endpoint(request_url, response):
    test_results = []

    """
    3.	GET /status
        - returns a Data Rights Status object
        - Data Rights Status object MUST contain field “request_id”
            - request_id value should match the value passed in from request
        - Data Rights Status object MUST contain field “received_at”
            - “received_at” is an ISO 8601 string (ISO time format)
        - Data Rights Status object MUST contain “status” field
            - “status” allowable values: [ "in_progress" | "open" | "fulfilled" | "revoked" | "denied" | "expired" ]
            - allowable status varies with action; see below
        - Data Rights Status object MAY contain “reason” field
            - “reason” allowable values: “need_verification” | "suspected_fraud" | “insufficient_verification” | "no_match" | "claim_not_covered" | "too_many_requests" | "outside_jurisdiction" | "other" | “none”
            - allowable reason varies with status; see below
        - Additional unknown fields - throw a warning

    3.1	GET /status  fulfilled
        - Additional fields: “results_url”, “expires_at”
        - Final

    3.2	GET /status  denied
        - “reason” allowable values: "suspected_fraud" | “insufficient_verification” | "no_match" | "claim_not_covered" | "too_many_requests" | "outside_jurisdiction" | "other" | “none”
        - Additional fields: “processing_details”
        - Final for all reasons except "too_many_requests"

    3.3	GET /status  expired
        - The time is currently after “expires_at” in the request
        - Final
    """

    # test returns a Data Rights Status object
    is_data_rights_status_obj = test_is_data_rights_status_obj(response)
    test_results.append({'name': 'Returns a Data Rights Status object', 'result': is_data_rights_status_obj})

    # test Data Rights Status object MUST contain field “request_id”
    contains_request_id = test_contains_request_id(response)
    test_results.append({'name': 'Contains field request_id', 'result': contains_request_id})

    # test request_id value should match the value passed in from request
    request_id_matches_request = test_request_id_matches_request(response, request_url)
    test_results.append({'name': 'request_id matches request', 'result': request_id_matches_request})

    # test Data Rights Status object MUST contain field “received_at”
    contains_received_at = test_contains_received_at(response)
    test_results.append({'name': 'Contains field received_at', 'result': contains_received_at})

    # test “received_at” is an ISO 8601 string (ISO time format)
    is_received_at_time_format = test_is_received_at_time_format(response)
    test_results.append({'name': 'Is received_at ISO time format', 'result': is_received_at_time_format})

    # test Data Rights Status object MUST contain “status” field
    contains_status_field = test_contains_status_field(response)
    test_results.append({'name': 'Contains status field', 'result': contains_status_field})

    # test “status” allowable values: [ "in_progress" | "open" | "fulfilled" | "revoked" | "denied" | "expired" ]
    is_status_valid = test_is_status_valid(response)
    test_results.append({'name': 'Is status valid', 'result': is_status_valid})

    # test Data Rights Status object MAY contain “reason” field
    contains_reason_field = test_contains_reason_field(response)
    test_results.append({ 'name': 'Contains reason field', 'result': contains_reason_field })

    # test “reason” allowable values: "need_verification" | "suspected_fraud" | “insufficient_verification” | "no_match" | "claim_not_covered" | "too_many_requests" | "outside_jurisdiction" | "other" | “none”
    is_reason_valid = test_is_reason_valid(response)
    test_results.append({ 'name': 'Is reason valid', 'result': is_reason_valid })

    # test known Additional fields: “results_url”, “expires_at”, “processing_details”
    # test Additional, optional or unknown  fields - no additional fields allowed
    contains_no_unknown_fields = test_excercise_contains_no_unknown_fields(response)
    test_results.append({ 'name': 'Contains no unknown fields', 'result': contains_no_unknown_fields })

    # test GET /status - fulfilled
    if test_contains_status_field(response) and json.loads(response.text)['status'] == 'fulfilled':   
        is_reponse_valid_for_status_fulfilled = test_is_reponse_valid_for_status_fulfilled(response)
        test_results.append({ 'name': 'Response valid for status fulfilled', 'result': is_reponse_valid_for_status_fulfilled })

    # test GET /status - denied
    if test_contains_status_field(response) and json.loads(response.text)['status'] == 'denied':
        is_reponse_valid_for_status_denied = test_is_reponse_valid_for_status_denied(response)
        test_results.append({ 'name': 'Response valid for status denied', 'result': is_reponse_valid_for_status_denied })

    # test GET /status - expired
    if test_contains_status_field(response) and json.loads(response.text)['status'] == 'expired':
        is_reponse_valid_for_status_expired = test_is_reponse_valid_for_status_expired(response)
        test_results.append({ 'name': 'Response valid for status expired', 'result': is_reponse_valid_for_status_expired })

    return test_results


#-------------------------------------------------------------------------------------------------#
# test_status_endpoint

# todo: implement ...

"""
4.  POST /revoke response
    - Response MUST adhere to the Exercise Status Schema. 
    - Response MUST contain the new state.
"""

