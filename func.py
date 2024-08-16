import base64
import json
import io
from fdk import response
import oci
import requests
import time
from openapi_schema_validator import validate
import os
import ast
from bravado_core.spec import Spec
from bravado_core.validate import validate_object
from datetime import datetime
from random import randrange

#### IDCS Routines
#### https://docs.oracle.com/en/learn/apigw-modeldeployment/index.html#introduction
#### https://docs.oracle.com/en/learn/migrate-api-to-api-gateway/#introduction

def base64_string(clientID, secretID):
    auth = clientID + ":" + secretID
    auth_bytes = auth.encode("ascii")
    auth_base64_bytes = base64.b64encode(auth_bytes)
    auth_base64_message = auth_base64_bytes.decode("ascii")
    return auth_base64_message

def auth_idcs(token, url, clientID, secretID):
    url = url + "/oauth2/v1/introspect"

    auth_base64_message = base64_string(clientID, secretID)

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + auth_base64_message
    }

    payload = "token=" + token

    response = requests.request("POST", url, headers=headers, data=payload)
    return response

def auth_ad(url, clientID, secretID):
    url = url + "/oauth2/v2.0/token"

    auth_base64_message = base64_string(clientID, secretID)

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + auth_base64_message
    }

    payload = {"scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}

    response = requests.request("POST", url, headers=headers, data=payload)
    return response

def conta_items(dictData):
    contagem = 0
    for item in dictData:
        try:
            if type(dictData[item]) == list:
                contagem += len(dictData[item])
            else:
                if not type(dictData[item]) == str:
                    contagem += conta_items(dictData[item])
        except:
            print("item = not string")
    return contagem

def count_attributes(json_data):
    count = 0
    for key, value in json_data.items():
        count += 1
        if isinstance(value, dict):
            count += count_attributes(value)
    return count

def handler(ctx, data: io.BytesIO = None):
    config = oci.config.from_file("config")
    logging = oci.loggingingestion.LoggingClient(config)

    # functions context variables
    app_context = dict(ctx.Config())

    jsonData = ""

    try:
        header = json.loads(data.getvalue().decode('utf-8'))["data"]

        # IDCS Validation
        url = "https://idcs-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx.identity.oraclecloud.com"
        ClientId = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ClientSecret = "8xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        oic_clientId = "FXXXXXXXXXXXXXXXXXXXXXXXXXXX_APPID"
        oic_clientSecret = "xxxxxxxxxx-xxxxx-xxxxx-xxxx-xxxxxxxxxxxxx"
        auth_base64_message = base64_string(oic_clientId, oic_clientSecret)

        url_ad = "https://login.microsoftonline.com/xxxxxxxx-xxxxx-xxxxxx-xxxxxxxx"
        ClientId_ad = "xxxxxxxxxxxx-xxxx-xxxx-xxxxxxx-xxxxxxxxx"
        ClientSecret_ad = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

        try:
            token_ad = auth_ad(url_ad, ClientId_ad, ClientSecret_ad)
            print(token_ad.json())
        except(Exception) as ex2:
            print(ex2)

        # JSON Items counter
        jsonData = dict(json.loads(data.getvalue().decode('utf-8')).get("data"))["body"]
        jsonData = dict(json.loads(jsonData))
        c = count_attributes(jsonData)
        if (c > 12):
            rdata = json.dumps({
                "active": False,
                "context": {
                    "status_code": 401,
                    "message": "JSON exception",
                    "error": "JSON exception",
                }})

            return response.Response(
                ctx,
                status_code=401,
                response_data=rdata
            )

        try:
            body = dict(json.loads(data.getvalue().decode('utf-8')).get("data"))["body"]
            body = json.loads(body)
        except:
            body = None

        # header values
        access_token = header["token"]

        authorization = auth_idcs(access_token, url, ClientId, ClientSecret)
        try:
            if (authorization.json().get("active") != True):
                return response.Response(
                    ctx,
                    status_code=401,
                    response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
                )
        except(Exception) as ex1:
            jsonData = 'error parsing json payload(2): ' + str(ex1)
            put_logs_response = logging.put_logs(
                log_id="ocid1.log.oc1.iad.amaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    specversion="EXAMPLE-specversion-Value",
                    log_entry_batches=[
                        oci.loggingingestion.models.LogEntryBatch(
                            entries=[
                                oci.loggingingestion.models.LogEntry(
                                    data="error(a): " + jsonData,
                                    id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                            source="EXAMPLE-source-Value",
                            type="EXAMPLE-type-Value")]))
            rdata = json.dumps({
                "active": False,
                "context": {
                    "status_code": 401,
                    "message": "Unauthorized",
                    "body": body,
                    "error": str(ex1)
                }})

            return response.Response(
                ctx,
                status_code=401,
                response_data=rdata
            )

        rdata = json.dumps({
            "active": True,
            "context": {
                "body": body,
                "authorization_idcs": "Basic " + auth_base64_message
            }})

        return response.Response(
            ctx, response_data=rdata,
            status_code=200,
            headers={"Content-Type": "application/json", "body": json.dumps(body)}
        )

    except(Exception) as ex:
        jsonData = 'error parsing json payload(1): ' + str(ex)
        put_logs_response = logging.put_logs(
            log_id="ocid1.log.oc1.iad.amaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                specversion="EXAMPLE-specversion-Value",
                log_entry_batches=[
                    oci.loggingingestion.models.LogEntryBatch(
                        entries=[
                            oci.loggingingestion.models.LogEntry(
                                data="error(c): " + jsonData,
                                id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                        source="EXAMPLE-source-Value",
                        type="EXAMPLE-type-Value")]))

        pass

    return response.Response(
        ctx,
        status_code=401,
        response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
    )
