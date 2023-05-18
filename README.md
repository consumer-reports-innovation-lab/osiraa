# OSIRAA - Open Source Implementers’ Reference Authorized Agent

Version 0.7.0 - Updated March 2023

## There is a live demo version of OSIRAA available at [https://osiraa.datarightsprotocol.org/](https://osiraa.datarightsprotocol.org/).

## How to Use this App:
OSIRAA (Open Source Implementers’ Reference Authorized Agent) is a test suite designed to simulate the role of an Authorized Agent in a Data Rights Protocol (DRP) environment.    The application tests for the availability, correctness and completeness of API endpoints of a Privacy Infrastructure Provider (PIP) or Covered Business (CB) partner application.  See <a href="https://github.com/consumer-reports-digital-lab/data-rights-protocol/blob/main/data-rights-protocol.md" target="blank">https://github.com/consumer-reports-digital-lab/data-rights-protocol/blob/main/data-rights-protocol.md</a> for more info on DRP system roles and API specification.

## Admin Tool
A user may model a Privacy Infrastructure Provider (PIP) or Covered Business (CB) in the Admin Tool, along with any number of users.  This is a standard Python app, so you must first create an admin superuser before you can administer data configurations.  For version 0.7, a Covered Business requires a Discovery Endpoint, and Auth Bearer Token, to be supplied by the PIP/CB partner.  NOTE:  The previously required API Secret has been depricated.  The Authorized Agent will be using a public/private key instead of shared api secret.

## Cert Tests Definitions
The Data Rights Protocol is centered on a set of API calls between an Authorized Agent (AA) and a Privacy Infrastructure Provider or Covered Business, on behalf of a User exercising his or her data rights.

## Test Against a PIP or Covered Business API Endpoint
First select a Privacy Infrastructure Provider or Covered Business from the dropdown. You can then test the API endpoints for that PIP/CB for the following calls:  
  - GET /.well-known/data-rights.json
  - POST /exercise
  - GET /status

Some calls require additional parameters such as a User or Covered Regime.  These can be set via dropdowns above the button in each section to trigger the call.  Users (Identity Users) can be configured in the Admin Tool. 

Once the call is made, the app presents an analysis of the response. It shows the request url, the response code, and the response payload.  If the response is valid json, it tests for required fields, fields in the response specific to the request params, etc.  Note that you must first call Exercise for a given PIP/User combination before you can call Status.  This is because the Exercise call returns a request_id, which is used for subsequent Status calls.

## Test an Authorized Agent implementation
OSIRAA also contains a minimalist Privacy Infrastructure Provider API running at https://osiraa.datarightsprotocol.org/pip . Authorized Agents can be registered in the Django administration panel to test compliance with the Data Rights Protocol. The code in the [DRP PIP](https://github.com/consumer-reports-innovation-lab/osiraa/tree/main/drp_aa_mvp/drp_pip) Django app can also be used as a reference implementation for Privacy Infrastructure Providers implementing the protocol. 

## Versions
  - Python 3.9.6
  - Django 3.2.7


## Running OSIRAA
OSIRAA can be run in two ways: locally, or in a docker container. You should choose one or the other; attempting to run the app both ways may cause conflicts.
Running locally is better suited to the situation where you want to make changes to the source code and see them deployed without having to rebuild the app. 
Running in a docker container is better for when you wish to deploy the app and configure it to test against your own local or dev endpoints for end-to-end testing.


## Local Development

Make sure you have Python 3.9.6 installed.

(TODO: note for mac users about multiple python versions ... )

Clone the repo:

```
git clone https://github.com/consumer-reports-digital-lab/drp-authorized-agent.git drp-aa-mvp
cd drp-aa-mvp
```

Note: some recent versions macOS have python 2.7 already installed. You'll need to install python3 seperately. In order to to execute commands against the correct python version, use python3 instead of python in the commands listed below.

Create and activate local python environment:

```
python3 -m venv env
. ./env/bin/activate
```

Install requirements:  

```
cd drp_aa_mvp
pip install -r requirements.txt
```

Install and set up postgres (latest version 14).  There are several ways to do this.  One is via homebrew, which installs a basic set of tools including a CLU.  A more complete install is available at:  https://www.postgresql.org/download/macosx/.  This included a GUI admin tool that may be easier to use.  Once postgres is installed, you must create a default super user password, etc.

Create database:  Using PGAdmin select Object -> Create -> Database and name it `authorizedagent`. Alternatively, in the postgres CLI tool say:

```
createdb authorizedagent
```

Django setup:
```
python manage.py migrate
python manage.py createsuperuser
python manage.py collectstatic
```

Run/deploy the app (note: using port 8003 for P'slip/DRP insstance of OSIRAA)
```
python3 manage.py runserver 8003
```

See the app in the browser:

```
 http://localhost:8003/
```




## Run in `docker`

"Simply" install [docker-compose](https://docs.docker.com/compose/) run these commands:

```
docker-compose up -f docker-compose.yml -f docker-compose.override.yml --build -d
docker-compose run -it web /usr/local/bin/python /code/manage.py createsuperuser
```

This will:
- build the Django service
- start a PostgreSQL instance
- run the Django service's migrations
- prompt you to create a Django "super user" which can access the Django admin console

The django admin console should be running http://localhost:8000/admin .

## Contact
If you encounter development issues or want more information, you can reach the Data Rights Protocol team via email at datarightsprotocol@cr.consumer.org.


