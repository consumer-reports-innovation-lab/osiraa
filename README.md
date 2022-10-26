# OSIRAA - Open Source Implementer's Reference Authorized Agent

Version 0.5.0 - Updated October 2022

## There is a live demo version of OSIRAA available at [https://osiraa.datarightsprotocol.org/](https://osiraa.datarightsprotocol.org/).

## How to Use this App:
OSIRAA (Open Source Implementer's Reference Authorized Agent) is test suite designed to simulate the role of an Authorized Agent in a Digital Rights Protocol (DRP) environment.    The application tests for the availability, correctness and completeness of API endpoints of a Privacy Infrastructure Provider (PIP) or Covered Business (CB) partner application.  See <a href="https://github.com/consumer-reports-digital-lab/data-rights-protocol/blob/main/data-rights-protocol.md" target="blank">https://github.com/consumer-reports-digital-lab/data-rights-protocol/blob/main/data-rights-protocol.md</a> for more info on DRP system roles and API specification.

## Admin Tool
A user may model a PIP or Covered Business in the Admin Tool, along with any number of users.  This is a standard Python app, so you must first create an admin superuser in the usual way before you can administer data configurations.  For version 0.5, a covered business requires a Discovery Endpoint, Api Secret and Auth Bearer Token, to be supplied by the PIP/CB parter.

## Cert Tests Definitions
The Digital Rights Protocol is centered on a set of API calls between an Authorized Agent and a PIP or Covered Business, on behalf of a User exercising his or her digital rights.

## Run Tests Against a PIP or Covered Business API Endpoint
First select a PIP or Covered Business from the dropdown. You can then test the API endpoints for that PIP/CB for the following calls:  Discover, Exercise and Status.  Some calls require additional parameters such as a User or Covered Regime.  These can be set via dropdowns above the button in each section to trigger the call.  Users (Identity Users) can be configured in the Admin Tool. 

Once the call is made, the app presents an analysis of the response. It shows the request url, the response code, and the response payload.  If the the response is valid json, it test for required fields, fields in the response specific to the request params, etc.  Note that you must first call Exercise for a given PIP/User combination before you can call Status.  This is because the Exercise call returns a request_id, which is used for subsequent Status calls.


## Versions
  - Python 3.9.6
  - Django 3.2.7


## Develop locally

Clone repo:

```
git clone https://github.com/consumer-reports-digital-lab/drp-authorized-agent.git drp-aa-mvp
cd drp-aa-mvp
```

Create and activate local python environment:

```
python -m venv env
. ./env/bin/activate
```

Create requirements.txt if it does not already exist

```
pip freeze > requirements.txt
```

Install requirements:  

```
pip install -r requirements.txt
```


Install and set up postgres (latest version 14).  Note: there are serveral ways to do this.  One is via homebrew, which installs a basic set of tools including a CLU.  A more complete install is available at:  https://www.postgresql.org/download/macosx/.  This included a GUI admin tool that may be easier to use.  Once postgres is installed, you must create a default super user password, etc.

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

Run/deploy the app:

```
python3 manage.py runserver 8001
```

See the app in the browser:

```
 http://localhost:8001/
```




## Run in `docker`

NOTE:  Running the app in docker may cause conflicts with running locally as per the instructions above.  You should choose one or the other.  Running locally is better suited to the situation where you want to make changes to the source code and want to see them deployed without having to rebuild the app.  Running in a docker container is better for when you wish to deploy the app and configure it to test against you own local or dev DRP PIP endpoints for end-to-end testing.


"Simply" install [docker-compose](https://docs.docker.com/compose/) run these commands:

```
docker-compose up --build -d
docker-compose run -it web /usr/local/bin/python /code/manage.py createsuperuser
```

This will:
- build the Django service
- start a PostgreSQL instance
- run the Django service's migrations
- prompt you to create a Django "super user" which can access the Django admin console

The django admin console should be running http://localhost:8000/admin .


