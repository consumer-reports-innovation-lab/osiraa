FROM python:3
COPY drp_aa_mvp/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY drp_aa_mvp/ /code
WORKDIR /code
CMD "/entrypoint.sh"
EXPOSE 8000:8000
