FROM python:3.10

ARG USER=osiraa
ENV user=${USER}

RUN groupadd -g 1000 ${USER} && \
    useradd -m -u 1000 -g ${USER} -s /bin/bash ${USER} && \
    mkdir -p /code && \
    chown -R ${USER}:${USER} \
    /code 


COPY --chown=${USER}:${USER} drp_aa_mvp/requirements.txt /requirements.txt
COPY --chown=${USER}:${USER} docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY --chown=${USER}:${USER} drp_aa_mvp/ /code

USER ${USER}
WORKDIR /code

RUN pip install -r /requirements.txt

CMD "/entrypoint.sh"
EXPOSE 8000:8000
