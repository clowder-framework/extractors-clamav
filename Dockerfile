FROM python:3.7-alpine

ARG VERSION="unknown"
ARG BUILDNUMBER="unknown"
ARG GITSHA1="unknown"

# environemnt variables
ENV VERSION=${VERSION} \
    BUILDNUMBER=${BUILDNUMBER} \
    GITSHA1=${GITSHA1} \
    RABBITMQ_QUEUE="ncsa.clamav"

WORKDIR /extractor

RUN apk add --no-cache clamav clamav-libunrar

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY clamav.py extractor_info.json start.sh ./
CMD ./start.sh
