FROM python:3.13-alpine

# Copy the collector
COPY src /opt/openbas-collector-microsoft-sentinel

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxslt libxslt-dev libxml2 libxml2-dev && \
    cd /opt/openbas-collector-microsoft-sentinel && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY start.sh /
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]
