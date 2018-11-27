FROM python:3
WORKDIR /usr/src/app
COPY . .
RUN pip install -r requirements.txt; \
    apt-get update && apt-get install -y --no-install-recommends whois\
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["./entrypoint.sh"]

# docker build -t dnsmonitor .
# docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY dnsmonitor