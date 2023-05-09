FROM python:3
ENV PYTHONUNBUFFERED=1
WORKDIR /signdata
COPY requirements.txt /signdata/
RUN apt-get update && \
    apt-get install -y nano && \
    pip install -r requirements.txt
COPY . /signdata/
