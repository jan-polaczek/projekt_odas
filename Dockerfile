FROM chaberb/uwsgi-flask
WORKDIR ./

RUN apk add --no-cache --update musl-dev gcc libffi-dev python3-dev openssl-dev && pip3 install --upgrade pip && pip3 install --upgrade setuptools
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
EXPOSE 5000
COPY . .
RUN chmod 777 uploads
