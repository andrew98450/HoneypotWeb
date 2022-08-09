FROM python:3.9.13-alpine AS python

COPY . ./

ENV PORT 8080

RUN pip3 install -r requirements.txt

CMD ['python3', 'main.py']
