FROM python:3.9.13-alpine AS python

COPY . ./

RUN pip3 install -r requirements.txt

EXPOSE 8080

ENV PORT 8080

CMD ['python3', 'main.py']
