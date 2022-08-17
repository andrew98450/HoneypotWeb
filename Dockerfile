FROM python:3.9.13-slim-buster AS python

COPY . ./

RUN pip3 install -r requirements.txt

CMD ["python", "main.py"]
