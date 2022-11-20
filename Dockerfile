FROM python:3.9.12-slim AS python

COPY . ./

RUN pip3 install -r requirements.txt

CMD ["python", "main.py"]