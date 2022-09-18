FROM python:3.9.13-slim AS python

COPY . ./

RUN pip3 install -r requirements.txt

CMD ["python", "app.py"]