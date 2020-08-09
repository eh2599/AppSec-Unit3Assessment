FROM python:3.6-alpine

RUN adduser -D spell_check

WORKDIR /home/spell_check

RUN apk add --no-cache gcc musl-dev linux-headers python3-dev openssl-dev libffi-dev && pip3 install --upgrade pip

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

RUN chown -R spell_check:spell_check ./
USER spell_check

ENV FLASK_APP app.py
EXPOSE 5000

CMD["flask", "run"]
