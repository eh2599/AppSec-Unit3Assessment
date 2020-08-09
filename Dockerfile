FROM python:3.6-alpine

RUN adduser -D spell_check

WORKDIR /home/spell_check

ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0

RUN apk add --no-cache gcc musl-dev linux-headers

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt


COPY . .

RUN chown -R spell_check:spell_check ./
USER spell_check

EXPOSE 5000

CMD["flask", "run"]
