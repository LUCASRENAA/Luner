FROM python:3.11.2
LABEL mainteiner="Lucas Renan < lrms2 at discente.ifpe.edu.br>"

#Prevents Python from writing pyc files to disc
#Prevents Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code/

COPY requirements.txt /code/

RUN pip install -U pip setuptools wheel &&\
        pip install -r  /code/requirements.txt

COPY . .