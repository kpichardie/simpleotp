FROM ubuntu:20.04

RUN apt-get update

ENV TZ=Europe/Paris

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get install -y python3 python3-pip tzdata

RUN pip3 install pyotp pyqrcode pypng

COPY main.py /main.py

RUN python3 -c "import pyotp; print(pyotp.random_base32())" > .totp_secret

