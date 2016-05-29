FROM python:2.7

RUN pip install mitmproxy 
RUN pip install adblockparser
RUN git clone https://github.com/google/re2.git
# Anything after 2016-03-01 fails `pip install re2`
RUN cd re2 && git checkout 2016-03-01
RUN cd re2 && make && make install
RUN pip install re2
RUN mkdir /code
ADD . /code
RUN rm -f /code/easylists/*
#RUN pip install .

EXPOSE 8118

VOLUME /ca

CMD cd code && \
  mitmdump \
    --script adblock.py \
    --cadir /ca \
    --port 8118
