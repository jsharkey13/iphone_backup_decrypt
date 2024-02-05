FROM python:3.11

LABEL org.opencontainers.image.source=https://github.com/jsharkey13/iphone_backup_decrypt
LABEL org.opencontainers.image.description="Python:3.11 container with iphone_backup_decrypt and fastpbkdf2."

RUN pip install iphone_backup_decrypt[fastpbkdf2]

CMD python
