FROM python:3.13

COPY root/* ./
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT [ "python", "ldaputil.py"]