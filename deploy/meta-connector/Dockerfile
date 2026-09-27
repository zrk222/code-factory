FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FACTORY_META_DATABASE=/data/meta-connector.sqlite

WORKDIR /app
COPY pyproject.toml README.md ./
COPY factoryline ./factoryline
RUN pip install --no-cache-dir '.[hosted]' && \
    mkdir /data && \
    useradd --system --uid 10001 --home-dir /data factory && \
    chown factory:factory /data

USER factory
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/ready', timeout=2).read()"
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "factoryline.meta_connector_api:app"]
