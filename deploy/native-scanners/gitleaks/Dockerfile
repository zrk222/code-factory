# Native scanner foundation. This is not a factory.deep-worker.v1 adapter.
FROM zricethezav/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854
LABEL org.opencontainers.image.title="Code Factory native Gitleaks scanner"
LABEL org.opencontainers.image.version="8.28.0"
LABEL io.code-factory.protocol="native-sarif-only"
LABEL io.code-factory.deep-worker="false"
USER 1000:1000
WORKDIR /src
ENTRYPOINT ["gitleaks"]
