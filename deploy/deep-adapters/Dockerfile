# Worker SDK; a final approved image must bundle its native toolchain and profile.
# Linux amd64 base pin verified against the upstream Python image index.
FROM python@sha256:1267eb99c0bd130ef73ba0f1246ec8949c2f14bb2a2a9f2b5129277156d0abf5 AS worker
COPY factoryline/__init__.py factoryline/deep_audit_io.py factoryline/runtime_audit_common.py factoryline/runtime_audit_process.py /usr/local/lib/python3.11/site-packages/factoryline/
COPY --chmod=0555 deploy/deep-adapters/entrypoint /opt/factory/bin/audit-adapter
RUN mkdir -p /src /out
LABEL io.code-factory.protocol="factory.deep-worker.v1"
LABEL io.code-factory.configured="false"
USER 1000:1000
WORKDIR /src
ENTRYPOINT ["/opt/factory/bin/audit-adapter"]

FROM worker AS gitleaks-worker
COPY --from=zricethezav/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854 /usr/bin/gitleaks /usr/bin/gitleaks
