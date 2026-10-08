# Linux/amd64 worker image recipes. Digests below were resolved from the
# upstream registries; update only with a reviewed version and digest pair.
FROM python:3.11.17-slim-bookworm@sha256:8a00ecb83ed9d0864dfd102a1bdb2067fda907ceb30bb86d09da9ee558b19590 AS sdk
USER 0:0
RUN python -m pip uninstall -y setuptools wheel
COPY factoryline/__init__.py factoryline/deep_audit_io.py factoryline/runtime_audit_common.py factoryline/runtime_audit_process.py /usr/local/lib/python3.11/site-packages/factoryline/
COPY --chmod=0555 deploy/deep-adapters/entrypoint /opt/factory/bin/audit-adapter
RUN mkdir -p /src /out /opt/factory/rules
LABEL io.code-factory.protocol="factory.deep-worker.v1"
USER 1000:1000
WORKDIR /src
ENTRYPOINT ["/opt/factory/bin/audit-adapter"]

FROM semgrep/semgrep:1.141.0@sha256:64102d27111415eb3d51a313bf69739030a069716d7ba4827c2f8842c02b481e AS semgrep-tool
FROM semgrep-tool AS semgrep-worker
USER 0:0
COPY factoryline/__init__.py factoryline/deep_audit_io.py factoryline/runtime_audit_common.py factoryline/runtime_audit_process.py /usr/lib/python3.12/site-packages/factoryline/
COPY --chmod=0555 deploy/deep-adapters/entrypoint /opt/factory/bin/audit-adapter
COPY --chown=1000:1000 deploy/deep-adapters/profiles/semgrep-pattern-limited.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/semgrep-pattern-limited.yml /opt/factory/rules/semgrep-pattern-limited.yml
RUN mkdir -p /src /out /opt/factory/rules
WORKDIR /src
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.analysis-depth="pattern-limited"

ENTRYPOINT ["/usr/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS codeql-python-worker
USER 0:0
ADD --checksum=sha256:1ec99cfa9420f04c2330784b4ddb8363a0dd67c3e4471cd93963c50e6c433717 https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-linux64.tar.zst /tmp/codeql-bundle.tar.zst
COPY deploy/deep-adapters/requirements-codeql.txt /tmp/requirements-codeql.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-codeql.txt
RUN python -c 'import tarfile,zstandard; stream=zstandard.ZstdDecompressor().stream_reader(open("/tmp/codeql-bundle.tar.zst","rb")); tarfile.open(fileobj=stream,mode="r|").extractall("/opt/codeql",filter="data")' && rm -f /tmp/codeql-bundle.tar.zst
RUN /opt/codeql/codeql/codeql query compile --precompile --threads=4 --ram=4096 -- /opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11/codeql-suites/python-security-extended.qls && find /opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11 -type f -name '*.qlx' -exec chmod 0444 {} +
COPY --chown=1000:1000 deploy/deep-adapters/profiles/codeql-python-full.json /opt/factory/adapter-profile.json
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.analysis-depth="interprocedural-full" io.code-factory.language="python"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM ghcr.io/google/osv-scanner:v2.2.0@sha256:a6e641ed444704349d4319b80019654643aa9036b76ee1699a9f927dfe1b0d5c AS osv-tool
FROM anchore/syft:v1.33.0@sha256:cefadcf11bd9cce9e3ec5248bb1538a84e33d519486c1b4523ac155c9b5f5033 AS syft-tool
FROM sdk AS osv-worker
COPY --from=osv-tool /osv-scanner /usr/local/bin/osv-scanner
COPY --chmod=0555 deploy/deep-adapters/bin/osv-offline /opt/factory/bin/osv-offline
ADD --checksum=sha256:36ef7d92e174230b8c7c26b952562be23837472c2239b6752de64d5d683a800e https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip?generation=1791370055357324 /tmp/osv-pypi-all.zip
USER 0:0
RUN mkdir -p /opt/factory/osv-db/osv-scanner/PyPI && mv /tmp/osv-pypi-all.zip /opt/factory/osv-db/osv-scanner/PyPI/all.zip && chmod 0444 /opt/factory/osv-db/osv-scanner/PyPI/all.zip
COPY --chown=1000:1000 deploy/deep-adapters/profiles/osv.json /opt/factory/adapter-profile.json
USER 1000:1000
LABEL io.code-factory.configured="true" io.code-factory.family="dependencies" io.code-factory.mode="offline-pypi-snapshot"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS syft-worker
COPY --from=syft-tool /syft /usr/local/bin/syft
COPY --chown=1000:1000 deploy/deep-adapters/profiles/syft.json /opt/factory/adapter-profile.json
LABEL io.code-factory.configured="true" io.code-factory.family="dependencies" io.code-factory.mode="sbom-only"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM zricethezav/gitleaks:v8.28.0@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854 AS gitleaks-tool
FROM sdk AS gitleaks-worker
COPY --from=gitleaks-tool /usr/bin/gitleaks /usr/bin/gitleaks
COPY --chown=1000:1000 deploy/deep-adapters/profiles/gitleaks.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/gitleaks-8.28.0.toml /opt/factory/rules/gitleaks.toml
COPY --chown=1000:1000 deploy/deep-adapters/rules/GITLEAKS-LICENSE.txt /opt/factory/rules/GITLEAKS-LICENSE.txt
COPY --chown=1000:1000 deploy/deep-adapters/rules/empty-ignore.txt /opt/factory/rules/empty-gitleaksignore
LABEL io.code-factory.configured="true"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM aquasec/trivy:0.68.1@sha256:52e6fb1ff6a8232d6ec480ca9dd0b8db6728e252d092cb7712df7103ba09502e AS trivy-tool
FROM sdk AS trivy-worker
COPY --from=trivy-tool /usr/local/bin/trivy /usr/local/bin/trivy
COPY --chown=1000:1000 deploy/deep-adapters/profiles/trivy-config.json /opt/factory/adapter-profile.json
COPY --chown=1000:1000 deploy/deep-adapters/rules/empty-ignore.txt /opt/factory/rules/empty-trivyignore
COPY --chown=1000:1000 deploy/deep-adapters/rules/trivy.yaml /opt/factory/rules/trivy.yaml
LABEL io.code-factory.configured="true"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS runtime-worker
USER 0:0
COPY deploy/deep-adapters/requirements-runtime.txt /tmp/requirements-runtime.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-runtime.txt
USER 1000:1000
COPY --chown=1000:1000 deploy/deep-adapters/profiles/runtime-coverage.json /opt/factory/adapter-profile.json
LABEL io.code-factory.configured="true" io.code-factory.harness="candidate-supplied"

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
FROM sdk AS fuzz-worker
USER 0:0
COPY deploy/deep-adapters/requirements-fuzz.txt /tmp/requirements-fuzz.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /tmp/requirements-fuzz.txt
USER 1000:1000
COPY --chown=1000:1000 deploy/deep-adapters/profiles/atheris.json /opt/factory/adapter-profile.json
LABEL io.code-factory.configured="true" io.code-factory.harness="candidate-supplied"
ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "factoryline.deep_audit_io"]
