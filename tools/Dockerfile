# Agent "tools" container: every scanner/signing CLI the pipeline uses, pinned, copied from the
# projects' own release images. Published to ghcr.io/pratheek888/devsecops-tools by CI.
FROM aquasec/trivy:0.76.2 AS trivy
FROM zricethezav/gitleaks:v8.30.1 AS gitleaks
FROM anchore/syft:v1.57.2 AS syft
FROM gcr.io/projectsigstore/cosign:v3.1.4 AS cosign
FROM gcr.io/go-containerregistry/crane:v0.22.1 AS crane
FROM mikefarah/yq:4.54.3 AS yq

FROM alpine:3.22
RUN apk add --no-cache bash ca-certificates git jq openssh-client \
 && adduser -D -u 1000 jenkins
COPY --from=trivy    /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=gitleaks /usr/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=syft     /syft                /usr/local/bin/syft
COPY --from=cosign   /ko-app/cosign       /usr/local/bin/cosign
COPY --from=crane    /ko-app/crane        /usr/local/bin/crane
COPY --from=yq       /usr/bin/yq          /usr/local/bin/yq
USER 1000
WORKDIR /home/jenkins
RUN trivy --version && gitleaks version && syft version && cosign version && crane version && yq --version
