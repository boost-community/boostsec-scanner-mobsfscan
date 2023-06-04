ARG IMAGE_URL=289082777815.dkr.ecr.us-east-2.amazonaws.com/wolfi-images
ARG IMAGE_VERSION=1.0.7

ARG BASE_SHA=@sha256:63ff3494476a21153e29767845ef2c76fc0c4f2feb143d185fc460eacd35febd
ARG BUILD_SHA=@sha256:6cc077985e20abde3eba90dd0fbfa2c52d61e004b142b7f0bb366a37dd9e69c6


FROM ${IMAGE_URL}:python-build-${IMAGE_VERSION}${BUILD_SHA} as builder
  RUN --mount=type=secret,id=GITHUB_TOKEN set -ex \
   && git-activate-token-auth

  COPY pyproject.toml \
       poetry.lock \
       /app/

  RUN --mount=type=secret,id=GITHUB_TOKEN --mount=type=ssh set -ex \
   && poetry install --no-root --without dev

  COPY boostsec /app/boostsec

  RUN poetry build \
   && poetry run pip install dist/*.whl --no-deps \
   && rm -rf .venv/src


FROM ${IMAGE_URL}:python-app-${IMAGE_VERSION}${BASE_SHA} as base
  COPY --from=builder /app/.venv /app/.venv
  ENTRYPOINT ["boost-convert-mobsfscan"]
