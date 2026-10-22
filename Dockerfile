# NetWatch has no runtime dependencies, so the image is Python plus this
# package. Captures are mounted from the host; nothing is baked in.
FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY netwatch ./netwatch
RUN pip install --no-cache-dir --no-deps .

# Analyze a mounted capture and write a report next to it:
#   docker run --rm -v "$PWD/captures:/captures" netwatch \
#     analyze /captures --baseline /captures/baseline.json --html /captures/report.html
ENTRYPOINT ["netwatch"]
CMD ["--help"]
