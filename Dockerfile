# Helix in a container, with every optional module installed.
#
#   docker run --rm -v "$PWD:/data" ghcr.io/thalha-a9/helix -u USERNAME
#
# Reports are written to ./results on the host. Add --user "$(id -u):$(id -g)"
# if your user id is not 1000 and the files should belong to you.
FROM python:3.13-slim

# WeasyPrint (PDF reports) needs Pango and HarfBuzz, plus a font to draw text.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in helix.py ./
COPY osint ./osint
RUN pip install --no-cache-dir ".[full]" \
 && cd / && rm -rf /src

# Not root. The home folder holds the site list cache and stays writable for
# any --user, so the cache works whoever runs the container.
RUN useradd --create-home --uid 1000 helix \
 && mkdir -p /home/helix/.cache \
 && chmod -R 1777 /home/helix
ENV HOME=/home/helix \
    PYTHONUNBUFFERED=1
USER helix
WORKDIR /data

ENTRYPOINT ["helix-osint"]
CMD ["--help"]
