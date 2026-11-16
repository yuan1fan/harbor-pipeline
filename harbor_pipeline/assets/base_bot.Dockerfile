FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
# The upstream image includes Chromium and its system dependencies, but not
# the Python package. Match its version to the preinstalled browser binaries.
RUN python -m pip install --no-cache-dir playwright==1.48.0
