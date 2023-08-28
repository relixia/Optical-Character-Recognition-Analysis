# Base image
FROM python:3.11

# Install required system packages
RUN apt-get update && \
    apt-get install -y libgl1-mesa-glx tesseract-ocr

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python -
ENV PATH="${PATH}:/root/.local/bin"

# Set the working directory in the container
WORKDIR /app

# Copy only the pyproject.toml and poetry.lock files to leverage Poetry caching
COPY pyproject.toml poetry.lock /app/

# Install project dependencies with Poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-root

# Copy the entire 'src' directory into the container
COPY ocr_analysis/ /app/ocr_analysis/

# Set the working directory to /app/
WORKDIR /app/ocr_analysis/
