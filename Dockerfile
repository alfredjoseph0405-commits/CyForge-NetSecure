# Use lightweight Python base
FROM python:3.11-slim

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    tshark \
    tcpdump \
    build-essential \
    libpcap-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /proj

# Copy requirements if you have (optional)
# COPY requirements.txt .
# RUN pip install -r requirements.txt

# Install Python dependencies
RUN pip install django python-dotenv google-genai bandit

# Copy project (optional if using volume, but safe fallback)
COPY ./main /proj

# Expose Django port
EXPOSE 8000