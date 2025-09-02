# Use the same curl image as a base
FROM curlimages/curl:8.7.1

# Switch to the root user to install packages
USER root

# Install jq using the Alpine package manager
RUN apk add --no-cache jq