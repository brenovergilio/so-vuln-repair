#!/bin/bash

CONTAINER_NAME="sonarqube"
# Define a pasta principal que vai guardar tudo
SONAR_DIR="$(pwd)/sonarqube"

if docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1; then
    echo "🧹 Removing old container..."
    docker rm -f $CONTAINER_NAME
fi

echo "📁 Preparing directories inside ./sonarqube/ ..."
mkdir -p "$SONAR_DIR/data" "$SONAR_DIR/logs" "$SONAR_DIR/extensions"

# Força o dono da pasta principal e de tudo lá dentro para o UID do SonarQube (1000)
sudo chown -R 1000:1000 "$SONAR_DIR"

echo "🚀 Creating and starting '$CONTAINER_NAME'..."

# Run the new container (Note the :z at the end of the -v lines for Fedora's SELinux)
docker run -d --restart unless-stopped --name "$CONTAINER_NAME" \
    -p 9000:9000 \
    -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
    -v "$SONAR_DIR/data:/opt/sonarqube/data:z" \
    -v "$SONAR_DIR/logs:/opt/sonarqube/logs:z" \
    -v "$SONAR_DIR/extensions:/opt/sonarqube/extensions:z" \
    sonarqube:lts-community
    
echo "✅ SonarQube started successfully! It might take a minute or two to fully boot."
echo "🌐 Access it at: http://localhost:9000 (Default login: admin / admin)"