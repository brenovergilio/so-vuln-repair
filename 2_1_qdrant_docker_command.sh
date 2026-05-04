#!/bin/bash

CONTAINER_NAME="qdrant"

if docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1; then
    echo "📦 The container '$CONTAINER_NAME' already exists."
    
    if [ "$(docker inspect -f '{{.State.Running}}' $CONTAINER_NAME)" = "true" ]; then
        echo "✅ It is already running. No action needed."
    else
        echo "🔄 It was stopped. Starting it now..."
        docker start $CONTAINER_NAME
    fi
else
    echo "🚀 Container not found. Creating and starting '$CONTAINER_NAME'..."
    
    docker run -d --restart unless-stopped --name "$CONTAINER_NAME" \
        -p 6333:6333 \
        -p 6334:6334 \
        -v "$(pwd)/qdrant_storage:/qdrant/storage" \
        qdrant/qdrant
        
    echo "✅ Qdrant started successfully!"
fi