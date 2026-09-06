#!/bin/sh
set -eu

model="${OLLAMA_MODEL:-llama3.1:8b}"
embedding_model="${RAG_EMBEDDING_MODEL:-nomic-embed-text}"
local_host="http://127.0.0.1:11434"

ollama serve &
server_pid=$!

stop_server() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap stop_server INT TERM

until OLLAMA_HOST="$local_host" ollama list >/dev/null 2>&1; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        exit $?
    fi
    sleep 1
done

if ! OLLAMA_HOST="$local_host" ollama show "$model" >/dev/null 2>&1; then
    echo "Descargando el modelo local de Ollama: $model"
    OLLAMA_HOST="$local_host" ollama pull "$model"
fi

if ! OLLAMA_HOST="$local_host" ollama show "$embedding_model" >/dev/null 2>&1; then
    echo "Descargando el modelo local de embeddings: $embedding_model"
    OLLAMA_HOST="$local_host" ollama pull "$embedding_model"
fi

echo "Ollama listo con los modelos: $model, $embedding_model"
wait "$server_pid"
