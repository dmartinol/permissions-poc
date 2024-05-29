#!/bin/bash

## Docker setup
# https://medium.com/@buffetbenjamin/securing-fastapi-with-keycloak-part-2-a-tale-of-roles-660ab5963ee5


if [ -f .env ]; then
    source .env
else
    echo ".env file not found!"
    exit 1
fi
echo $REALM

read_token(){
  username="$1"
  response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=${CLIENT_ID}" \
     -d "client_secret=${CLIENT_SECRET}" \
     -d "username=${username}" \
     -d "password=${PASSWORD}" \
     -d "grant_type=password")
  echo $response | jq -r .access_token
}

read_service(){
  local access_token="$1"
  local service_path="$2"
  echo "Trying GET http://localhost:8000${service_path}"
  curl -X GET "http://localhost:8000${service_path}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $access_token"
  echo ""
  echo "Trying POST http://localhost:8000${service_path}"
  curl -X POST "http://localhost:8000${service_path}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $access_token"
}

read -p "Is it a secured service? (y/n): " IS_SECURED
if [ "$IS_SECURED" == "y" ]; then
  read -p "Enter your username: " USERNAME
  access_token=$(read_token "$USERNAME")
  echo "Got token!"
  if [ "$access_token" == "null" ]; then
    echo "Failed to get access token"
    exit 1
  fi
else
  access_token="NA"
fi

while true; do
    echo ""
    read -p "Enter the service path, e.g. '/a' (RETURN to stop): " SERVICE_PATH
    if [ -n "$SERVICE_PATH" ]; then
        read_service "$access_token" "$SERVICE_PATH"
    else
        break
    fi
done



