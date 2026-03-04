@echo off
docker compose --env-file .env.properties up %*
