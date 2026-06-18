  sudo docker compose -f deploy/docker-compose.yml down -v   # nuke old data
  sudo make docker-up                                        # rebuilds + starts
  cat deploy/bootstrap/cred.txt                              # ← creds appear here

