#!/bin/bash


####################
# Install docker
####################

if ! command -v docker >/dev/null 2>&1; then
  info "Installing docker ..."

  curl https://releases.rancher.com/install-docker/19.03.sh | sh

  info "Installing docker ... OK"
fi


###########################
# Install docker compose
###########################

info "Installing docker-compose ..."
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod a+x /usr/local/bin/docker-compose
docker-compose version

info "Installing docker-compose ... OK"


###########################
# Install and run robot-shop
###########################

info "Installing robot-shop ..."
cd /root/
git clone https://github.com/instana/robot-shop.git
cd /root/robot-shop
export INSTANA_AGENT_KEY="qUMhYJxjSv6uZh2SyqTEnw"
docker-compose -f docker-compose.yaml -f docker-compose-load.yaml up -d
info "Installing robot-shop ... OK"
cd /root/robot-shop
docker-compose ps
info "Running docker containers ... OK"


###########################
# Set up instana agent
###########################

info "Setting up instana agent ..."
curl -o setup_agent.sh https://setup.instana.io/agent && chmod 700 ./setup_agent.sh && sudo ./setup_agent.sh -a qUMhYJxjSv6uZh2SyqTEnw -t dynamic -e yao-2-instana-kind-instana-kind-env.fyre.ibm.com:1444 -y
systemctl status instana-agent
systemctl start instana-agent
systemctl status instana-agent
info "Setting up instana agent ... OK"


