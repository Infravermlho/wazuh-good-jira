#!/bin/bash
set -e

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
CONFIG_PATH="/usr/share/wazuh-good-jira"

cd "${SCRIPT_DIR}" || return

echo -e "Moving the integration to /var/ossec/integrations/"
mkdir -p "/var/ossec/integrations/" && cp "${SCRIPT_DIR}/integration/custom-good-jira.py" "/var/ossec/integrations/custom-good-jira.py"
chmod 750 /var/ossec/integrations/custom-good-jira.py
chown root:wazuh "/var/ossec/integrations/custom-good-jira.py" || echo -e "Wazuh user not found"

if [ -e ${CONFIG_PATH} ]; then
  echo -e "Config files found, overwrite? (y/n)"
  read -s -r -n 1 key

  if [ "$key" = "y" ]; then
    mkdir -p "${CONFIG_PATH}" && cp "${SCRIPT_DIR}/default.config.yaml" "${CONFIG_PATH}/config.yaml"
  fi
else
  echo -e "config files not found, creating"
  mkdir -p "${CONFIG_PATH}" && cp "${SCRIPT_DIR}/default.config.yaml" "${CONFIG_PATH}/config.yaml"
fi

chmod 775 "${CONFIG_PATH}/config.yaml"
chown root:wazuh "${CONFIG_PATH}/config.yaml" || echo -e "Wazuh user not found"
echo -e "custom-good-jira installed sucessfully"
