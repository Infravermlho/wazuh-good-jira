#!/usr/bin/env python
# Script for creating Jira messages out of Wazuh alert_json
# Config files are located on "/usr/share/wazuh-good-jira"

import argparse
import json
import os
import re as _re
import sys
import time
import traceback

from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser(
    description="Script for creating Jira messages out of Wazuh Alerts"
)
parser.add_argument("alert_json")
parser.add_argument("url")
parser.add_argument("api_token")
parser.add_argument("-l", "--log_path", help="set a different log path")
args = parser.parse_args()

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
TIMEOUT = 360
CONFIG_PATH = "/usr/share/wazuh-good-jira"
LOG_PATH = args.log_path if args.log_path else f"{pwd}/logs/integrations.log"


class Templater:
    pat = r"\$\{(.*?)\}"
    pattern = _re.compile(pat)

    def substitute(self, template, mapping) -> str:
        """
        Replaces words surrounded by {} with their respective attributes in the mapping dict
        """

        # Helper function for .sub()
        def convert(mo):
            match = mo.group()[2:-1]
            split = match.split(".")
            if match is not None:
                cursor = mapping
                for key in split:
                    try:
                        cursor = cursor[key]
                    except KeyError:
                        return mo.group()

                return str(cursor)
            return mo.group()

        return self.pattern.sub(convert, template)


class Logger:
    def __init__(self, log_path):
        self.log_path = log_path

    def log(self, msg):
        """
        Writes message to log file
        """
        now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

        msg = f"{now}| Custom-Good-Jira | {msg} \n"
        print(msg, end="")

        with open(self.log_path, "a", encoding="utf-8") as file_io:
            file_io.write(msg)


def make_alert(alert_json):
    """
    Interprets the alert args and converts it into a POST request to Jira
    """

    logger.log("Parsing alert json")

    alert_id = str(alert_json["rule"]["id"])
    with open(f"{CONFIG_PATH}/config.yaml") as file_io:
        config = yaml.safe_load(file_io)

    templater = Templater()
    rule_template: dict = config["rule_id"]["default"] | (
        config["rule_id"][alert_id] if alert_id in config["rule_id"] else {}
    )

    # Traverses dict and substitutes patterns
    def traverse_dict(obj):
        if isinstance(obj, str):
            return templater.substitute(obj, alert_json)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                obj[key] = traverse_dict(value)

        return obj

    for key, value in rule_template.items():
        rule_template[key] = traverse_dict(value)

    message = {"fields": rule_template}

    api_token = args.api_token.split(":")
    basic_auth = HTTPBasicAuth(api_token[0], api_token[1])

    logger.log("Parsing done")
    logger.log(f"Message: {message}")

    post_params = {
        "url": args.url,
        "headers": {"content-type": "application/json"},
        "data": json.dumps(message),
        "timeout": TIMEOUT,
        "auth": basic_auth,
    }
    response_action = requests.post(**post_params)

    logger.log(
        f"POST request done, response is: {response_action}\n {response_action.content}"
    )


if __name__ == "__main__":
    logger = Logger(LOG_PATH)
    try:
        import requests
        import yaml

        pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    except ImportError:
        logger.log(
            "Missing modules.\nInstall: pip install requests\nInstall: pip install pyyaml",
        )
        sys.exit(1)

    if not os.path.isfile(f"{CONFIG_PATH}/config.yaml"):
        logger.log(
            f"Missing config files on {CONFIG_PATH}",
        )
        sys.exit(1)

    try:
        logger.log("good-jira started:")

        with open(args.alert_json, encoding="utf-8") as alert_file:
            alert_json = json.loads(alert_file.read())

        make_alert(alert_json)
    except Exception as _general_e:
        logger.log("".join(traceback.format_exception(_general_e)))
        raise _general_e
