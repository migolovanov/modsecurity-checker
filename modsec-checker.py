import os
import re
import sys
import json
import time
import rstr
import exrex
import asyncio
import argparse
import urllib.parse
import requests
from ModSecurity import *
from jinja2 import Template
from operator import itemgetter
from textx.metamodel import metamodel_from_file
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)


def colorize(color, text):
    text = str(text)
    if color == 'red':
        print(''.join(['\033[1;31m', text, '\033[1;m']))
    elif color == 'green':
        print(''.join(['\033[1;32m', text, '\033[1;m']))
    elif color == 'blue':
        print(''.join(['\033[1;34m', text, '\033[1;m']))
    else:
        print(text)


class Rule:
    def __init__(self, rule):
        self.id = 0
        self.filename = None
        self.get_rule_id(rule)
        self.rule = rule.parent._tx_parser.input[rule._tx_position:rule._tx_position_end]
        self.rule_original = self.rule
        if not re.search("nolog", self.rule):
            self.rule = re.sub(r"(id\s*:\s*[0-9]*,)", "\\1 nolog,", self.rule)
        if not re.search("deny", self.rule):
            self.rule = re.sub(r"(id\s*:\s*[0-9]*,)", "\\1 deny,", self.rule)
        sys.stdout = open(os.devnull, 'w')
        self.regex = rule.operator.rx
        self.method = None
        self.payload = ""
        self.valid = False
        try:
            sys.stdout = open(os.devnull, 'w')
            self.payload = exrex.getone(self.regex)
            sys.stdout = sys.__stdout__
            self.valid = bool(re.search(self.regex, self.payload))
            self.method = "exrex"
        except BaseException:
            True
        if not self.valid:
            try:
                self.payload = rstr.xeger(self.regex)
                self.valid = bool(re.search(self.regex, self.payload))
                self.method = "rstr"
            except BaseException:
                True
        self.arguments = set()
        self.variables = set()
        for v in rule.variables:
            if v and not v.negated:
                self.variables.add(v.collection)
                if v.collectionArg:
                    self.arguments.add(v.collectionArg)
        self.request = Request(self)

    def get_rule_id(self, rule):
        if rule.__class__.__name__ == "SecRule" or rule.__class__.__name__ == "SecAction":
            for action in rule.actions:
                if action.id:
                    self.id = action.id
                    return


def pretty_raw_request(response):
    result = response.request.method + " " + \
        response.request.path_url + " HTTP/1.1\n"
    result += "Host: %s\n" % response.url.split('/')[2]

    for key, value in response.request.headers.items():
        if key != "Connection":
            result += "%s: %s\n" % (key, value)

    result += "Connection: %s\n" % response.request.headers["Connection"]

    if response.request.body is not None:
        result += "\n%s" % response.request.body
    else:
        result += "\n"
    return result


class Request:
    def __init__(self, rule):
        self.uri = "/"
        self.protocol = "1.1"
        self.xml = None
        self.method = None
        self.files = []
        self.form = {}
        self.query = {}
        self.cookie = {}
        self.headers = {}

        self.set_protocol(rule)
        self.set_method(rule)
        self.set_headers(rule)
        self.set_params(rule)

    def set_protocol(self, rule):
        if "REQUEST_PROTOCOL" in rule.variables:
            self.protocol = rule.payload

    def set_method(self, rule):
        if rule.variables & set(["ARGS",
                                 "ARGS_NAMES",
                                 "ARGS_GET",
                                 "ARGS_GET_NAMES",
                                 "QUERY_STRING",
                                 "REQUEST_BASENAME",
                                 "REQUEST_FILENAME",
                                 "REQUEST_LINE",
                                 "REQUEST_URI",
                                 "REQUEST_URI_RAW",
                                 "REQUEST_COOKIES",
                                 "REQUEST_COOKIES_NAMES",
                                 "REQUEST_HEADERS",
                                 "REQUEST_HEADERS_NAMES",
                                 "MATCHED_VARS"]):
            self.method = "get"
        elif rule.variables & set(["ARGS_POST", "ARGS_POST_NAMES", "REQUEST_BODY", "FILES", "FILES_NAMES", "FULL_REQUEST", "MULTIPART_FILENAME", "MULTIPART_NAME", "XML"]):
            self.method = "post"
        elif rule.variables & set(["REQUEST_METHOD"]):
            self.method = rule.payload
        elif rule.variables & set(["REQUEST_LINE"]):
            m = re.search("([A-Z])+", rule.payload)
            if m:
                self.method = m.group(1)

        if "XML" in rule.variables:
            self.xml = '<?xml version="1.0" encoding="UTF-8"?>'
            self.xml += '<test>{}</text>'.format(rule.payload)
            for a in rule.arguments:
                self.xml += '<{}>{}</{}>'.format(a, rule.payload, a)

    def set_params(self, rule):
        if rule.variables & set(["REQUEST_BASENAME", "REQUEST_FILENAME"]):
            self.uri += urllib.parse.quote_plus(rule.payload)

        if rule.variables & set(["ARGS",
                                 "ARGS_GET",
                                 "QUERY_STRING",
                                 "REQUEST_LINE",
                                 "REQUEST_URI",
                                 "REQUEST_URI_RAW"]):
            self.query["test"] = rule.payload
            for a in rule.arguments:
                self.query[a] = rule.payload

        if rule.variables & set(["ARGS_NAMES", "ARGS_GET_NAMES"]):
            self.query[rule.payload] = "test"

        if "ARGS_POST_NAMES" in rule.variables:
            self.form[rule.payload] = "test"

        if rule.variables & set(
                ["FILES", "FILES_NAMES", "MULTIPART_FILENAME", "MULTIPART_NAME"]):
            self.files.append(
                {"filename": rule.payload, "name": rule.payload, "data": "test"})

    def set_headers(self, rule):
        if "REQUEST_HEADERS" in rule.variables:
            self.headers["Test"] = rule.payload
            for a in rule.arguments:
                self.headers[a] = rule.payload

        if "REQUEST_HEADERS_NAMES" in rule.variables:
            self.headers[rule.payload] = "test"

        if "REQUEST_COOKIES" in rule.variables:
            self.cookie["test"] = rule.payload
            for a in rule.arguments:
                self.cookie[a] = rule.payload

        if "REQUEST_COOKIES_NAMES" in rule.variables:
            self.cookie[rule.payload] = "test"

        if rule.variables & set(["FULL_REQUEST", "REQUEST_BODY", "ARGS_POST"]):
            self.form["test"] = rule.payload
            for a in rule.arguments:
                self.form[a] = rule.payload


async def check_mod_security(rule):
    modsec = ModSecurity()
    rules = Rules()
    rules.load("SecRuleEngine On\nSecDebugLogLevel 0\n{}".format(rule.rule))
    transaction = Transaction(modsec, rules, None)
    transaction.processURI(
        "{}?{}".format(
            rule.request.uri,
            urllib.parse.urlencode(
                rule.request.query)),
        rule.request.method.upper(),
        rule.request.protocol)
    for k, v in rule.request.headers.items():
        transaction.addRequestHeader(k, v)

    body = ""
    if rule.request.cookie:
        cookie = ""
        for k, v in rule.request.cookie.items():
            cookie += " {}={};".format(k, v)
            try:
                transaction.addRequestHeader("Cookie", cookie)
            except BaseException:
                True

    if rule.request.method != "get" and rule.request.uri == "/":
        if not body and rule.request.form:
            transaction.addRequestHeader(
                "Content-Type", "application/x-www-form-urlencoded")
            for k, v in rule.request.form.items():
                body += "{}={}".format(k, v)

        if not body and rule.request.files:
            transaction.addRequestHeader(
                "Content-Type", "multipart/form-data; boundary=12345")
            body += "--12345\n"
            for v in rule.request.files:
                body += 'Content-Disposition: form-data; name="{}" filename=""\n\n'.format(
                    v["name"], v["filename"])
                body += v["data"]
            body += "--12345--"

        if not body and rule.request.xml:
            body = rule.request.xml

        if body:
            transaction.appendRequestBody(body)

    transaction.processRequestHeaders()
    transaction.processRequestBody()
    intervention = ModSecurityIntervention()
    blocked = bool(transaction.intervention(intervention))
    return rule, blocked


async def send_to_waf(args, rule):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
    rule.request.headers["User-Agent"] = ua
    files = {}
    for i in rule.request.files:
        files[i["name"]] = i["data"]
    try:
        resp = requests.request(
            rule.request.method,
            "{}{}?{}".format(
                args.host,
                rule.request.uri,
                urllib.parse.urlencode(
                    rule.request.query)),
            params=rule.request.form,
            files=files,
            headers=rule.request.headers,
            cookies=rule.request.cookie,
            verify=False)
    except BaseException:
        resp = requests.request(
            rule.request.method,
            "{}{}?{}".format(
                args.host,
                rule.request.uri,
                urllib.parse.urlencode(
                    rule.request.query)),
            params=rule.request.form,
            files=files,
            headers={
                "User-Agent": ua},
            verify=False)
    rule.request = pretty_raw_request(resp)
    return rule, resp.status_code


async def is_config_valid(fname):
    rules = Rules()
    rules.loadFromUri(fname)
    return not rules.getParserError()


async def main(loop):
    parser = argparse.ArgumentParser(description="ModSecurity rules tester")
    parser.add_argument("-f", "--folder",
                        dest="folder",
                        required=True,
                        help="Folder containing ModSecurity rules")
    parser.add_argument(
        "-u",
        "--url",
        dest="host",
        required=True,
        help="Host with WAF to send requests (e.g. https://waf.hostname)")
    parser.add_argument(
        "-t",
        "--template",
        dest="template",
        default="report.jinja2",
        help="Jinja2 report template to generate WAF testing report (default: report.html)")
    parser.add_argument("-o", "--output",
                        dest="output",
                        default="report.html",
                        help="Output file for report (default: report.html)")
    parser.add_argument("-s", "--s",
                        dest="status",
                        type=int,
                        default=403,
                        help="Stats code of blocked requests")
    parser.add_argument('--all',
                        dest='all',
                        action='store_true',
                        help='Include parse errors in the report')
    args = parser.parse_args()
    rules = []
    report = {
        "error": {
            "parsing": set(),
            "regex": {}
        },
        "results": {}
    }
    report = {
        "good": {},
        "bad": [],
        "files": set()
    }
    colorize("green", "Looking for files in {}".format(args.folder))
    for folder, subs, files in os.walk(args.folder):
        for fname in files:
            name = os.path.join(folder, fname)
            go = True
            for i in ["RESPONSE", "EXCLUSION", "EXCEPTION", "LEAKAGE"]:
                if i in name:
                    go = False
            if go and await is_config_valid(name):
                colorize("green", "Processing {}".format(name))
                report["files"].add(name)
                modsec_mm = metamodel_from_file('modsec.tx', memoization=True)
                model = None
                try:
                    model = modsec_mm.model_from_file(name)
                except Exception as err:
                    colorize("red", "Cannot parse file {}".format(name))
                    colorize("red", err)
                if model:
                    for r in model.rules:
                        if hasattr(r, 'operator') and r.operator.rx:
                            rule = None
                            rule = Rule(r)
                            rule.filename = name
                            if rule and rule.id and rule.method and rule.valid and rule.request.method:
                                rules.append(rule)
                            else:
                                if rule:
                                    rule.request = None
                                    report["bad"].append(
                                        {"rule": rule.__dict__, "error": "Failed to create valid payload", "status": 0})
    tasks = [check_mod_security(r) for r in rules]
    check_on_waf = []
    colorize("green", "Checking {} rules".format(len(tasks)))
    for task in asyncio.as_completed(tasks):
        rule, state = await task
        if state:
            check_on_waf.append(rule)
        else:
            rule.request = None
            report["bad"].append({"rule": rule.__dict__,
                                  "error": "ModSecurity didn't blocked generated payload",
                                  "status": 0})

    tasks = [send_to_waf(args, r) for r in check_on_waf]
    colorize("green", "Verifying on {} {} rules".format(args.host, len(tasks)))
    for task in asyncio.as_completed(tasks):
        rule, state = await task
        if state not in report["good"]:
            report["good"][state] = []
        report["good"][state].append(
            {"rule": rule.__dict__, "error": False, "status": state})

    colorize("green", "Saving report to file {}".format(args.output))
    report["date"] = time.strftime("%d %B %Y %H:%M:%S")
    report["total"] = len(report["bad"])
    report["args"] = args.__dict__
    report["good_count"] = 0
    for k in report["good"]:
        report["total"] += len(report["good"][k])
        report["good_count"] += len(report["good"][k])
    template = Template(open(args.template, "r").read())
    output = template.render(data=report)
    with open(args.output, "w") as f:
        f.write(output)
    if report["total"]:
        colorize("green", "Done. Total {} rules, successful {} ({}%)".format(
            report["total"],
            report["good_count"],
            100.0 * report["good_count"] / report["total"]))

loop = asyncio.get_event_loop()
future = asyncio.ensure_future(main(loop))
loop.run_until_complete(future)
loop.close()
