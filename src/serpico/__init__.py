# BSD 3-Clause License
#
# Copyright (c) 2026, Jesús Daniel Colmenares Oviedo <DtxdF@disroot.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import time
import os
import subprocess
import tempfile
import re
import platform
import sys
import json
import traceback
import requests
import nvdlib
import xmltodict

# Regex
REGEX_UNSUPPORTED_RELEASE = r"\d+(?:(?:\.\d+)?-(?:PRERELEASE|CURRENT))"
REGEX_NON_STABLE_RELEASES = r"\((?:stable|releng)/\d+(?:\.\d+)?, (\d+(?:\.\d+)?-(?:[a-zA-Z]+\d+|[a-zA-Z]+\d*\-p\d+))\)"
REGEX_STABLE_RELEASES = r"(?:stable)/\d+(?:\.\d+)?-n\d+"
REGEX_VULNERABILITIES = r"CVE Name:\s+(CVE-.+)"
REGEX_STABLE_RELEASE = r"\d+(\.\d+)?-STABLE"
REGEX_NREVISION = r"^\d+-n(\d+)(?:-\w+)?$"
REGEX_NON_STABLE_RELEASE = r"^(\d+)\.(\d+)-(\w+)(-p\d+)?$"
REGEX_META = r"^([^=]+)=(.+)$"
REGEX_FREEBSD_RELEASE = r"^(\d+\.\d+-\w+)(?:-p\d+)?$"
REGEX_STAGE_LEVEL = r"^[a-zA-Z]+(\d)$"
REGEX_PATCH_LEVEL = r"^-p(\d+)$"

# Scanner methods
VULN_SCANNER_PACKAGE = "package"
VULN_SCANNER_RELEASE = "release"
VULN_SCANNER_ALL = "all"
VULN_SCANNER = {
    VULN_SCANNER_ALL : [VULN_SCANNER_PACKAGE, VULN_SCANNER_RELEASE],
    VULN_SCANNER_PACKAGE : [VULN_SCANNER_PACKAGE],
    VULN_SCANNER_RELEASE : [VULN_SCANNER_RELEASE]
}

# URLs
SECURITY_FEED = "https://www.freebsd.org/security/feed.xml"

# key-mapping
KEY_PACKAGE_NAME = "serpico.package.name"
KEY_PACKAGE_VERSION ="serpico.package.version"
KEY_PACKAGE_CATEGORY = "serpico.package.category"
KEY_VULN_ID = "serpico.vulnerability.cve"
KEY_VULN_DESCRIPTION = "serpico.vulnerability.description"
KEY_VULN_SEVERITY = "serpico.vulnerability.severity"
KEY_VULN_SCORE = "serpico.vulnerability.score"
KEY_VULN_REFERENCE = "serpico.vulnerability.reference"
KEY_VULN_PUBLISHED_AT = "serpico.vulnerability.published_at"
KEY_VULN_STATUS = "serpico.vulnerability.status"
KEY_JAIL = "serpico.jail"

# Default language for CVE descriptions
CVE_DESCRIPTION_LANG = "en"
CVE_DESCRIPTION_LANG_FALLBACK = "en"

# Time / Date
STRFTIME_STARTING_TIME = "%Y-%m-%d %H:%M %Z"

# Executables
PKG_EXECUTABLE = "/usr/sbin/pkg"
JLS_EXECUTABLE = "/usr/sbin/jls"
FREEBSD_VERSION_EXECUTABLE = "/bin/freebsd-version"

# Meta keys
META_SERPICO_ENABLED = "serpico"

def main():
    try:
        start()

    except Exception as err:
        print_pretty_exc(err)
        sys.exit(1)

def start():
    myuid = os.getuid()

    if myuid != 0:
        log_err("Serpico is designed to run as root and your UID (%d) does not meet this requirement." % myuid)
        sys.exit(1)

    release = is_unsupported_release()

    if release is not None:
        log_err("Unsupported release: %s" % release)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="serpico",
        description="Security scanner for FreeBSD packages and releases",
        add_help=False
    )
    parser.add_argument("--scan-jails", action="store_true")
    parser.add_argument("--no-fetch-audit-db", action="store_true")
    parser.add_argument("--category", default=VULN_SCANNER_ALL)
    parser.add_argument("--security-feed", default=SECURITY_FEED)
    parser.add_argument("--nvd-api-key")
    parser.add_argument("--nvd-api-key-file")
    parser.add_argument("--nvd-request-delay", type=float)
    parser.add_argument("--cve-description-lang", default=CVE_DESCRIPTION_LANG)

    args = parser.parse_args()

    nvd_api_key_file = args.nvd_api_key_file

    if nvd_api_key_file is not None:
        with open(nvd_api_key_file) as fd:
            nvd_api_key = fd.readline().strip()
    else:
        nvd_api_key = args.nvd_api_key

    categories = args.category
    categories = categories.split(",")

    scan_methods = []

    for category in categories:
        if category not in VULN_SCANNER:
            log_err("Invalid category: %s" % category)
            sys.exit(1)

        scan_methods.extend(VULN_SCANNER[category])

    scan_methods = set(scan_methods)

    if VULN_SCANNER_PACKAGE in scan_methods and not is_pkg_bootstrapped():
        log_err("Scan category '%s' requires pkg(8) to be bootstrapped!" % VULN_SCANNER_PACKAGE)
        sys.exit(1)

    jails = []

    if args.scan_jails:
        jails = get_jails()

    for scan_method in scan_methods:
        if scan_method == VULN_SCANNER_PACKAGE:
            run_package_scan({
                "no-fetch-audit-db" : args.no_fetch_audit_db,
                "cve-description-lang" : args.cve_description_lang,
                "nvd-api-key" : nvd_api_key,
                "nvd-request-delay" : args.nvd_request_delay
            })

            for jail, meta in jails.items():
                run_package_scan({
                    "no-fetch-audit-db" : args.no_fetch_audit_db,
                    "cve-description-lang" : args.cve_description_lang,
                    "nvd-api-key" : nvd_api_key,
                    "nvd-request-delay" : args.nvd_request_delay,
                    "jail" : jail
                })

        elif scan_method == VULN_SCANNER_RELEASE:
            run_release_scan({
                "security-feed" : args.security_feed,
                "nvd-api-key" : nvd_api_key,
                "nvd-request-delay" : args.nvd_request_delay,
                "cve-description-lang" : args.cve_description_lang
            })

            for jail, meta in jails.items():
                run_release_scan({
                    "security-feed" : args.security_feed,
                    "nvd-api-key" : nvd_api_key,
                    "nvd-request-delay" : args.nvd_request_delay,
                    "cve-description-lang" : args.cve_description_lang,
                    "jail" : jail
                })

    sys.exit(0)

def run_release_scan(options):
    jail = options.get("jail")

    log_info("Starting Serpico ( category:%s, jail:%s ) at %s" % (
        VULN_SCANNER_RELEASE, jail, time.strftime(STRFTIME_STARTING_TIME)))

    found = 0
    parsed = parse_security_feed(options)

    starting_time = time.time()

    for info in parsed:
        json_info = json.dumps(info)

        print(json_info)

        found += 1

    ending_time = time.time() - starting_time

    log_warn("Serpico done: found %d vulnerabilities in %g seconds" % (
        found, ending_time))

def parse_security_feed(options):
    security_feed = options["security-feed"]
    cve_description_lang = options["cve-description-lang"]
    nvd_api_key = options["nvd-api-key"]
    nvd_request_delay = options["nvd-request-delay"]
    jail = options.get("jail")

    log_info("Reading security feed from '%s'" % security_feed)

    content = read_from(security_feed)

    parsed = xmltodict.parse(content, disable_entities=False)

    if "rss" not in parsed \
            or "channel" not in parsed["rss"] \
            or "item" not in parsed["rss"]["channel"] \
            or not isinstance(parsed["rss"]["channel"]["item"], list):
        log_warn("Security feed seems to be invalid or incomplete!")

        return

    items = parsed["rss"]["channel"]["item"]

    for item in items:
        title = item["title"]
        link = item["link"]

        log_info("Reading security advisory '%s' from '%s'" % (title, link))

        security_advisory = read_from(link)

        vulnerabilities = get_vulnerabilities_from_advisory(security_advisory)

        # Ignore errata notice
        if len(vulnerabilities) == 0:
            continue

        if not is_vulnerable(security_advisory, jail=jail):
            continue

        platform_release = get_platform_release(jail=jail)
        platform_version = get_platform_version(jail=jail)

        log_warn("Found %d vulnerabilities in '%s' (%s)" % (len(vulnerabilities), platform_release, platform_version))

        for vulnerability in vulnerabilities:
            cve_info = get_cve_info(vulnerability, api_key=nvd_api_key,
                delay=nvd_request_delay)

            # XXX: This may be due to a reserved state, so we could analyze the
            #      security warning ourselves.
            if cve_info is None:
                log_warn("No information was found for '%s'" % vulnerability)
                continue

            output = {
                KEY_PACKAGE_NAME : platform_release,
                KEY_PACKAGE_VERSION : platform_version,
                KEY_PACKAGE_CATEGORY : VULN_SCANNER_RELEASE,
                KEY_VULN_ID : vulnerability,
                KEY_VULN_DESCRIPTION : get_cve_description(cve_info, cve_description_lang),
                KEY_VULN_SEVERITY : get_cve_severity(cve_info),
                KEY_VULN_SCORE : get_cve_score(cve_info),
                KEY_VULN_REFERENCE : cve_info.url,
                KEY_VULN_PUBLISHED_AT : cve_info.published,
                KEY_VULN_STATUS : cve_info.vulnStatus,
                KEY_JAIL : jail
            }

            yield output

def run_package_scan(options):
    jail = options.get("jail")

    log_info("Starting Serpico ( category:%s, jail:%s ) at %s" % (
        VULN_SCANNER_PACKAGE, jail, time.strftime(STRFTIME_STARTING_TIME)))

    found = 0
    parsed = _run_package_scan(options)

    starting_time = time.time()

    for info in parsed:
        json_info = json.dumps(info)

        print(json_info)

        found += 1

    ending_time = time.time() - starting_time

    log_warn("Serpico done: found %d vulnerabilities in %g seconds" % (
        found, ending_time))

def _run_package_scan(options):
    nvd_api_key = options["nvd-api-key"]
    nvd_request_delay = options["nvd-request-delay"]
    cve_description_lang = options["cve-description-lang"]
    no_fetch_audit_db = options["no-fetch-audit-db"]
    jail = options.get("jail")

    if not no_fetch_audit_db:
        fetch_audit_db(jail=jail)

    pkg_audit = get_pkg_audit(jail=jail)

    if pkg_audit is None:
        return

    pkg_count = pkg_audit["pkg_count"]

    if pkg_count == 0:
        return

    packages = pkg_audit["packages"]

    for pkg_name, pkg_info in packages.items():
        if "issues" not in pkg_info \
                or "version" not in pkg_info:
            continue

        pkg_version = pkg_info["version"]

        issues = pkg_info["issues"]

        for issue in issues:
            if "cve" not in issue:
                continue

            vulnerabilities = issue["cve"]

            log_warn("Found %d vulnerabilities in '%s' (%s)" % (len(vulnerabilities), pkg_name, pkg_version))

            for vulnerability in vulnerabilities:
                cve_info = get_cve_info(vulnerability, api_key=nvd_api_key,
                    delay=nvd_request_delay)

                if cve_info is None:
                    log_warn("No information was found for '%s'" % vulnerability)
                    continue

                output = {
                    KEY_PACKAGE_NAME : pkg_name,
                    KEY_PACKAGE_VERSION : pkg_version,
                    KEY_PACKAGE_CATEGORY : VULN_SCANNER_PACKAGE,
                    KEY_VULN_ID : vulnerability,
                    KEY_VULN_DESCRIPTION : get_cve_description(cve_info, cve_description_lang),
                    KEY_VULN_SEVERITY : get_cve_severity(cve_info),
                    KEY_VULN_SCORE : get_cve_score(cve_info),
                    KEY_VULN_REFERENCE : cve_info.url,
                    KEY_VULN_PUBLISHED_AT : cve_info.published,
                    KEY_VULN_STATUS : cve_info.vulnStatus,
                    KEY_JAIL : jail
                }

                yield output

def get_pkg_audit(jail=None):
    cmd = [PKG_EXECUTABLE]

    if jail is not None:
        cmd.extend(["-j", jail])

    cmd.extend(["audit", "-Rjson-compact"])

    pkg_audit = subprocess.run(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True)

    try:
        pkg_audit_json = json.loads(pkg_audit.stdout)

    except json.decoder.JSONDecodeError:
        stdout = pkg_audit.stderr.strip()

        if jail is None:
            log_warn("pkg-audit(8): %s" % stdout)
        else:
            log_warn("pkg-audit(8) (jail:%s): %s" % (jail, stdout))

        return

    else:
        return pkg_audit_json

def fetch_audit_db(jail=None):
    cmd = [PKG_EXECUTABLE]

    if jail is not None:
        cmd.extend(["-j", jail])

    cmd.extend(["audit", "-F"])

    pkg_audit_fetch = subprocess.run(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True)

    for l in pkg_audit_fetch.stdout.splitlines():
        if jail is None:
            log_warn("pkg-audit(8): %s" % l)

        else:
            log_warn("pkg-audit(8) (jail:%s): %s" % (jail, l))

def get_cve_score(cve_info):
    vulnerability = cve_info.id
    (_, score, _) = cve_info.score

    if score is None:
        score = 0.0

        log_warn("Score for '%s' has not been found!" % vulnerability)

    return score

def get_cve_severity(cve_info):
    vulnerability = cve_info.id
    (_, _, severity) = cve_info.score

    if severity is None:
        severity = ""

        log_warn("Severity for '%s' has not been found!" % vulnerability)

    return severity

def get_cve_description(cve_info, lang):
    vulnerability = cve_info.id
    descriptions = cve_info.descriptions

    if len(descriptions) == 0:
        log_warn("There is no descriptions available for '%s'" % vulnerability)
        return ""

    fallback_lang = CVE_DESCRIPTION_LANG_FALLBACK
    fallback_description = None

    for description in descriptions:
        if description.lang == fallback_lang:
            fallback_description = description.value

        if description.lang == lang:
            return description.value

    if fallback_description is None:
        log_warn("There is no descriptions available for '%s'" % vulnerability)
        return ""

    return fallback_description

def get_cve_info(vulnerability, api_key=None, delay=None):
    cve_info = nvdlib.searchCVE(cveId=vulnerability, key=api_key, delay=delay, limit=1)

    if len(cve_info) == 0:
        return

    return cve_info[0]

def is_pkg_bootstrapped():
    return subprocess.run([PKG_EXECUTABLE, "-N"], stderr=subprocess.DEVNULL).returncode == 0

def is_vulnerable(content, jail=None):
    if jail is None and is_stable_release():
        for corrected in get_stable_releases_from_advisory(content):
            vulnerable = is_stable_vulnerable(corrected)

            if vulnerable is None:
                continue

            return vulnerable

    else:
        for corrected in get_non_stable_releases_from_advisory(content):
            vulnerable = is_non_stable_vulnerable(corrected, jail=jail)

            if vulnerable is None:
                continue

            return vulnerable

    return False

def is_non_stable_vulnerable(release, jail=None):
    corrected_parsed = re.findall(REGEX_NON_STABLE_RELEASE, release)

    if len(corrected_parsed) == 0:
        log_warn("Invalid release '%s'" % release)
        return False

    (major, minor, stage, patch) = corrected_parsed[0]

    current = get_platform_version(jail=jail)
    current_parsed = re.findall(REGEX_NON_STABLE_RELEASE, current)

    if len(current_parsed) == 0:
        log_warn("Invalid release '%s'" % current)
        return False

    (current_major, current_minor, current_stage, current_patch) = current_parsed[0]

    if current_major != major \
            or current_minor != minor:
        return

    if current_stage == "RELEASE" \
            and stage != "RELEASE":
        return

    if current_stage.startswith("ALPHA"):
        stage_level = get_stage_level(stage)
        current_stage_level = get_stage_level(current_stage)

        return current_stage_level < stage_level

    elif current_stage.startswith("BETA") \
            or current_stage.startswith("RC"):
        if current_stage.startswith("BETA") \
                and stage.startswith("RC"):
            return True

        if current_stage.startswith("RC") \
                and stage.startswith("BETA"):
            return

        stage_level = get_stage_level(stage)
        current_stage_level = get_stage_level(current_stage)

        if current_stage_level < stage_level:
            return True

        else:
            patch_level = get_patch_level(patch)
            current_patch_level = get_patch_level(current_patch)

            if patch_level is None:
                return False

            if current_patch_level is None:
                return True

            return current_patch_level < patch_level

    elif current_stage == "RELEASE":
        patch_level = get_patch_level(patch)
        current_patch_level = get_patch_level(current_patch)

        if patch_level is None:
            log_warn("A corrected release must contain the patch level! (jail:%s, corrected:%s)" % (
                jail, release))
            return False

        if current_patch_level is None:
            return True

        return current_patch_level < patch_level

    else:
        log_warn("Unsupported stage '%s' (jail:%s, corrected:%s)" % (current_stage, jail, release))
        return False

def get_patch_level(patch):
    patch_level = re.findall(REGEX_PATCH_LEVEL, patch)

    if len(patch_level) == 0:
        return

    return patch_level

def get_stage_level(stage):
    stage_level = re.findall(REGEX_STAGE_LEVEL, stage)

    if len(stage_level) == 0:
        return

    stage_level = int(stage_level[0])

    return stage_level

def is_stable_vulnerable(release):
    (_, corrected_revision) = release.split("/", 1)

    current_revision = get_revision_from_release()

    # XXX: This will not work at FreeBSD 1xx.x.
    if int(current_revision[:2]) != int(corrected_revision[:2]):
        return

    corrected_nrevision = re.findall(REGEX_NREVISION, corrected_revision)[0]
    corrected_nrevision = int(corrected_nrevision)
    current_nrevision = get_nrevision_from_release()

    return current_nrevision < corrected_nrevision

def get_nrevision_from_release():
    revision = get_revision_from_release()
    nrevision = re.findall(REGEX_NREVISION, revision)[0]
    nrevision = int(nrevision)

    return nrevision

def get_revision_from_release():
    version = get_platform_version()
    (_, revision) = version.split(" ")[2].split("/", 1)

    return revision

def get_vulnerabilities_from_advisory(content):
    match = re.findall(REGEX_VULNERABILITIES, content)

    if len(match) == 0:
        return []

    vulnerabilities = match[0].split(",")
    vulnerabilities = [v.strip() for v in vulnerabilities]

    return vulnerabilities

def get_non_stable_releases_from_advisory(content):
    return re.findall(REGEX_NON_STABLE_RELEASES, content)

def get_stable_releases_from_advisory(content):
    return re.findall(REGEX_STABLE_RELEASES, content)

def read_from(file_):
    content = requests.get(file_).text

    return content

def is_stable_release():
    release = get_platform_release()

    is_stable = re.match(REGEX_STABLE_RELEASE, release) is not None

    return is_stable

def is_unsupported_release():
    release = get_platform_release()

    if re.match(REGEX_UNSUPPORTED_RELEASE, release) is None:
        return
    
    return release

def get_platform_release(jail=None):
    if jail is None:
        return platform.release()

    freebsd_version = get_platform_version(jail=jail)
    
    if freebsd_version is None:
        return

    freebsd_release = re.findall(REGEX_FREEBSD_RELEASE, freebsd_version)

    if len(freebsd_release) == 0:
        log_warn("Invalid FreeBSD version from jail '%s': %s" % (freebsd_version, jail))
        return

    freebsd_release = freebsd_release[0]

    return freebsd_release

def get_platform_version(jail=None):
    if jail is None:
        return platform.version()

    freebsd_version = subprocess.run([FREEBSD_VERSION_EXECUTABLE, "-j", jail],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True)

    if freebsd_version.returncode != 0:
        log_warn("Can't get FreeBSD version from jail '%s': %s" % (jail, freebsd_version.stdout))
        return

    platform_version = freebsd_version.stdout.strip()

    return platform_version

def get_jails():
    jls = subprocess.run([JLS_EXECUTABLE, "--libxo", "json", "name", "meta"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    jls_json = json.loads(jls.stdout)
    jls_output_version = int(jls_json["__version"])

    if jls_output_version == 2:
        return get_jails_v2(jls_json)

    else:
        raise NotImplementedError("I'm not designed to parse the output of jls(8) in this version (%d)" % jls_output_version)

def get_jails_v2(info):
    jail_dict = {}
    jail_information = info["jail-information"]["jail"]

    for info in jail_information:
        name = info["name"]
        meta = info["meta"]
        meta_values = meta.splitlines()

        meta_dict = {}

        for meta_value in meta_values:
            meta_info = re.findall(REGEX_META, meta_value)

            if len(meta_info) == 0:
                continue

            (meta_key, meta_value) = meta_info[0]

            meta_dict[meta_key] = meta_value

        if META_SERPICO_ENABLED not in meta_dict:
            continue

        jail_dict[name] = meta_dict

    return jail_dict

def log_info(m):
    print("===> %s" % m, file=sys.stderr)

def log_err(m):
    print("###> %s" % m, file=sys.stderr)

def log_warn(m):
    print("##!> %s" % m, file=sys.stderr)

def print_pretty_exc(exc):
    print("Exception:", file=sys.stderr)
    print("", "type:", exc.__class__.__name__, file=sys.stderr)
    print("", "error:", exc, file=sys.stderr)

    with tempfile.NamedTemporaryFile(prefix="serpico", mode="w", delete=False) as fd:
        print("", "file:", fd.name, file=sys.stderr)
        traceback.print_exc(file=fd)

if __name__ == "__main__":
    main()
