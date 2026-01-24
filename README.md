# Serpico

**serpico** is a security scanner for FreeBSD packages and releases that compares the versions against a list of versions marked as vulnerable, then displays vulnerability information in a JSON-compact format for easy analysis by other security tools.

## Installation

**Bleeding-edge version**:

```sh
pkg install -y python314 py311-pipx
pipx install --system-site-packages --force --global --python 3.14 git+https://github.com/DtxdF/serpico.git
```

**Stable version**:

```sh
pkg install -y py311-serpico
```

## Wazuh

The main goal of this tool is to implement vulnerability detection in FreeBSD's Wazuh, as it is currently an unsupported platform, so I have prepared some rules for alerts. There is no need to create decoders, as Wazuh already decodes the logs that are in JSON. See [ossec/etc/rules/local_rules.xml](ossec/etc/rules/local_rules.xml).

On the agent side, you must add the following to your `ossec.conf`:

```
<wodle name="command">
  <tag>serpico</tag>
  <disabled>no</disabled>
  <command>/usr/local/bin/serpico --scan-jails</command>
  <interval>12h</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

### Wazuh Dashboard

![](assets/shots/first.png)
![](assets/shots/second.png)
![](assets/shots/third.png)

Thanks to [Nicolas Curioni](https://groups.google.com/g/wazuh/c/N6-t0jTaBrY/m/8v3HMzgJBAAJ), we have a handy dashboard to display a summary of our systems' vulnerabilities. I just edited the ndjson so that the parameters match those used by Serpico.

To install **FreeBSD VD Dashboard** simply click the hamburger button and select `Dashboard Management > Saved Objects`, then import the [ndjson](wazuh-dashboard/FreeBSD_VD_Dashboard.ndjson) file.

## Documentation

* `man 1 serpico`
