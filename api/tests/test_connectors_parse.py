from app.connectors.impl import (
    parse_tenable_vulns, parse_shadowserver_rows, parse_shodan_search,
    parse_dnsdumpster, parse_generic_services, parse_nmap_xml,
)


def test_tenable_dedups_services():
    findings = [
        {"asset": {"ipv4": "10.0.0.1", "network_id": "AS1"}, "port": {"port": 443, "protocol": "TCP", "service": "www"}},
        {"asset": {"ipv4": "10.0.0.1"}, "port": {"port": 443, "protocol": "TCP"}},  # dup
        {"asset": {"ipv4": "10.0.0.1"}, "port": {"port": 53, "protocol": "UDP"}},
        {"asset": {}, "port": {"port": 22}},  # no ip -> skipped
    ]
    out = parse_tenable_vulns(findings)
    keys = {(o.ip, o.port, o.protocol) for o in out}
    assert keys == {("10.0.0.1", 443, "tcp"), ("10.0.0.1", 53, "udp")}
    assert all(o.asserts_present for o in out)


def test_shadowserver_rows():
    out = parse_shadowserver_rows([{"ip": "1.1.1.1", "port": "80", "protocol": "tcp", "service": "http"}])
    assert out[0].ip == "1.1.1.1" and out[0].port == 80 and out[0].protocol == "tcp"


def test_shodan_search():
    data = {"matches": [{"ip_str": "2.2.2.2", "port": 8443, "transport": "tcp",
                         "product": "nginx", "asn": "AS7"}]}
    out = parse_shodan_search(data)
    assert out[0].port == 8443 and out[0].service_type == "nginx" and out[0].asn == "AS7"


def test_dnsdumpster_records():
    data = {"a": [{"host": "www.x.com", "ips": [{"ip": "3.3.3.3", "asn": "AS9", "range": "3.3.3.0/24"}]}]}
    out = parse_dnsdumpster(data)
    assert out[0].entity_kind == "dns_name"
    assert out[0].fqdn == "www.x.com" and out[0].resolves_to_ip == "3.3.3.3"
    assert out[0].netblock == "3.3.3.0/24"


def test_generic_services_present_flag():
    out = parse_generic_services([{"ip": "4.4.4.4", "port": 25, "present": False}])
    assert out[0].asserts_present is False


def test_nmap_xml_open_closed():
    open_xml = '<nmaprun><host><ports><port portid="443"><state state="open"/></port></ports></host></nmaprun>'
    closed_xml = '<nmaprun><host><ports><port portid="443"><state state="closed"/></port></ports></host></nmaprun>'
    assert parse_nmap_xml(open_xml) is True
    assert parse_nmap_xml(closed_xml) is False
    assert parse_nmap_xml("not xml") is False
