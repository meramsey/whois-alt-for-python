import json
import aiodns
import wizard_whois
import asyncio
from datetime import date, datetime
import requests
from requests.exceptions import Timeout, ConnectionError
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


# https://findwork.dev/blog/advanced-usage-python-requests-timeouts-retries-hooks/
class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        DEFAULT_TIMEOUT = 1
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


http = requests.Session()
# Mount  TimeoutHTTP adapter with retries it for both http and https usage
adapter = TimeoutHTTPAdapter(timeout=2.5)
retries = Retry(total=1, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
http.mount("https://", TimeoutHTTPAdapter(max_retries=retries))
http.mount("http://", TimeoutHTTPAdapter(max_retries=retries))

TIMEOUT = 1.0  # timeout in seconds
wizard_whois.net.socket.setdefaulttimeout(TIMEOUT)


def check_http(name):
    """Is the domain reachable via http?"""
    try:
        url = 'http://' + name
        http.get(url)
        return True
    except requests.exceptions.ConnectionError:
        print(f"URL {url} not reachable")
        return False


class DomainInfo:
    DEFAULT_TIMEOUT = 1  # seconds
    rdapbootstrapurl = 'https://www.rdap.net/'
    wizard_whois.net.socket.setdefaulttimeout(DEFAULT_TIMEOUT)

    def __init__(self, domain):
        self.name = domain
        self.domain = domain
        # Setup dictionary and defaults
        self.domain = domain.lower()
        self.url = 'http://' + self.domain
        self.domain_dict = {}
        self.domain_whois = {}
        self.registrar = ''
        self.registration = ''
        self.expiration = ''
        self.status = []
        self.soa = {}
        # Setup lists variables
        self.whois_nameservers = []
        self.domain_nameservers = []
        self.domain_www = []
        self.domain_mx = []
        self.domain_txt = []
        self.dns_lookup_continue = ''
        self.expired = ''
        self.dns = {}
        self.ns = []
        self.spf = ''
        self.dkim = ''
        self.dmarc = ''
        self.dnssec = {}

        # Initialize Whois and DNS
        self.get_whois_domain()
        self.check_expiration()
        self.get_domain_dns()

    def get_domain_whois_info(self):
        # "domain": "google.com"
        self.domain_dict['domain'] = self.domain
        # domain_dict['WHOIS'] = {'nameservers': None}

        try:
            self.domain_whois = wizard_whois.get_whois(self.domain)
            print(self.domain_whois)
        except:
            return False
            # pass

        # "WHOIS": {"registrar": "MarkMonitor Inc."}
        try:
            # domain_dict['WHOIS']['registrar'] = str(self.domain_whois['registrar'][0])
            # print('Registrar is :' + str(self.domain_whois['registrar'][0]))
            update_dict = {"WHOIS": {'registrar': str(self.domain_whois['registrar'][0])}}
            self.domain_dict.update(update_dict)
            self.registrar = str(self.domain_whois['registrar'][0])
        except:
            pass

        # "WHOIS": {"status": "['client delete prohibited', 'server transfer prohibited', 'server update prohibited']"
        try:
            # print(str(self.domain_whois['status'][0]).rsplit())
            whois_statuses = []
            whois_status = self.domain_whois['status']
            for status in whois_status:
                status = status.rsplit()
                # print(status[0])
                whois_statuses.append(status[0])
            # print(str(whois_statuses))
            self.domain_dict['WHOIS']['status'] = whois_statuses

        except:
            pass

        # Source "WHOIS": {"registration": "1997-09-15T04:00:00Z", "expiration": "2028-09-14T04:00:00Z"}
        try:
            self.domain_dict['WHOIS']['registration'] = str(self.domain_whois['creation_date'][0])
            self.registration = str(self.domain_whois['creation_date'][0])
        except:
            pass

        try:
            self.domain_dict['WHOIS']['expiration'] = str(self.domain_whois['expiration_date'][0])
            self.expiration = str(self.domain_whois['expiration_date'][0])
        except:
            update_dict = {"WHOIS": {'expiration': 'No Expiration Found'}}
            self.domain_dict.update(update_dict)
            self.expiration = 'No Expiration Found'
            pass

        # "WHOIS": {"secureDNS": {"delegationSigned": false}}
        try:
            domainwhois_dnssec_raw = str(self.domain_whois['raw']).split('DNSSEC: ', 1)[1]
            # print(domainwhois_dnssec_raw)
            if "signedDelegation" in domainwhois_dnssec_raw:
                # print('signedDelegation')
                # domain_dict['WHOIS']['secureDNS'] = 'signedDelegation'
                self.domain_dict['WHOIS']['secureDNS'] = {"delegationSigned": 'true'}
                self.dnssec = {"secureDNS": {"delegationSigned": 'true'}}
            elif "unsigned" in domainwhois_dnssec_raw:
                # print('unsigned')
                # domain_dict['WHOIS']['secureDNS'] = 'unsigned'
                self.domain_dict['WHOIS']['secureDNS'] = {"delegationSigned": 'false'}
                self.dnssec = {"secureDNS": {"delegationSigned": 'false'}}
        except:
            pass

        #  "WHOIS": {"nameservers": [["NS1.GOOGLE.COM", "216.239.32.10"], ["NS2.GOOGLE.COM", "216.239.34.10"]]}
        try:
            loop = asyncio.get_event_loop()
            resolver = aiodns.DNSResolver(loop=loop)

            async def query(name, query_type):
                return await resolver.query(name, query_type)

            for nameserver in self.domain_whois['nameservers']:
                # print(ns)
                ns = nameserver.lower()
                coro = query(ns, 'A')
                result = loop.run_until_complete(coro)
                # print(result)
                ip = str(result[0].host)
                # print(ns, ip)
                self.whois_nameservers.append([str(ns), str(ip)])
            self.domain_dict['WHOIS']['nameservers'] = self.whois_nameservers
        except:
            pass

    def check_expiration(self):
        """Is the domain active?. Also catches when tld does not have an expiration. Returns True if not expired or has
        no expiration date """
        try:
            past = datetime.strptime(str(self.domain_dict['WHOIS']['expiration']), "%Y-%m-%d %H:%M:%S")
            present = datetime.now()
            if past.date() < present.date():
                # self.DomainExpiresLabel.setText("Expired:")
                # self.DomainExpiresValue.setText('')
                # self.DomainExpiresValue.setStyleSheet("QLabel { background-color : red}")
                print('Domain is expired or unregistered')
                return False
            else:
                print('Domain is not expired')
                return True
        except:
            var = KeyError == 'WHOIS'
            print('No Expiration Found')
            # domain_dict['WHOIS']['expiration'] = 'No Expiration Found'
            return True
            pass

    def get_domain_rdap_info(self):
        request = self.rdapbootstrapurl + 'domain/' + self.domain
        try:
            domain_response = http.get(request).text
            # print(request)
            # print(domain_response)
            self.domain_whois = json.loads(str(domain_response))
            # print(json.dumps(self.domain_whois, indent=4))
            return self.domain_whois
        except:
            print('RDAP Lookup Failed')
            return False

    def create_domain_dict_rdap(self):
        # "domain": "google.com"
        self.domain_dict['domain'] = self.domain

        # rdapsource
        self.domain_dict['rdapurl'] = self.rdapbootstrapurl + 'domain/' + self.domain

        # "WHOIS": {"status": "['client delete prohibited', 'server transfer prohibited', 'server update prohibited']"
        try:
            self.domain_dict['WHOIS'] = {'status': str(self.domain_whois['status'])}
        except:
            pass

        # "WHOIS": {"registrar": "MarkMonitor Inc."}
        try:
            self.domain_dict['WHOIS']['registrar'] = str(self.domain_whois["entities"][0]['vcardArray'][1][1][3])
            self.registrar = str(self.domain_whois["entities"][0]['vcardArray'][1][1][3])
        except:
            pass

        # "WHOIS": {"registration": "1997-09-15T04:00:00Z", "expiration": "2028-09-14T04:00:00Z"}
        try:
            for event in self.domain_whois['events']:
                # print(event)
                event_action = event['eventAction']
                event_date = event['eventDate']
                if event_action == 'registration':
                    self.domain_dict['WHOIS']['registration'] = event_date.replace("T", " ").replace("Z", "")
                    self.registration = self.domain_dict['WHOIS']['registration']
                elif event_action == 'expiration':
                    self.domain_dict['WHOIS']['expiration'] = event_date.replace("T", " ").replace("Z", "")
                    self.expiration = self.domain_dict['WHOIS']['expiration']
                    # print(event_action, event_date)
                # print(event.eventAction, event.eventDate)
        except:
            pass

        # "WHOIS": {"secureDNS": {"delegationSigned": false}}
        try:
            self.domain_dict['WHOIS']['secureDNS'] = str(self.domain_whois['secureDNS'])
            self.dnssec = self.domain_dict['WHOIS']['secureDNS']
        except:
            pass

        #  "WHOIS": {"nameservers": [["NS1.GOOGLE.COM", "216.239.32.10"], ["NS2.GOOGLE.COM", "216.239.34.10"]]}
        try:
            loop = asyncio.get_event_loop()
            resolver = aiodns.DNSResolver(loop=loop)

            async def query(name, query_type):
                return await resolver.query(name, query_type)

            for nameserver in self.domain_whois['nameservers']:
                # print(nameserver['ldhName'])
                ns = nameserver['ldhName'].lower()
                coro = query(ns, 'A')
                result = loop.run_until_complete(coro)
                # print(result)
                ip = str(result[0].host)
                # print(ns, ip)
                self.whois_nameservers.append([ns, ip])

            self.domain_dict['WHOIS']['nameservers'] = self.whois_nameservers
        except:
            pass

    def get_domain_dns(self):
        site = self.domain

        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)

        async def query(name, query_type):
            return await resolver.query(name, query_type)

        try:
            res_ns = loop.run_until_complete(resolver.query(site, 'NS'))
            for elem in res_ns:
                # print(elem.host)
                ns = str(elem.host)
                coro = query(ns, 'A')
                result = loop.run_until_complete(coro)
                # print(result)
                ip = str(result[0].host)
                self.ns.append(ns)
                self.domain_nameservers.append([ns, ip])
            self.dns_lookup_continue = True
        except:
            self.dns_lookup_continue = False
            pass

        if self.dns_lookup_continue:
            try:
                # SOA query the host's DNS
                res_soa = loop.run_until_complete(resolver.query(site, 'SOA'))
                # print(res_soa)
                # for elem in res_soa:
                # print(str(res_soa.nsname) + " " + str(res_soa.hostmaster) + " " + str(res_soa.serial))
                domain_soa_dict = {"DNS": {
                    "SOA": {"nsname": str(res_soa.nsname), "hostmaster": str(res_soa.hostmaster),
                            "serial": str(res_soa.serial),
                            "refresh": str(res_soa.refresh), "retry": str(res_soa.retry),
                            "expires": str(res_soa.expires),
                            "minttl": str(res_soa.minttl), "ttl": str(res_soa.ttl)}}}
                self.domain_dict.update(domain_soa_dict)
                # print(domain_dict)
                self.soa = self.domain_dict['DNS']['SOA']
            except:
                pass

            try:
                # WWW query the host's DNS
                res_cname = loop.run_until_complete(resolver.query('www.' + site, 'CNAME'))
                www_name = 'www.' + site
                # print(www_name + ' ==> ' + res_cname.cname)
                self.domain_www.append(['CNAME', str(www_name), str(res_cname.cname)])
            except:
                pass

            try:
                res_www = loop.run_until_complete(resolver.query('www.' + site, 'A'))
                for elem in res_www:
                    # print(elem)
                    www_name = 'www.' + site
                    # print('www.' + site + ' ==> ' + elem.host)
                    self.domain_www.append(['A', str(www_name), str(elem.host)])
            except:
                pass

            try:
                res_a = loop.run_until_complete(resolver.query(site, 'A'))
                for elem in res_a:
                    # print(elem.host)
                    domain_a = elem.host
                    self.domain_www.append(['A', str(site), str(domain_a)])
            except:
                pass

            try:
                res_aaaa = loop.run_until_complete(resolver.query(site, 'AAAA'))
                for elem in res_aaaa:
                    # print(elem.host)
                    domain_aaaa = elem.host
                    self.domain_www.append(['AAAA', str(site), str(domain_aaaa)])
            except:
                pass

            try:
                # MX query the host's DNS
                res_mx = loop.run_until_complete(resolver.query(site, 'MX'))
                for elem in res_mx:
                    # print(res_mx)
                    # print(str(elem.host) + ' has preference ' + str(elem.priority))
                    self.domain_mx.append(['MX', str(elem.host), str(elem.priority)])
            except:
                pass

            try:
                res_txt = loop.run_until_complete(resolver.query(site, 'TXT'))
                for elem in res_txt:
                    # print(str(elem.text))
                    self.domain_txt.append(['TXT', str(site), str(elem.text)])
                    if 'v=spf' in str(elem.text):
                        self.spf = str(elem.text)
            except:
                pass

            try:
                self.domain_dict['DNS']['NS'] = self.domain_nameservers
            except:
                print('NS lookups failed')
                pass
            try:
                self.domain_dict['DNS']['WWW'] = self.domain_www
            except:
                print('WWW lookup failed')
                pass

            try:
                self.domain_dict['DNS']['MX'] = self.domain_mx
            except:
                print('MX lookup failed')
                pass

            try:
                self.domain_dict['DNS']['TXT'] = self.domain_txt
            except:
                print('TXT lookup failed')
                pass

        self.dns = self.domain_dict['DNS']

    def get_whois_domain(self):
        if self.get_domain_rdap_info():
            self.create_domain_dict_rdap()
        else:
            self.get_domain_whois_info()

# How to use
# domain = DomainInfo('wizardassistant.com')
# print(f"{domain.domain}'s registrar is {domain.registrar} ")
# print(f"Whois Namservers: {domain.whois_nameservers} ")
# print('')
# print(f"WWW records: {domain.domain_www}")
# print(f"SOA record: {domain.soa['serial']}")
# print('')
# print(f"DNS Nameservers: {domain.ns} ")
# print(f"Domain's SPF: {domain.spf} ")
# print(f"Domain Expiration: {domain.expiration} ")
# for key, value in domain.dns.items():
#    print(key, ':', value)
