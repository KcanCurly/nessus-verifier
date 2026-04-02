class PARSE_POST_HTTP_VERSION:
    def __init__(self, product, regex):
        self.product = product
        self.regex = regex
        self.versions = {}
        self.is_found = False

    def check(self, host, version):
        import re
        match = re.search(self.regex, version)
        if match:
            version = match.group(1)
            self.is_found = True
            if version not in self.versions:
                self.versions[version] = []
            self.versions[version].append(host)

    def print(self, file=None):
        for version, hosts in self.versions.items():
            print(f"{self.product} {version}:", file=file)
            for host in hosts:
                print(f"    {host}", file=file)


def get_instances():
    return [
        PARSE_POST_HTTP_VERSION("Apache HTTP Server", r"Apache/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Microsoft IIS", r"Microsoft-IIS/(\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Nginx", r"nginx/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Jetty", r"Jetty\((\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Python", r"Python/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("OpenSSL", r"OpenSSL/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Tornado", r"TornadoServer/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Werkzeug", r"Werkzeug/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("mini_httpd", r"mini_httpd/(\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("lighttpd", r"lighttpd/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("lighttpd", r"LightTPD/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Boa", r"Boa/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("Schneider WEB", r"Schneider-WEB/V(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("AvigilonOnvifNvt", r"AvigilonOnvifNvt/(\d+\.\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("lwIP", r"lwIP/(\d+\.\d+\.\d+)"),
        PARSE_POST_HTTP_VERSION("PowerStudio", r"PowerStudio v(\d+\.\d+\.\d+)"),
    ]