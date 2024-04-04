import requests

class OWASPPentest:
    def __init__(self, target_url):
        self.target_url = target_url

    def test_ssrf(self):
        # Simple test for SSRF
        print("Testing for SSRF...")
        payload = {'url': 'http://example.com'}
        response = requests.get(self.target_url, params=payload)
        if "example.com" in response.text:
            print("Potential SSRF vulnerability detected.")
        else:
            print("No SSRF vulnerability detected.")

    def test_injection(self):
        # Simple SQL Injection Test
        print("Testing for Injection...")
        sql_payload = "' OR '1'='1"
        response = requests.get(f"{self.target_url}?query={sql_payload}")
        if "database error" in response.text.lower():
            print("Potential SQL Injection vulnerability detected.")
        else:
            print("No SQL Injection vulnerability detected.")

    def test_security_misconfiguration(self):
        # Check for common misconfigurations
        print("Testing for Security Misconfiguration...")
        headers = requests.get(self.target_url).headers
        if 'X-Powered-By' in headers or 'Server' in headers:
            print("Potential Security Misconfiguration detected (revealing server info).")
        else:
            print("No obvious Security Misconfiguration detected.")

    def test_broken_access_control(self):
          # This is a rudimentary example and must be tailored to the specific application.
        print("Testing for Broken Access Control...")

        # List of endpoints that should require authorization
        protected_endpoints = [
            "/admin",
            "/user/settings",
            "/user/data"
        ]
        for endpoint in protected_endpoints:
            url = f"{self.target_url}{endpoint}"
            response = requests.get(url)
            if response.status_code != 403 and response.status_code != 401:
                print(f"Potential Broken Access Control detected at {url}")
            else:
                print(f"Access control enforced at {url}")

    def test_cryptographic_failures(self):
        # Check for cryptographic issues like weak SSL/TLS
        print("Testing for Cryptographic Failures...")
        try:
            response = requests.get(self.target_url, verify=True)
            if 'https' not in self.target_url:
                print("Potential Cryptographic Failure detected (Non-HTTPS connection).")
            else:
                print("No obvious Cryptographic Failure detected.")
        except requests.exceptions.SSLError:
            print("Potential Cryptographic Failure detected (SSL Error).")

    def run_all_tests(self):
        self.test_ssrf()
        self.test_injection()
        self.test_security_misconfiguration()
        self.test_broken_access_control()
        self.test_cryptographic_failures()


def main():
    print("OWASP Top Ten Penetration Testing Tool")
    target_url = input("Enter the target URL: ")
    pentest = OWASPPentest(target_url)
    pentest.run_all_tests()

if __name__ == "__main__":
    main()
