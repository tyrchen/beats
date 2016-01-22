from packetbeat import BaseTest

"""
Tests for checking the hide_keywords options.
"""


class Test(BaseTest):

    def test_http_hide_post(self):
        """
        Should be able to strip the password from
        a POST request.
        """
        self.render_config_template(
            http_hide_keywords=["pass", "password"]
        )
        self.run_packetbeat(pcap="hide_secret_POST.pcap",
                            debug_selectors=["http", "httpdetailed"])
        objs = self.read_output()

        assert len(objs) == 1
        o = objs[0]
        print("hello world!", o)
        assert o["type"] == "http"
        assert o["params.pass"] == "xxxxx"
        assert o["params.user"] == "monica"
        assert o["path"] == "/login"
        for _, val in o.items():
            if isinstance(val, basestring):
                assert "secret" not in val

    def test_http_hide_get(self):
        """
        Should be able to strip the password from
        a GET request.
        """
        self.render_config_template(
            http_hide_keywords=["pass", "password"]
        )
        self.run_packetbeat(pcap="hide_secret_GET.pcap",
                            debug_selectors=["http", "httpdetailed"])
        objs = self.read_output()

        assert len(objs) == 1
        o = objs[0]
        print("hello world!", o)
        assert o["type"] == "http"
        assert o["params.pass"] == "xxxxx"
        assert o["params.user"] == "monica"

        assert o["path"] == "/login"
        for _, val in o.items():
            if isinstance(val, basestring):
                assert "secret" not in val

    def test_http_hide_post_default(self):
        """
        By default nothing is stripped.
        """
        self.render_config_template()
        self.run_packetbeat(pcap="hide_secret_POST.pcap",
                            debug_selectors=["http", "httpdetailed"])
        objs = self.read_output()

        assert len(objs) == 1
        o = objs[0]
        assert o["type"] == "http"
        assert o["params.pass"] == "secret"
        assert o["params.user"] == "monica"



        assert o["path"] == "/login"
