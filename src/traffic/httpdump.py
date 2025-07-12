import json
import os, sys

sys.path.append("src")
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import io
from config import traffic_output_dir


def item(package_name, id, url, method, headers, content, log=""):
    return {
        "package_name": package_name,
        "traffic_id": id,
        "url": url,
        "request_method": method,
        "headers": headers,
        "content": content,
        "encrypt_flag": "",
        "third_party_flag": "1",
        "plaintext": "",
        "hook_func_signature": "",
        "traffic_keyword": "",
        "log": log,
    }


class HTTPDump:
    def __init__(self) -> None:
        self.pkg_name = ""
        self.apk_name = ""  # cannot initialized with options here

    def load(self, loader):
        loader.add_option(
            name="pkg_name",
            typespec=str,
            default="",
            help="Add a count header to responses",
        )

        loader.add_option(
            name="apk_name",
            typespec=str,
            default="",
            help="Add a count header to responses",
        )

    def request(self, flow: http.HTTPFlow):
        if self.pkg_name == "":
            self.pkg_name = ctx.options.pkg_name if len(ctx.options.pkg_name) > 0 else ""
        if self.apk_name == "":
            self.apk_name = ctx.options.apk_name if len(ctx.options.apk_name) > 0 else ""
        flow_id = flow.id
        flow_url = flow.request.url
        query2dict = {}
        for k, v in flow.request.query.items():
            query2dict[k] = v
        request_content = None
        try:
            request_content = flow.request.content.decode("utf-8")
        except Exception as e:
            try:
                request_content = flow.request.content.decode("latin1")
            except Exception as e:
                request_content = f"RAW_CONTENT_{flow.request.raw_content.hex()}"

        flow_content = {"query": query2dict, "content": request_content}
        headers_dict = {}
        for k, v in flow.request.headers.items():
            headers_dict[k] = v
        flow_item = item(self.pkg_name, flow_id, flow_url, flow.request.method, headers_dict, str(flow_content))
        with open(
            os.path.join(traffic_output_dir, f"{self.pkg_name}-{self.apk_name}-simple.json"),
            "a",
            encoding="utf-8",
        ) as f:
            f.write(json.dumps(flow_item, indent=4, ensure_ascii=False) + ",\n")

    def running(self):
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        if self.pkg_name == "":
            self.pkg_name = ctx.options.pkg_name if len(ctx.options.pkg_name) > 0 else ""
        if self.apk_name == "":
            self.apk_name = ctx.options.apk_name if len(ctx.options.apk_name) > 0 else ""
        # raw traffic
        with open(os.path.join(traffic_output_dir, f"{self.pkg_name}-{self.apk_name}-raw.bin"), "wb") as f:
            w = io.FlowWriter(f)
            w.add(flow)

    def done(self):
        pass


addons = [HTTPDump()]
