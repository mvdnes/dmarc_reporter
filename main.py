import config
import contextlib
import codecs
import datetime
import defusedxml.ElementTree
import email
import email.header
import gzip
import imaplib
import io
import sys
import zipfile

CONTENT_ZIP = ["application/zip", "application/x-zip-compressed"]
CONTENT_GZIP = ["application/gzip"]
CONTENT_IGNORE = ["multipart/mixed", "text/html", "text/plain"]

if sys.platform == 'win32':
    import win_unicode_console
    win_unicode_console.enable()

# As suggested on http://stackoverflow.com/a/14024198
@contextlib.contextmanager
def limit_memory(limit):
    try:
        import resource
    except ImportError:
        sys.stderr.write("Warning: Could not enable memory usage limit\n")
        sys.stderr.flush()
        yield
        return
    type=resource.RLIMIT_AS
    soft_limit, hard_limit = resource.getrlimit(type)
    resource.setrlimit(type, (limit, hard_limit))
    try:
        yield
    finally:
        resource.setrlimit(type, (soft_limit, hard_limit))

def dump_zip(zipdata):
    archive = zipfile.ZipFile(io.BytesIO(zipdata), 'r')
    for info in archive.infolist():
        fobj = archive.open(info)
        parse_report(fobj)

def dump_gz(gzdata):
    fobj = gzip.open(io.BytesIO(gzdata))
    parse_report(fobj)

class DmarcStatistics:
    organisation = None
    report_id = None

    start = None
    end = None

    domain = None

    def __init__(self, xmlctx):
        self.parse_metadata(xmlctx)

        if "@" in self.report_id:
            # Some reporters like to write this as a message ID
            self.report_id, _ = self.report_id.split("@", 1)
        if self.report_id.startswith(self.organisation + '.'):
            # Other reporters prepend their domain name
            self.report_id = self.report_id[len(self.organisation)+1:]

        self.passed = 0
        self.failed = 0
        self.spfresult = {}
        self.dkimresult = {}

        self.parse_records(xmlctx)

        self.spfinfo = ', '.join([k + "=" + str(v) for k,v in self.spfresult.items()])
        self.dkiminfo = ', '.join([k + "=" + str(v) for k,v in self.dkimresult.items()])

    def parse_metadata(self, xmlctx):
        for event, elem in xmlctx:
            if event == 'end' and elem.tag == 'report_metadata':
                self.organisation = elem.findtext('org_name')
                self.report_id = elem.findtext('report_id')
                try:
                    self.start = datetime.datetime.fromtimestamp(int(elem.findtext('date_range/begin'))).isoformat()
                except TypeError:
                    self.start = None
                try:
                    self.end = datetime.datetime.fromtimestamp(int(elem.findtext('date_range/end'))).isoformat()
                except TypeError:
                    self.end = None
            if event == 'end' and elem.tag == 'policy_published':
                self.domain = elem.findtext('domain')
                break

    def parse_records(self, xmlctx):
        for event, elem in xmlctx:
            if event == 'end' and elem.tag == 'record':
                record = elem
                policy = record.find("row/policy_evaluated")
                source = record.find("row/source_ip").text
                count = int(record.find("row/count").text)


                if policy.findtext("dkim") == "pass" or policy.findtext("spf") == "pass":
                    self.passed += 1
                else:
                    self.failed += 1

                for dkimelem in record.findall("auth_results/dkim"):
                    dkimdomain = dkimelem.findtext('domain')
                    if dkimdomain != self.domain:
                        continue
                    dkim = dkimelem.findtext('result')
                    if dkim not in self.dkimresult:
                        self.dkimresult[dkim] = 1
                    else:
                        self.dkimresult[dkim] += 1

                for spfelem in record.findall("auth_results/spf"):
                    spfdomain = spfelem.findtext('domain')
                    if spfdomain != self.domain:
                        continue
                    spf = spfelem.findtext('result')
                    if spf not in self.spfresult:
                        self.spfresult[spf] = 1
                    else:
                        self.spfresult[spf] += 1

    def __str__(self):
        template = (
            "Report ID `{report_id}` from {organisation}\n"
            "From {start} to {end}\n"
            " • *Passed*: {passed}\n"
            " • *Failed*: {failed}\n"
            " • SPF: {spfinfo}\n"
            " • DKIM: {dkiminfo}\n"
        )

        return template.format(**self.__dict__)

def parse_report(fobj):
    try:
        xmlctx = defusedxml.ElementTree.iterparse(fobj, events=('end',))
        report = DmarcStatistics(xmlctx)
        print(str(report))
    except defusedxml.ElementTree.ParseError as e:
        print("Error parsing XML: '{}'".format(str(e)))

def main():
    connection = imaplib.IMAP4_SSL(config.host)
    connection.login(config.username, config.password)
    connection.enable('UTF8=ACCEPT')

    _, data = connection.select(config.mailbox)
    _, data = connection.search(None, config.mailfilter)
    for num in data[0].split():
        _, data = connection.fetch(num, '(RFC822)')
        msg = email.message_from_bytes(data[0][1])
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in CONTENT_ZIP:
                dump_zip(part.get_payload(decode=True))
            elif content_type in CONTENT_GZIP:
                dump_gz(part.get_payload(decode=True))
            elif content_type in CONTENT_IGNORE:
                pass
            else:
                print("Unknown content type '{}'".format(part.get_content_type()))

if __name__ == '__main__':
    # limit to 128 MiB
    with limit_memory(1 << 27):
        main()
