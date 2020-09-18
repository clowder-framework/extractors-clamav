#!/usr/bin/env python

import datetime
import logging
import re
import os
import subprocess
import time

from pyclowder.extractors import Extractor
import pyclowder.files


class ClamAV(Extractor):
    def __init__(self):
        Extractor.__init__(self)

        self.context = {
            "scan":  "https://clowder.ncsa.illinois.edu/contexts/clamav#scan",
            "database": "https://clowder.ncsa.illinois.edu/contexts/clamav#database",
        }
        print(self.database_info())

        # parse command line and load default logging configuration
        self.setup()

        # setup logging for the exctractor
        logging.getLogger('pyclowder').setLevel(logging.DEBUG)
        logging.getLogger('__main__').setLevel(logging.DEBUG)

    @staticmethod
    def database_info():
        clamav_db = {'bytecode': {'version': 0, 'sigs': 0, 'built': None},
                     'daily': {'version': 0, 'sigs': 0, 'built': None},
                     'main': {'version': 0, 'sigs': 0, 'built': None},
                     'signatures': 0}

        # get database info
        result = subprocess.check_output(['clamconf']).decode("utf-8")
        for line in result.split("\n"):
            if line.startswith('bytecode.cvd: '):
                m = re.match(r'^bytecode.cvd: version (\d+), sigs: (\d+), built on (.*)$', line)
                if len(m.groups()) == 3:
                    clamav_db['bytecode']['version'] = int(m.group(1))
                    clamav_db['bytecode']['sigs'] = int(m.group(2))
                    clamav_db['bytecode']['built'] = datetime.datetime.strptime(m.group(3),
                                                                                '%a %b %d %H:%M:%S %Y').isoformat()
            elif line.startswith('daily.cvd: '):
                m = re.match(r'^daily.cvd: version (\d+), sigs: (\d+), built on (.*)$', line)
                if len(m.groups()) == 3:
                    clamav_db['daily']['version'] = int(m.group(1))
                    clamav_db['daily']['sigs'] = int(m.group(2))
                    clamav_db['daily']['built'] = datetime.datetime.strptime(m.group(3),
                                                                             '%a %b %d %H:%M:%S %Y').isoformat()
            elif line.startswith('main.cvd: '):
                m = re.match(r'^main.cvd: version (\d+), sigs: (\d+), built on (.*)$', line)
                if len(m.groups()) == 3:
                    clamav_db['main']['version'] = int(m.group(1))
                    clamav_db['main']['sigs'] = int(m.group(2))
                    clamav_db['main']['built'] = datetime.datetime.strptime(m.group(3),
                                                                            '%a %b %d %H:%M:%S %Y').isoformat()
            elif line.startswith('Total number of signatures: '):
                m = re.match(r'^Total number of signatures: (\d+)$', line)
                if len(m.groups()) == 1:
                    clamav_db['signatures'] = int(m.group(1))
        return clamav_db

    def process_message(self, connector, host, secret_key, resource, parameters):
        # Process the file and upload the results
        inputfile = resource["local_paths"][0]
        file_id = resource['id']

        # run scan
        clamav_scan = {'infected': False, 'virus': None}
        try:
            os.chmod(inputfile, 0o644)
            subprocess.check_output(['clamdscan', '--no-summary', inputfile]).decode("utf-8")
        except subprocess.CalledProcessError as e:
            logging.getLogger().exception("clamdscan " + inputfile)
            clamav_scan['infected'] = True
            clamav_scan['virus'] = e.output.decode("utf-8").replace(inputfile + ': ', '').strip()

        # store results as metadata
        metadata = {
            "@context": ["https://clowder.ncsa.illinois.edu/contexts/metadata.jsonld", self.context],
            "file_id": file_id,
            "content": {
                "database": ClamAV.database_info(),
                "scan": clamav_scan
            },
            "agent": {
                "@type": "cat:extractor",
                "extractor_id": host + "api/extractors/" + self.extractor_info['name']
            }
        }

        pyclowder.files.upload_metadata(connector, host, secret_key, file_id, metadata)


if __name__ == "__main__":
    extractor = ClamAV()
    extractor.start()
