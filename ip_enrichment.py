import os
import re
import json

from cortexutils.analyzer import Analyzer


class IPEnrichment(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def process(self):
        # Get the IP address observable from the TheHive case
        ip_address = self.get_data().get('ip')

        # Check if the IP address is valid
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
            self.error('Invalid IP address')
            return

        # Check if the text file exists on the local machine
        file_path = '/path/to/text/file.txt'
        if not os.path.isfile(file_path):
            self.error('File not found')
            return

        # Open the text file and search for the IP address
        with open(file_path, 'r') as file:
            for line in file:
                if ip_address in line:
                    # Extract the information from the same line as the IP address
                    info = line.strip().split('\t')[1]

                    # Update the observable description in the TheHive case
                    observable_id = self.get_data().get('_id')
                    observable_data = {'description': info}
                    self.add_observable_data(observable_id, observable_data)
                    return

        self.info('No information found for IP address')
        return


if __name__ == '__main__':
    ip_enrichment = IPEnrichment()
    ip_enrichment.run()
    sys.exit(0)
