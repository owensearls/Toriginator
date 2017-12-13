import urllib
import tempfile

from stem.descriptor import DocumentHandler, parse_file

class Consensus:
    directory_authority = 'http://86.59.21.38/'
    descriptor_type = 'network-status-consensus-3 1.0'

    def __init__(self, consensus_file=None):
        self.consensus = self.get_consensus(self.directory_authority)
        self.routers = self.parse_routers(self.consensus)

    def get_consensus(self, da, consensus_file=None):
        path = 'tor/status-vote/current/consensus/'

        if consensus_file is None:
            consensus_file = tempfile.NamedTemporaryFile()
            urllib.urlretrieve(da + path, consensus_file.name)

        consensus = next(parse_file(consensus_file.name,
                                    descriptor_type=self.descriptor_type,
                                    document_handler=DocumentHandler.DOCUMENT))
        return consensus

    def parse_routers(self, consensus):
        routers = {}
        for router in consensus.routers.values():
            routers[router.address] = router

        return routers