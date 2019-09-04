from fame.core.module import ProcessingModule
import superpehasher


class superhash(ProcessingModule):
    # You have to give your module a name, and this name should be unique.
    name = "SuperPeHasher"
    # (optional) Describe what your module will do. This will be displayed to users.
    description = "Calculate different kind of hash for PE file."
    acts_on = ["executable"]


    # This method will be called, with the object to analyze in target
    def each(self, target):
        self.results = {}

        print(type(target))

        malf = superpehasher.SuperPEHasher(target)
        #md5 = malf.get_md5())
        #print("sha1: \t\t" + malf.get_sha1())
        #print("sha256: \t" + malf.get_sha2())
        SHA512 = malf.get_sha5()
        SSDEEP = malf.get_ssdeep()
        IMPHASH = malf.get_imphash()
        IMPFUZZY = malf.get_impfuzzy()
        xored_richhash, clear_richhash = malf.get_richhash
        #print("RicHash xored: \t" + xored_richhash)
        #print("RicHash clear: \t" + clear_richhash)
        MINHASH = malf.get_mmh()
        PEHASH = malf.get_pehash()
        MACHOCHASH = malf.get_machoc_hash()

        self.results = {
            'SHA512': SHA512,
            'SSDEEP': SSDEEP,
            'IMPHASH': IMPHASH,
            'IMPFUZZY': IMPFUZZY,
            'Xored RichHash': xored_richhash,
            'Clear RichHash': clear_richhash,
            'MINHASH': MINHASH,
            'PEHASH': PEHASH,
            'Machoc Hash': MACHOCHASH
        }

        return True
