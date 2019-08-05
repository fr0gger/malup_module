#import sys
import pefile
import base64
import cStringIO
from extract_icon import ExtractIcon
#import json as JSON
import os

# from PIL import Image, ImageChops


def extract_icon(pe):
    pe_parsed = pe #pefile.PE(pe, fast_load=True)
    pe_parsed.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

    ico_extractor = ExtractIcon(pe_parsed)
    groups = ico_extractor.get_group_icons()

    b64img = 0
    buffer = cStringIO.StringIO()

    for group in groups:

        for i, res in enumerate(group):
            img = ico_extractor.export(group, i)

            width, height = img.size

            if width == 48 and height == 48:
                #print "coucou"
                #img.save(os.path.join("img/", str(i) + "toto.ico"))
                img.save(buffer, format="PNG")
                b64img = base64.b64encode(buffer.getvalue())
                #b64img = base64.b64encode(img.tostring())

    #print b64img
    #print JSON.dumps({"ICON":b64img})
    return b64img

#extract_icon(sys.argv[1])