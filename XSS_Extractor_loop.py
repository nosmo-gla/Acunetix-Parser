import re
import os
from defusedxml import ElementTree
'''
takes XML files from ./scans/ and makes a table of XSS injection points
puts files in ./outputs/<domain-name>_XSS.csv
'''

def multiple_replace(replace_map, content):
    sanitised = content
    for bad, good in replace_map.items():
        sanitised = re.sub(bad, good, sanitised)
    return sanitised

directory = 'scans'

for files in os.listdir(directory):
    filename = os.path.join(directory, files)
    if filename[-4:] != '.xml':
        continue
    header = "domain,path,param\n"                 # set header
    vuln = "XSS"

    # Sanitize document for bad chars (not always necessary)
    # This replaces bad chars with ascii replacements
    # Would need reversed to run an exploit
    # could potentially only run this on error?
    replace_map = {'\x1B': 'ESC', '\x00': 'NULL'}
    regex_pattern = r"cross[- ]?site[- ]?scripting"


    with open(filename, 'r') as f:
        content = f.read()
        sanitised = multiple_replace(replace_map, content)
        if content != sanitised:
            print(f'Filtered ESC,NULL from %s' % filename)
            with open(filename + '_sanitised', 'w') as f2:
                f2.write(sanitised)

            filename += '_sanitised'


    # Parse document as XML
    tree = ElementTree.parse(filename)
    root = tree.getroot()

    # Extract domain name from file
    domain = root.find('Scan').find('StartURL').text.strip()


    # Filter through XML branches, extract all "ReportItem"s
    reportitems = root.find('Scan').find('ReportItems').findall('ReportItem')

    # Creates a file without knowing if the issue exists
    # also feel like constantly opening and closing the file is inefficient..?
    out_data = header

    for issue in reportitems:
        title = issue.find('Name').text.strip()
        if re.search(regex_pattern, title, re.IGNORECASE):
            path = issue.find('Affects').text.strip()
            try:
                param = issue.find('Parameter').text.strip()
            except(AttributeError):
                print("AttributeError in " + filename)
            out_data += (','.join([domain, path, param]) + '\n')

    if out_data != header:
        out_doc = 'outputs\\' + '_'.join([domain, vuln]) + ".csv"
        with open(out_doc, 'w') as f:
            print("writing output to " + out_doc)
            f.write(out_data)

