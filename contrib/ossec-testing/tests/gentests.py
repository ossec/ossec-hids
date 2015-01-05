#!/usr/bin/env python
"""
Given a rules xml file, outputs a naive ossec-testing ini file.

This is ONLY a starting point containing always-passing tests.
"""
import xml.etree.ElementTree as ET


def xmlfile():
    """rule generator from xml file"""
    tree = ET.parse(XMLFILE)
    for rule in tree.getiterator("rule"):
        yield rule


def getrules():
    """returns a dict of rules"""
    rules = {}
    for node in xmlfile():
        rule = dict()

        rule.update(node.items())
        for child in node.getchildren():
            rule[child.tag] = child.text

        if 'match' in rule:
            rule['match'] = rule['match'].replace('"', '')
            rule['match'] = rule['match'].split("|")
        else:
            rule['match'] = []

        rules[rule['id']] = rule
    return rules


def main():
    """Returns an INI filestring"""
    out = []
    rules = getrules()
    for key, rule in rules.iteritems():
        lines, inc = [], 1

        if 'regex' in rule:
            example = rule['regex'].replace(r'\S+', 'example')
            rule['match'].append(example)

        lines.append('[{description}]')

        if 'match' in rule and len(rule['match']) > 0:
            for string in rule['match']:
                lines.append('log {0} pass = {1}'.format(inc, string))
                inc += 1

        lines.append('')
        lines.append('rule = {id}')
        lines.append('alert = {level}')
        lines.append('decoder = web-accesslog')
        lines.append('')
        stanza = "\n".join(lines).format(**rule)
        out.append(stanza)
    return "\n".join(out)

if __name__ == '__main__':
    import os.path
    import sys
    SCRIPTNAME = sys.argv[0]

    if len(sys.argv) != 2:
        print "Usage: {0} /var/ossec/rules/file.xml".format(sys.argv[0])
        sys.exit(1)

    XMLFILE = sys.argv[1]
    if not os.path.exists(XMLFILE):
        print "Error: could not find file {0}".format(XMLFILE)
        sys.exit(1)

    print main()
