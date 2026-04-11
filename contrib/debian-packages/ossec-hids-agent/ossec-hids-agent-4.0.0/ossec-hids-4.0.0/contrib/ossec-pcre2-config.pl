#! /usr/bin/perl -w

use strict;
use warnings;

use Cwd qw/getcwd realpath/;
use File::Basename;
use File::Find;
use File::Temp qw/tempfile/;

my $ossec_regex_convert = realpath(dirname($0) . '/../src/ossec-regex-convert');

sub get_install_dir () {
    open(FILE, '<', 'src/LOCATION') || die("Cannot find INSTALL DIR");
    my $dir = '/var/ossec';

    while (<FILE>) {
        if (m{^DIR\s*=\s*(["']?)(.*)\g1$}p) {
            $dir = $2;
            last;
        }
    }

    return $dir;
}

my $old_tags = join('|', split(/\n/m, `$ossec_regex_convert -t`));

sub convert_file ($) {
    my $filename = shift();
    print("Converting ${filename}...\n");

    unless (open(SRC, '<', $filename)) {
        print(STDERR "Cannot read '${filename}'\n");
        return;
    }
    my ($tmp_fh, $tmp_filename) = tempfile('tmp-ossec-config-convert.XXXXX', DIR => '/tmp', SUFFIX => '.xml');

    while (<SRC>) {
        if (m{^(\s*)<\s*($old_tags)([^>]*)>(.*?)<\s*/\s*\g2\s*>}pg) {
            my ($indent, $old_type, $options, $old_regex) = ($1, $2, $3, $4);
            $old_regex =~ s/'/'\\''/g;
            my $out = qx/$ossec_regex_convert -b -- $old_type '$old_regex'/;
            chomp($out);
            my ($type, $regex) = split(/ /, $out, 2);
            if ($old_regex) {
                print($tmp_fh "$indent<$type$options>$regex</$type>\n");
            } else {
                print($tmp_fh "$indent<$type$options></$type>\n");
            }
        } else {
            print($tmp_fh $_);
        }
    }

    close(SRC);
    close($tmp_fh);

    rename($tmp_filename, $filename);
}

sub wanted() {
    my $filename = $File::Find::name;

    if ($filename =~ m/[.]xml$/) {
        convert_file($filename);
    }
}

my $INSTALL_DIR = get_install_dir();
if (! -d ${INSTALL_DIR}) {
    print(STDERR "Please install OSSEC first\n");
    exit(1);
}

find({wanted => \&wanted, no_chdir => 1}, $INSTALL_DIR);

exit(0);
