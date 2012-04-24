#!/usr/bin/perl -w

#
# Copyright (c) 2012 by Delphix.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

use strict;
use Getopt::Std;

my $component = '[-$:a-zA-Z_.?*\\\[\]!][-$:0-9a-zA-Z_.`?*\\\[\]!]*';

my @ent = ();
my @ret = ();

sub parse {
    my ($program) = @_;
    while ($program ne "") {

        if ($program =~ /^\s*($component)\s*(.*)/s) {
            my @probes = ();
            my $predicate = "";
            my $body = "";

            push(@probes, $1);
            $program = $2;

            while ($program ne "") {
                if ($program =~ /^,\s*($component)\s*(.*)/s) {
                    push(@probes, $1);
                    $program = $2;
                } elsif ($program =~ /^\/(.*?)\/\s*(.*)/s) {
                    $predicate = $1;
                    $program = $2;
                } elsif ($program =~ /^\{(.*?)\}(.*)/s) {
                    $body = $1;
                    $program = $2;
                    last;
                } else {
                    die "bad: $program";
                }
            }

            my $yes = 0;
            my $no = 0;
        
            for my $probe (@probes) {
                if ($probe =~ /^java\$target:/) {
                    $yes++;
                } else {
                    $no++;
                }
            }

            if ($yes && $no) {
                die "you can't mix java and non-java probes; sorry\n";
            }

            if ($no) {
                print D join(",\n", @probes) . "\n";
                print D "/$predicate/\n" if ($predicate ne "");
            } else {

                print D "btrace\$target:::event\n";

                my @points = ();

                for (my $i = 0; $i < @probes; $i++) {
                    $probes[$i] =~ /^.*:(.*):(.*):(.*)/;
                    my ($mod, $func, $name) = ($1, $2, $3);
                    my $e = 0;
                    my $r = 0;
                    if ($name eq "") {
                        $e = $r = 1;
                    } elsif ($name eq "entry") {
                        $e = 1;
                    } elsif ($name eq "return") {
                        $r = 1;
                    } else {
                        die "entry or return only\n";
                        exit(1);
                    }

                    my @pb = ();

                    if ($mod =~ /(.*)\*(.*)/) {
                        die "no internal globbing\n" if ($2 ne "");
                        push(@pb, "strstr(this->__jd_mod, \"$1\") == " .
                            "this->__jd_mod") if ($1 ne "");
                    } else {
                        push(@pb, "this->__jd_mod == \"$mod\"")
                            if ($mod ne "");
                    }

                    if ($func =~ /(.*)\*(.*)/) {
                        die "no internal globbing\n" if ($2 ne "");
                        push(@pb, "strstr(this->__jd_func, \"$1\") == " .
                            "this->__jd_func") if ($1 ne "");
                    } else {
                        push(@pb, "this->__jd_func == \"$func\"")
                            if ($func ne "");
                    }

                    push(@pb, "this->__jd_name == \"$name\"") if ($name ne "");

                    push(@points, "(" . join(" && ", @pb) . ")")
                        if (@pb);

                    $mod = "*" if ($mod eq "");
                    $func = "*" if ($func eq "");

                    if ($mod =~ /\*/) {
                        $mod =~ s/\./\\\\\./g;
                        $mod =~ s/\*/\.\*/;
                        $mod = "/$mod/"
                    }
                    if ($func =~ /\*/) {
                        $func =~ s/\./\\\\\./g;
                        $func =~ s/\*/\.\*/;
                        $func = "/$func/"
                    }

                    push(@ent, "clazz=\"$mod\", " .
                        "method=\"$func\", " .
                        "location=\@Location(Kind.ENTRY)") if ($e);

                    push(@ret, "clazz=\"$mod\", " .
                        "method=\"$func\", " .
                        "location=\@Location(Kind.RETURN)") if ($r);
                }

                my @preds = ();

                push(@preds, "(" . join(" ||\n", @points) . ")")
                    if (@points);
                push(@preds, $predicate) if ($predicate ne "");

                print D "/" . join(" &&\n", @preds) . "/\n" if (@preds);

                my $probeprov = '(strjoin("java", lltostr(pid)))';
                $body =~ s/probeprov/$probeprov/g;
                $body =~ s/probemod/this->__jd_mod/g;
                $body =~ s/probefunc/this->__jd_func/g;
                $body =~ s/probename/this->__jd_name/g;
            }

            print D "{$body}\n";
            

        } elsif ($program =~ /^(\/\*.*?\*\/)(.*)/s) {
            print D "$1\n";
            $program = $2;

        } elsif ($program =~ m/^([^\n]*)\n(.*)/s) {
            print D "$1\n";
            $program = $2;
        } else {
            print D "dead $program\n";
            last;
        }
    }
}

sub genb {
    print B "import com.sun.btrace.annotations.*;\n";
    print B "import static com.sun.btrace.BTraceUtils.*;\n";
    
    print B "\@BTrace\n";
    print B "public class jdtrace {\n";
    
    my $body = "\t\tString p = Strings.strcat(c, Strings.strcat(\":\",\n" .
      "\t\t    Strings.strcat(m, Strings.strcat(\":\", name))));\n" .
      "\t\tD.probe(p, \"\");\n";

    my $i = 0;
    
    foreach my $pair (["entry", \@ent], ["return", \@ret]) {
        my ($type, $probes) = @$pair;
        foreach my $e (@$probes) {
            $i++;
            print B "\t\@OnMethod($e)\n";
            print B "\tpublic static void probe$i(\@ProbeClassName String c,\n";
            print B "\t     \@ProbeMethodName String m) {\n";
            print B "\t\tString name = \"$type\";\n";
            print B $body;
            print B "\t}\n";
            print B "\n";
        }
    }
    
    print B "}\n";
}

sub usage() {
	print "jdtrace -p <pid> [-n <program>] [-s file]\n";
	exit(2);
}

my %opts;
getopts('ep:s:n:vwx:', \%opts);

die "-p <pid> is required\n" unless ($opts{'p'});
die "one of -n or -s must be specified" unless ($opts{'n'} or $opts{'s'});
die "only one of -n or -s may be specified" if ($opts{'n'} and $opts{'s'});

my $tmpdir = "/tmp/jdtrace.$$";
my $dfile = "$tmpdir/jdtrace.d";
my $bfile = "$tmpdir/jdtrace.java";

mkdir($tmpdir) or die;

open(D, ">", $dfile);
open(B, ">", $bfile);

print D "btrace\$target:::event\n";
print D "{\n";
print D "\tthis->__jd_arg = copyinstr(arg0);\n";
#print D "\ttrace(this->__jd_arg);\n";
#print D "\ttrace(strstr(this->__jd_arg, \"java.net.\"));\n";
print D "\tthis->__jd_mod = strtok(this->__jd_arg, \":\");\n";
print D "\tthis->__jd_func = strtok(NULL, \":\");\n";
print D "\tthis->__jd_name = strtok(NULL, \":\");\n";
print D "}\n\n";

my $program;
if ($opts{'s'}) {
	my @lines = <>;
	$program = join("", @lines);
} else {
	$program = $opts{'n'};
}

parse($program);
genb();

if (defined $opts{'v'}) {
	print "---8<--- jdtrace.d ---8<---\n";
	system("cat $dfile");
	print "---8<--- jdtrace.d ---8<---\n\n";

	print "---8<--- jdtrace.java ---8<---\n";
	system("cat $bfile");
	print "---8<--- jdtrace.java ---8<---\n";
}

if (defined $opts{'e'}) {
    exit(0);
}

my $child = fork();
if ($child == 0) {
	chdir("/export/home/delphix/btrace~hg");
	$ENV{'JAVA_HOME'} = "/usr/jdk/instances/jdk1.6.0";
	exec("echo 1 | sudo -E -u delphix bin/btrace $opts{'p'} $bfile");
}

system("dtrace -Z -p $opts{'p'} -s $dfile");

system("rm -rf $tmpdir");
